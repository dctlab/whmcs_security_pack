<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — deterministic, explainable anomaly detection.
 *
 * This is NOT machine learning and does not claim to be — it is a small
 * set of fixed, hand-written threshold rules evaluated against the
 * EXISTING Security Events feed (dctlab_security_pack_events, via
 * ActivityController's data source) and, where relevant, the client's
 * recent login-country history. Nothing here is a second event system:
 * evaluate() takes plain arrays of already-recorded event rows as input
 * and returns findings; it never writes an event itself.
 *
 * Every rule follows the same shape so results are uniformly
 * explainable and testable:
 *   ["detected" => bool, "rule" => string, "severity" => info|warning|high|critical,
 *    "confidence" => low|medium|high, "reason" => string, "evidence" => array,
 *    "dedupe_key" => string, "ip" => ?string]
 *
 * evaluate() is pure — no database access, no globals, no time() calls
 * beyond what's passed in — so every rule is unit-testable with synthetic
 * event arrays. gather() is the thin DB-backed wrapper used by the real
 * admin page (see AnomaliesController).
 */
class SecurityAnomalyService
{
    /**
     * @param array $events Each row: ["event_type"=>string, "ip"=>?string,
     *   "country_code"=>?string, "created_at"=>"Y-m-d H:i:s", "severity"=>string]
     * @param array $thresholds Optional overrides:
     *   failed_login_count (default 5), failed_login_window_minutes (default 10),
     *   country_switch_window_minutes (default 60), event_spike_multiplier (default 3)
     * @param int $now Unix timestamp "now" is evaluated relative to — passed
     *   in explicitly (never time()) so this stays pure/deterministic.
     * @return array list of findings, most severe first
     */
    public static function evaluate(array $events, array $thresholds, int $now): array
    {
        $failedLoginCount = max(1, (int) ($thresholds["failed_login_count"] ?? 5));
        $failedLoginWindow = max(1, (int) ($thresholds["failed_login_window_minutes"] ?? 10)) * 60;
        $countrySwitchWindow = max(1, (int) ($thresholds["country_switch_window_minutes"] ?? 60)) * 60;
        $spikeMultiplier = max(1.0, (float) ($thresholds["event_spike_multiplier"] ?? 3));

        $email2faFailureCount = max(1, (int) ($thresholds["email_2fa_failure_count"] ?? 5));
        $email2faFailureWindow = max(1, (int) ($thresholds["email_2fa_failure_window_minutes"] ?? 15)) * 60;

        $findings = [];
        $findings = array_merge($findings, self::detectRepeatedFailedLogins($events, $failedLoginCount, $failedLoginWindow, $now));
        $findings = array_merge($findings, self::detectMultiIpFailedLogins($events, $failedLoginCount, $failedLoginWindow, $now));
        $findings = array_merge($findings, self::detectNewCountryLogin($events, $countrySwitchWindow, $now));
        $findings = array_merge($findings, self::detectEventVolumeSpike($events, $spikeMultiplier, $now));
        $findings = array_merge($findings, self::detectRepeatedEmail2faFailures($events, $email2faFailureCount, $email2faFailureWindow, $now));

        $severityOrder = ["critical" => 0, "high" => 1, "warning" => 2, "info" => 3];
        usort($findings, static function ($a, $b) use ($severityOrder) {
            return ($severityOrder[$a["severity"]] ?? 9) <=> ($severityOrder[$b["severity"]] ?? 9);
        });

        return $findings;
    }

    /**
     * Rule: N+ failed logins from the SAME IP within the window.
     * Conservative — requires the configured threshold to actually be
     * met; a handful of failed logins (someone mistyping a password) is
     * never flagged.
     */
    private static function detectRepeatedFailedLogins(array $events, int $threshold, int $windowSeconds, int $now): array
    {
        $failedByIp = [];
        foreach ($events as $event) {
            if(!self::isFailedLoginEvent($event)) {
                continue;
            }
            $ts = strtotime((string) ($event["created_at"] ?? ""));
            if($ts === false || ($now - $ts) > $windowSeconds) {
                continue;
            }
            $ip = (string) ($event["ip"] ?? "");
            if($ip === "") {
                continue;
            }
            $failedByIp[$ip][] = $ts;
        }
        $findings = [];
        foreach ($failedByIp as $ip => $timestamps) {
            $count = count($timestamps);
            if($count < $threshold) {
                continue;
            }
            $severity = $count >= ($threshold * 2) ? "critical" : "high";
            $findings[] = [
                "detected" => true,
                "rule" => "auth.repeated_failures_same_ip",
                "severity" => $severity,
                "confidence" => "high",
                "reason" => $count . " failed login attempts from the same IP within " . (int) ($windowSeconds / 60) . " minutes.",
                "evidence" => ["failures" => $count, "ip" => $ip, "window_minutes" => (int) ($windowSeconds / 60)],
                "dedupe_key" => "auth.repeated_failures_same_ip:" . $ip,
                "ip" => $ip,
            ];
        }
        return $findings;
    }

    /**
     * Rule: N+ failed logins across MULTIPLE distinct IPs within the
     * window — a pattern more consistent with a distributed
     * credential-stuffing attempt than a single confused user.
     */
    private static function detectMultiIpFailedLogins(array $events, int $threshold, int $windowSeconds, int $now): array
    {
        $ips = [];
        $count = 0;
        foreach ($events as $event) {
            if(!self::isFailedLoginEvent($event)) {
                continue;
            }
            $ts = strtotime((string) ($event["created_at"] ?? ""));
            if($ts === false || ($now - $ts) > $windowSeconds) {
                continue;
            }
            $ip = (string) ($event["ip"] ?? "");
            if($ip !== "") {
                $ips[$ip] = true;
            }
            $count++;
        }
        $distinctIps = count($ips);
        if($count < $threshold || $distinctIps < 3) {
            return [];
        }
        return [[
            "detected" => true,
            "rule" => "auth.distributed_failures",
            "severity" => "high",
            "confidence" => "medium",
            "reason" => $count . " failed login attempts from " . $distinctIps . " different IP addresses within " . (int) ($windowSeconds / 60) . " minutes.",
            "evidence" => ["failures" => $count, "distinct_ips" => $distinctIps, "window_minutes" => (int) ($windowSeconds / 60)],
            "dedupe_key" => "auth.distributed_failures:window",
            "ip" => null,
        ]];
    }

    /**
     * Rule: a successful login from a country not seen in this client's
     * recent history, shortly after other login activity — flagged as
     * "Unusual", never as a confirmed attack (a legitimate traveling
     * user looks identical). Requires an explicit prior-country baseline
     * to be passed in (never inferred from a single data point).
     */
    private static function detectNewCountryLogin(array $events, int $windowSeconds, int $now): array
    {
        $successesByActor = [];
        foreach ($events as $event) {
            if(($event["event_type"] ?? "") !== "login.client.success") {
                continue;
            }
            $ts = strtotime((string) ($event["created_at"] ?? ""));
            if($ts === false) {
                continue;
            }
            $actor = (string) ($event["actor_id"] ?? "");
            $country = (string) ($event["country_code"] ?? "");
            if($actor === "" || $country === "") {
                continue;
            }
            $successesByActor[$actor][] = ["ts" => $ts, "country" => $country];
        }
        $findings = [];
        foreach ($successesByActor as $actor => $logins) {
            usort($logins, static fn ($a, $b) => $a["ts"] <=> $b["ts"]);
            $seenCountries = [];
            foreach ($logins as $i => $login) {
                $isNewCountry = $seenCountries !== [] && !isset($seenCountries[$login["country"]]);
                if($isNewCountry && $i > 0) {
                    $prev = $logins[$i - 1];
                    $gap = $login["ts"] - $prev["ts"];
                    if($gap >= 0 && $gap <= $windowSeconds && $prev["country"] !== $login["country"]) {
                        $findings[] = [
                            "detected" => true,
                            "rule" => "auth.new_country_short_interval",
                            "severity" => "warning",
                            "confidence" => "low",
                            "reason" => "Login from " . $login["country"] . " occurred " . (int) round($gap / 60) . " minute(s) after a login from " . $prev["country"] . " for the same account — physically implausible for a single traveler, but also consistent with shared-device or VPN use.",
                            "evidence" => ["previous_country" => $prev["country"], "new_country" => $login["country"], "gap_minutes" => (int) round($gap / 60)],
                            "dedupe_key" => "auth.new_country_short_interval:" . $actor,
                            "ip" => null,
                        ];
                    }
                }
                $seenCountries[$login["country"]] = true;
            }
        }
        return $findings;
    }

    /**
     * Rule: today's total event count is a large multiple of the recent
     * daily average — a generic "something unusual is happening" signal
     * that doesn't try to guess what.
     */
    private static function detectEventVolumeSpike(array $events, float $multiplier, int $now): array
    {
        $todayStart = $now - ($now % 86400);
        $baselineStart = $todayStart - (7 * 86400);
        $todayCount = 0;
        $baselineCount = 0;
        foreach ($events as $event) {
            $ts = strtotime((string) ($event["created_at"] ?? ""));
            if($ts === false) {
                continue;
            }
            if($ts >= $todayStart) {
                $todayCount++;
            } elseif($ts >= $baselineStart && $ts < $todayStart) {
                $baselineCount++;
            }
        }
        $baselineDailyAvg = $baselineCount / 7;
        // Require a meaningful absolute floor too — 3 events today vs a
        // baseline average of 0.5 is technically a 6x multiple but not a
        // meaningful "spike" worth alerting on.
        if($baselineDailyAvg < 2 || $todayCount < 10) {
            return [];
        }
        if($todayCount < ($baselineDailyAvg * $multiplier)) {
            return [];
        }
        return [[
            "detected" => true,
            "rule" => "events.volume_spike",
            "severity" => "warning",
            "confidence" => "medium",
            "reason" => "Today's security event volume (" . $todayCount . ") is " . round($todayCount / max(0.1, $baselineDailyAvg), 1) . "x the recent daily average (" . round($baselineDailyAvg, 1) . ").",
            "evidence" => ["today_count" => $todayCount, "baseline_daily_avg" => round($baselineDailyAvg, 2)],
            "dedupe_key" => "events.volume_spike:" . date("Y-m-d", $now),
            "ip" => null,
        ]];
    }

    private static function isFailedLoginEvent(array $event): bool
    {
        return in_array($event["event_type"] ?? "", ["login.client.failed", "login.admin.failed"], true);
    }

    /**
     * Security Pack 2.6 — Step 80: repeated Email 2FA verification
     * failures from the same IP within the window, the same
     * deterministic-threshold shape as detectRepeatedFailedLogins()
     * above (never a second architecture, never "AI").
     */
    private static function detectRepeatedEmail2faFailures(array $events, int $threshold, int $windowSeconds, int $now): array
    {
        $failedByIp = [];
        foreach ($events as $event) {
            if(($event["event_type"] ?? "") !== "email_2fa.verification.failed") {
                continue;
            }
            $ts = strtotime((string) ($event["created_at"] ?? ""));
            if($ts === false || ($now - $ts) > $windowSeconds) {
                continue;
            }
            $ip = (string) ($event["ip"] ?? "");
            if($ip === "") {
                continue;
            }
            $failedByIp[$ip][] = $ts;
        }
        $findings = [];
        foreach ($failedByIp as $ip => $timestamps) {
            $count = count($timestamps);
            if($count < $threshold) {
                continue;
            }
            $severity = $count >= ($threshold * 2) ? "critical" : "high";
            $findings[] = [
                "detected" => true,
                "rule" => "email_2fa.repeated_failures_same_ip",
                "severity" => $severity,
                "confidence" => "high",
                "reason" => $count . " failed Email 2FA verification attempts from the same IP within " . (int) ($windowSeconds / 60) . " minutes.",
                "evidence" => ["failures" => $count, "ip" => $ip, "window_minutes" => (int) ($windowSeconds / 60)],
                "dedupe_key" => "email_2fa.repeated_failures_same_ip:" . $ip,
                "ip" => $ip,
            ];
        }
        return $findings;
    }

    /**
     * DB-backed wrapper for the real admin page — pulls recent events
     * from the EXISTING dctlab_security_pack_events table (no second event
     * store), applies configured thresholds, and returns the same shape
     * evaluate() does. Bounded by $lookbackHours so this never loads an
     * unbounded table into PHP.
     */
    public static function gather(array $settings, int $lookbackHours = 24 * 14): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->select(["event_type", "ip", "country_code", "actor_id", "created_at", "severity"])
                ->where("created_at", ">=", date("Y-m-d H:i:s", time() - ($lookbackHours * 3600)))
                ->orderBy("id", "DESC")
                ->limit(20000)
                ->get()
                ->map(static fn ($r) => (array) $r)
                ->all();
        } catch (\Throwable $e) {
            return [];
        }

        $thresholds = [
            "failed_login_count" => (int) ($settings["anomaly_failed_login_count"] ?? 5),
            "failed_login_window_minutes" => (int) ($settings["anomaly_failed_login_window_minutes"] ?? 10),
            "country_switch_window_minutes" => (int) ($settings["anomaly_country_switch_window_minutes"] ?? 60),
            "event_spike_multiplier" => (float) ($settings["anomaly_event_spike_multiplier"] ?? 3),
            "email_2fa_failure_count" => (int) ($settings["anomaly_email_2fa_failure_count"] ?? 5),
            "email_2fa_failure_window_minutes" => (int) ($settings["anomaly_email_2fa_failure_window_minutes"] ?? 15),
        ];

        return self::evaluate($rows, $thresholds, time());
    }
}
