<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — Security Alerts.
 *
 * Alerts are a curated, deliberately SMALL summary view over signals the
 * module already computes elsewhere — SecurityAnomalyService findings,
 * Security Events, CSP report telemetry, and the Security Score
 * snapshot history. This class does not introduce a second event store;
 * every alert here is derived, on demand, from existing tables. Nothing
 * is persisted by this class itself (compare to
 * dctlab_security_pack_anomalies, which DOES have its own row lifecycle for
 * acknowledge/dismiss — alerts are a read-only summary layer on top of
 * that plus other signals).
 *
 * classifySeverity...() helpers are pure and unit-testable; gather() is
 * the DB-backed aggregator used by the real admin page.
 */
class SecurityAlertService
{
    /**
     * Pure: decides IP-repeat-block alert severity from a hit count.
     */
    public static function ipBlockSeverity(int $blockedCount): ?string
    {
        if($blockedCount >= 20) {
            return "critical";
        }
        if($blockedCount >= 5) {
            return "high";
        }
        return null;
    }

    /**
     * Pure: decides country-restriction-spike severity from today's
     * blocked-country-event count vs a baseline average.
     */
    public static function countrySpikeSeverity(int $todayCount, float $baselineAvg): ?string
    {
        if($todayCount < 10) {
            return null;
        }
        if($baselineAvg > 0 && $todayCount < ($baselineAvg * 3)) {
            return null;
        }
        return $todayCount >= 50 ? "high" : "warning";
    }

    /**
     * Pure: decides CSP-violation-spike severity from today's occurrence
     * sum vs a baseline average.
     */
    public static function cspSpikeSeverity(int $todayOccurrences, float $baselineAvg): ?string
    {
        if($todayOccurrences < 20) {
            return null;
        }
        if($baselineAvg > 0 && $todayOccurrences < ($baselineAvg * 3)) {
            return null;
        }
        return $todayOccurrences >= 200 ? "high" : "warning";
    }

    /**
     * Pure: decides Security Score drop severity from a point delta.
     * Never fires on a small day-to-day wobble (< 8 points) — ordinary
     * telemetry fluctuation must not generate a CRITICAL alert.
     */
    public static function scoreDropSeverity(int $previousScore, int $currentScore): ?string
    {
        $drop = $previousScore - $currentScore;
        if($drop < 8) {
            return null;
        }
        return $drop >= 20 ? "critical" : "warning";
    }

    /**
     * DB-backed: gathers the current set of open alerts. Bounded queries
     * only — aggregate counts, never a full table scan into PHP.
     */
    public static function gather(array $settings): array
    {
        $alerts = [];

        // 1) Unacknowledged HIGH/CRITICAL anomalies.
        try {
            $anomalyRows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")
                ->where("status", "open")
                ->whereIn("severity", ["high", "critical"])
                ->orderBy("created_at", "DESC")
                ->limit(50)
                ->get();
            foreach ($anomalyRows as $row) {
                $alerts[] = [
                    "type" => "anomaly",
                    "severity" => $row->severity,
                    "title" => self::titleForRule((string) $row->rule),
                    "reason" => (string) $row->reason,
                    "href" => "?module=security_pack&c=anomalies",
                ];
            }
        } catch (\Throwable $e) {
        }

        // 2) IP repeatedly blocked by IP Restrictions.
        try {
            $blockRows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->select(["ip", \Illuminate\Database\Capsule\Manager::raw("COUNT(*) as hits")])
                ->where("event_type", "ip_rule.blocked")
                ->where("created_at", ">=", date("Y-m-d H:i:s", time() - 86400))
                ->whereNotNull("ip")
                ->groupBy("ip")
                ->get();
            foreach ($blockRows as $row) {
                $ip = $row->ip;
                $count = $row->hits;
                $severity = self::ipBlockSeverity((int) $count);
                if($severity !== null) {
                    $alerts[] = [
                        "type" => "ip_block_repeat",
                        "severity" => $severity,
                        "title" => "IP repeatedly blocked",
                        "reason" => $ip . " was blocked by IP Restrictions " . $count . " time(s) in the last 24 hours.",
                        "href" => "?module=security_pack&c=ipRestrictions",
                    ];
                }
            }
        } catch (\Throwable $e) {
        }

        // 3) Country restriction spike.
        try {
            $todayCountryBlocks = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->where("event_type", "country.blocked")
                ->where("created_at", ">=", date("Y-m-d 00:00:00"))
                ->count();
            $baselineCountryBlocks = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->where("event_type", "country.blocked")
                ->where("created_at", ">=", date("Y-m-d H:i:s", time() - (8 * 86400)))
                ->where("created_at", "<", date("Y-m-d 00:00:00"))
                ->count();
            $severity = self::countrySpikeSeverity($todayCountryBlocks, $baselineCountryBlocks / 7);
            if($severity !== null) {
                $alerts[] = [
                    "type" => "country_spike",
                    "severity" => $severity,
                    "title" => "Country restriction spike",
                    "reason" => $todayCountryBlocks . " country-restriction blocks today, above the recent baseline.",
                    "href" => "?module=security_pack&c=analytics",
                ];
            }
        } catch (\Throwable $e) {
        }

        // 4) CSP violation spike.
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_csp_reports")) {
                $todayCsp = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                    ->where("last_seen", ">=", date("Y-m-d 00:00:00"))
                    ->sum("occurrence_count");
                $baselineCsp = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                    ->where("last_seen", ">=", date("Y-m-d H:i:s", time() - (8 * 86400)))
                    ->where("last_seen", "<", date("Y-m-d 00:00:00"))
                    ->sum("occurrence_count");
                $severity = self::cspSpikeSeverity($todayCsp, $baselineCsp / 7);
                if($severity !== null) {
                    $alerts[] = [
                        "type" => "csp_spike",
                        "severity" => $severity,
                        "title" => "CSP violation spike",
                        "reason" => $todayCsp . " CSP violation occurrences today, above the recent baseline.",
                        "href" => "?module=security_pack&c=cspReports",
                    ];
                }
            }
        } catch (\Throwable $e) {
        }

        // 5) Security Score drop vs 7 days ago.
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_score_snapshots")) {
                $today = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_score_snapshots")->orderBy("snapshot_date", "DESC")->first();
                $weekAgo = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_score_snapshots")
                    ->where("snapshot_date", "<=", date("Y-m-d", time() - (7 * 86400)))
                    ->orderBy("snapshot_date", "DESC")
                    ->first();
                if($today && $weekAgo) {
                    $severity = self::scoreDropSeverity((int) $weekAgo->score, (int) $today->score);
                    if($severity !== null) {
                        $alerts[] = [
                            "type" => "score_drop",
                            "severity" => $severity,
                            "title" => "Security Score drop",
                            "reason" => "Security Score dropped from " . (int) $weekAgo->score . " to " . (int) $today->score . " (of " . (int) $today->max . ") over the last 7 days.",
                            "href" => "?module=security_pack",
                        ];
                    }
                }
            }
        } catch (\Throwable $e) {
        }

        $severityOrder = ["critical" => 0, "high" => 1, "warning" => 2, "info" => 3];
        usort($alerts, static function ($a, $b) use ($severityOrder) {
            return ($severityOrder[$a["severity"]] ?? 9) <=> ($severityOrder[$b["severity"]] ?? 9);
        });

        return $alerts;
    }

    private static function titleForRule(string $rule): string
    {
        $labels = [
            "auth.repeated_failures_same_ip" => "Repeated login failures from one IP",
            "auth.distributed_failures" => "Distributed login failure pattern",
            "auth.new_country_short_interval" => "New-country login shortly after another login",
            "events.volume_spike" => "Security event volume spike",
        ];
        return $labels[$rule] ?? $rule;
    }
}
