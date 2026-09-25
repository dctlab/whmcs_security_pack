<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — Security Analytics (Activity > Analytics).
 *
 * PHASE 3.4 (2026-08-24): migrated to the templates/admin/ presentation
 * layer, same pattern validated on Dashboard/Alerts/Activity. Every
 * query, every metric definition, the date-range resolution, and the
 * trend series/max calculation are UNCHANGED — copied verbatim from the
 * pre-Phase-3 controller, only the echo-based rendering moved into
 * analytics.tpl / components/top-list-card.tpl / components/stat-card.tpl.
 *
 * Every metric here is an AGGREGATE SQL query against the EXISTING
 * dctlab_security_pack_events table (plus dctlab_security_pack_csp_reports for
 * the one CSP metric) — never a full table SELECT loaded into PHP. Only
 * metrics that can be accurately calculated from data this module
 * actually records are shown; nothing is estimated or fabricated.
 */
class AnalyticsController
{
    private const RANGES = ["today" => 1, "7d" => 7, "30d" => 30, "90d" => 90];
    private const RANGE_LABELS = ["today" => "Today", "7d" => "7 Days", "30d" => "30 Days", "90d" => "90 Days"];

    public function index($vars = [])
    {
        $range = isset($_GET["range"]) && isset(self::RANGES[$_GET["range"]]) ? $_GET["range"] : "7d";
        $days = self::RANGES[$range];
        $since = $range === "today" ? date("Y-m-d 00:00:00") : date("Y-m-d H:i:s", time() - ($days * 86400));

        $content = TemplateRenderer::render("analytics", [
            "rangeLinks" => $this->buildRangeLinks($range),
            "metrics" => $this->buildMetrics($since),
            "trend" => $this->buildTrend($days),
            "topSources" => [
                "ips" => $this->topBy("ip", $since),
                "countries" => $this->topBy("country_code", $since),
                "eventTypes" => $this->topBy("event_type", $since),
                "cspSources" => $this->topCspSources($since),
            ],
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Security Analytics",
            "pageDescription" => "Aggregate metrics computed from recorded Security Events — never a full table load, never estimated or fabricated.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /** Unchanged: same 4 ranges, same active-state logic, same query param — was echoed directly before, now returned as data for the template (same pattern as ActivityController::buildPaginationLinks() from Phase 3.3). */
    private function buildRangeLinks(string $activeRange): array
    {
        $links = [];
        foreach (self::RANGES as $key => $d) {
            $links[] = [
                "key" => $key,
                "label" => self::RANGE_LABELS[$key],
                "active" => $activeRange === $key,
                "href" => "?module=security_pack&c=analytics&range=" . $key,
            ];
        }
        return $links;
    }

    private function count($eventTypes, $since)
    {
        try {
            return (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->whereIn("event_type", (array) $eventTypes)
                ->where("created_at", ">=", $since)
                ->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Unchanged metric set/order/queries — the original renderMetrics()'s $metrics array, verbatim. */
    private function buildMetrics($since): array
    {
        $metrics = [
            "Login attempts" => $this->count(["login.client.success", "login.client.failed", "login.admin.success", "login.admin.failed"], $since),
            "Successful logins" => $this->count(["login.client.success", "login.admin.success"], $since),
            "Blocked requests" => $this->count(["ip_rule.blocked", "country.blocked", "ip.login_blocked"], $since),
            "IP restrictions" => $this->count(["ip_rule.blocked"], $since),
            "Country blocks" => $this->count(["country.blocked"], $since),
            "Security setting changes" => $this->count(["settings.updated", "csp.policy.changed", "alert.configuration.changed", "email_2fa.settings.changed"], $since),
            "Password-reset activity" => $this->count(["account_protection.password_reset_disable_removed"], $since),
            "Email 2FA successes" => $this->count(["email_2fa.verification.success"], $since),
            "Email 2FA failures" => $this->count(["email_2fa.verification.failed"], $since),
            "Email 2FA resends" => $this->count(["email_2fa.otp.resent"], $since),
            "Email 2FA bypass uses" => $this->count(["email_2fa.bypass.used"], $since),
            "Security events (total)" => $this->count([
                "login.client.success", "login.client.failed", "login.admin.success", "login.admin.failed",
                "ip_rule.blocked", "country.blocked", "ip.login_blocked", "ip_rule.created", "ip_rule.deleted",
                "settings.updated", "csp.policy.changed", "csp.report.cleared", "geo_cache.cleared",
                "account_protection.password_reset_disable_removed", "ip_protection.session_ip_limit_removed",
                "ratelimit.exceeded", "anomaly.detected", "anomaly.acknowledged", "anomaly.dismissed",
                "alert.configuration.changed", "alert.digest.sent",
                "email_2fa.enabled", "email_2fa.disabled", "email_2fa.otp.sent", "email_2fa.otp.resent",
                "email_2fa.verification.success", "email_2fa.verification.failed",
                "email_2fa.bypass.created", "email_2fa.bypass.used", "email_2fa.bypass.revoked",
                "email_2fa.bypass.refreshed", "email_2fa.settings.changed", "email_2fa.reverification_required",
            ], $since),
        ];
        try {
            $metrics["CSP violations"] = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->where("last_seen", ">=", $since)->sum("occurrence_count");
        } catch (\Throwable $e) {
            $metrics["CSP violations"] = 0;
        }

        $out = [];
        foreach ($metrics as $label => $value) {
            $out[] = ["label" => $label, "value" => $value];
        }
        return $out;
    }

    /**
     * Bounded per-day event counts via a single GROUP BY query (never
     * one query per day, never a full table load) — same calculation as
     * the pre-Phase-3 renderTrend(), just returning the series/max/range
     * labels as data instead of echoing bars directly. The bar-height
     * math itself (percentage of $max) is left to the template, same as
     * every other display-only calculation in this presentation layer.
     */
    private function buildTrend($days): array
    {
        $days = min(90, max(1, $days));
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->select([
                    \Illuminate\Database\Capsule\Manager::raw("DATE(created_at) as d"),
                    \Illuminate\Database\Capsule\Manager::raw("COUNT(*) as c"),
                ])
                ->where("created_at", ">=", date("Y-m-d 00:00:00", time() - ($days * 86400)))
                ->groupBy("d")
                ->orderBy("d", "ASC")
                ->get();
        } catch (\Throwable $e) {
            $rows = [];
        }
        $byDay = [];
        foreach ($rows as $row) {
            $byDay[$row->d] = (int) $row->c;
        }
        $series = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $d = date("Y-m-d", time() - ($i * 86400));
            $series[$d] = $byDay[$d] ?? 0;
        }
        $max = max(1, max($series));

        return [
            "series" => $series,
            "max" => $max,
            "rangeStart" => (string) array_key_first($series),
            "rangeEnd" => (string) array_key_last($series),
        ];
    }

    private function topCspSources($since): array
    {
        try {
            $topCsp = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                ->select(["blocked_uri", \Illuminate\Database\Capsule\Manager::raw("SUM(occurrence_count) as total")])
                ->where("last_seen", ">=", $since)
                ->whereNotNull("blocked_uri")
                ->groupBy("blocked_uri")
                ->orderBy("total", "DESC")
                ->limit(10)
                ->get();
        } catch (\Throwable $e) {
            return [];
        }
        $out = [];
        foreach ($topCsp as $row) {
            $out[(string) $row->blocked_uri] = (int) $row->total;
        }
        return $out;
    }

    /**
     * Top-N via a single GROUP BY/ORDER BY/LIMIT query — never pulled
     * unbounded into PHP. User agents are DELIBERATELY not offered as a
     * "top" breakdown here (Step: analytics privacy) — a raw top-user-agent
     * list adds little security value and increases the chance of
     * incidentally surfacing something closer to fingerprinting data than
     * this module needs to expose.
     */
    private function topBy(string $column, $since): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->select([$column, \Illuminate\Database\Capsule\Manager::raw("COUNT(*) as c")])
                ->where("created_at", ">=", $since)
                ->whereNotNull($column)
                ->where($column, "!=", "")
                ->groupBy($column)
                ->orderBy("c", "DESC")
                ->limit(10)
                ->get();
        } catch (\Throwable $e) {
            return [];
        }
        $out = [];
        foreach ($rows as $row) {
            $out[(string) $row->{$column}] = (int) $row->c;
        }
        return $out;
    }
}
