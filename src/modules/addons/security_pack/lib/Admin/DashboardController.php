<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\SecurityScoreService;
use WHMCS\Module\Addon\Security_Pack\Security\SecurityAlertService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — Security Center Overview (Dashboard).
 *
 * PHASE 3.2 (2026-08-24): first controller migrated to the new
 * templates/admin/ presentation layer (see TemplateRenderer.php's
 * docblock for the architecture decision behind it). Functionally
 * UNCHANGED from the pre-refactor version — same SecurityScoreService
 * call, same recommendations cap, same feature/posture cards, same
 * links — only HOW the HTML is produced changed: this controller now
 * prepares a plain data array (a "view model") and hands it to
 * TemplateRenderer instead of echoing HTML directly. One genuinely new
 * piece was added (the Open Alerts / High-Severity Anomalies stat row,
 * spec Section 13) — both values come from EXISTING services
 * (SecurityAlertService::gather(), SecurityScoreService::gatherFacts()'s
 * existing open_high_severity_anomalies fact), never fabricated; no
 * second alert/scoring engine was introduced.
 *
 * Read-only — everything here is a summary/shortcut into the existing
 * feature pages (Settings, Language & Currency, Diagnostics, Activity),
 * nothing is duplicated or re-implemented.
 */
class DashboardController
{
    private function e($v)
    {
        return TemplateRenderer::e($v);
    }

    public function index($vars = [])
    {
        $settings = security_pack_settings();
        $facts = SecurityScoreService::gatherFacts();
        $result = SecurityScoreService::compute($settings, $facts);

        $stats = $this->buildStats($settings, $facts);
        $postureCards = $this->buildPostureCards($settings, $facts);

        $content = TemplateRenderer::render("dashboard", [
            "score" => $result["score"],
            "max" => $result["max"],
            "categories" => $result["categories"],
            "recommendations" => $result["recommendations"],
            "stats" => $stats,
            "postureCards" => $postureCards,
        ]);

        echo $this->assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "DCTLAB Security Pack",
            "pageDescription" => "Enterprise Security & Authentication for WHMCS",
            "pageActionsHtml" => '<a href="?module=security_pack&amp;c=Dashboard" class="btn btn-default btn-sm"><i class="fa fa-refresh" aria-hidden="true"></i> Refresh</a>',
            "content" => $content,
        ]);
    }

    /**
     * Loads the Phase 3.1 DCTLAB CSS layer for this page only (Dashboard
     * is the sole controller migrated so far — see this file's header
     * docblock). Uses the SAME absolute-URL resolution already relied on
     * by core/two_factor_admin_display.php's asset tag
     * (security_pack_2fa_asset_base_url()) rather than a second helper —
     * that function fixed a confirmed live bug where a relative "../"
     * asset URL 404'd on friendly-routed admin URLs (3.1.19); reusing it
     * avoids reintroducing the same bug here.
     */
    private function assetTags(): string
    {
        $base = function_exists("security_pack_2fa_asset_base_url") ? security_pack_2fa_asset_base_url() : "";
        $cssBase = $base . "/modules/addons/security_pack/assets/css/";
        $version = defined("SECURITY_PACK_VERSION") ? SECURITY_PACK_VERSION : "3.2";
        $files = ["security-pack.css", "components.css", "responsive.css"];
        $html = "";
        foreach ($files as $file) {
            $html .= '<link rel="stylesheet" href="' . $this->e($cssBase . $file . "?v=" . rawurlencode((string) $version)) . '">';
        }
        return $html;
    }

    /**
     * Real statistics only (spec Section 13: "Never hardcode numbers...
     * display Not enough data where appropriate") — both values are read
     * from existing services, no new counting logic:
     *   - Open Alerts: SecurityAlertService::gather($settings) is the
     *     same alert source the Alerts controller itself uses — count()
     *     of its result, not a re-implementation.
     *   - High-Severity Anomalies: SecurityScoreService::gatherFacts()'s
     *     existing "open_high_severity_anomalies" fact, already computed
     *     for the score calculation above — reused, not requeried.
     */
    private function buildStats(array $settings, array $facts): array
    {
        $openAlerts = null;
        try {
            $openAlerts = count(SecurityAlertService::gather($settings));
        } catch (\Throwable $e) {
            $openAlerts = null;
        }

        $highSeverityAnomalies = isset($facts["open_high_severity_anomalies"])
            ? (int) $facts["open_high_severity_anomalies"]
            : null;

        return [
            ["label" => "Open Alerts", "value" => $openAlerts, "href" => "?module=security_pack&c=alerts"],
            ["label" => "High-Severity Anomalies", "value" => $highSeverityAnomalies, "href" => "?module=security_pack&c=anomalies"],
        ];
    }

    private function buildPostureCards(array $settings, array $facts): array
    {
        $on = function ($key) use ($settings) {
            return isset($settings[$key]) && $settings[$key] !== "0" && $settings[$key] !== "";
        };
        // NOTE (functionality preservation): the pre-refactor controller
        // had two cards both literally labeled "IP Restrictions" — one
        // keyed off $settings["ip_range_limits"] (which is actually the
        // separate "IP Security Limited Clients" feature, c=ipLimitedClients
        // in the main menu) and one off $facts["ip_rules_configured"]
        // (the real "IP Restrictions" rules feature, c=ipRestrictions).
        // That was a pre-existing mislabeling in the old inline HTML, not
        // a deliberate duplicate card — both distinct features are kept
        // here (nothing removed), just each given its own correct label
        // matching the module's own menu naming, per spec Section 2 ("do
        // not remove a feature") and Section 19 ("preserve logic").
        return [
            ["label" => "Login Protection", "on" => $on("login_history"), "href" => "?module=security_pack&c=settings"],
            ["label" => "IP Security Limited Clients", "on" => $on("ip_range_limits"), "href" => "?module=security_pack&c=ipLimitedClients"],
            ["label" => "IP Restrictions", "on" => !empty($facts["ip_rules_configured"]), "href" => "?module=security_pack&c=ipRestrictions"],
            ["label" => "Country Protection", "on" => $on("country_restriction"), "href" => "?module=security_pack&c=settings"],
            ["label" => "GeoIP Language & Currency", "on" => $on("lang_currency"), "href" => "?module=security_pack&c=langCurrency"],
            ["label" => "Trusted Proxies", "on" => trim((string) ($settings["trusted_proxies"] ?? "")) !== "", "href" => "?module=security_pack&c=diagnostics"],
            ["label" => "Content Protection", "on" => $on("right_click") || $on("copy_paste") || $on("iframe"), "href" => "?module=security_pack&c=settings"],
        ];
    }
}
