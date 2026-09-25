<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\CountryRestrictionService;
use WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.8 — dedicated Country Restrictions admin page
 * (Security Center > Protection > Country Restrictions).
 *
 * This page is a CONSUMER/status view on top of the existing GeoIP
 * architecture — it does not perform its own country lookup, does not
 * touch a MaxMind database directly, and does not maintain a second
 * cache. All of that continues to live in GeoIpManager (used via
 * security_pack_resolve_country()), exactly as it does for GeoIP
 * Language & Currency, IP Restrictions, and Security Events.
 *
 * The enable toggle and the GEO Providers/Whitelist IP fields remain on
 * the main Settings tab (they're shared with other GeoIP-driven
 * features); this page owns only Country Restriction's own rule
 * configuration: Mode, the country list, and the unknown-country
 * policy.
 *
 * PHASE 3.6A (2026-08-24): migrated to the templates/admin/ presentation
 * layer. index()/save()/testLookup() — the CSRF check, the POST-only
 * guard on a=save, the mode/unknown-policy normalization
 * (CountryRestrictionService::normalizeMode()/normalizeUnknownPolicy()),
 * the per-code validation against the module's existing authoritative
 * country list (CountryRestrictionService::isValidCountryCode()), the
 * three updateOrInsert() calls, the security_pack_record_event() call,
 * and the redirect — are copied verbatim, byte-for-byte. testLookup()
 * is intentionally UNCHANGED and still echoes its own small HTML
 * fragment directly (it's an AJAX partial-response endpoint, not a full
 * page — routing it through TemplateRenderer/layout.tpl would change
 * what it returns to the jQuery call in country-restriction.tpl). Only
 * render() (formerly four private methods that echoed HTML directly)
 * now builds a view-model and hands it to TemplateRenderer; no query,
 * no validation rule, and no redirect target changed.
 */
class CountryRestrictionController
{
    private const OWNED_KEYS = ["country_restriction_mode", "disallowed_countries", "country_restriction_unknown_policy"];

    private function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
    }

    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";

        if($action !== "index" && $action !== "test_lookup" && !security_pack_csrf_valid()) {
            $_SESSION["nnm_cr_error"] = "Your session token expired — please try again.";
            redir("module=security_pack&c=countryRestriction", "addonmodules.php");
        }
        if($action === "save" && $_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("module=security_pack&c=countryRestriction", "addonmodules.php");
        }

        if($action === "save") {
            $this->save();
            return;
        }
        if($action === "test_lookup") {
            $this->testLookup();
            return;
        }

        $this->render();
    }

    private function render()
    {
        $settings = security_pack_settings();
        $token = security_pack_csrf_token();

        $errorMessage = null;
        if(isset($_SESSION["nnm_cr_error"])) {
            $errorMessage = (string) $_SESSION["nnm_cr_error"];
            unset($_SESSION["nnm_cr_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_cr_success"])) {
            $successMessage = (string) $_SESSION["nnm_cr_success"];
            unset($_SESSION["nnm_cr_success"]);
        }

        $enabled = !empty($settings["country_restriction"]);
        $mode = CountryRestrictionService::normalizeMode($settings["country_restriction_mode"] ?? null);
        $unknownPolicy = CountryRestrictionService::normalizeUnknownPolicy($settings["country_restriction_unknown_policy"] ?? null);

        $manager = new GeoIpManager();
        $providerRows = $manager->diagnostics();
        $anyProviderAvailable = false;
        foreach ($providerRows as $row) {
            if(!empty($row["available"])) {
                $anyProviderAvailable = true;
                break;
            }
        }
        $mmdbLoaded = function_exists("security_pack_mmdb_reader") && (bool) security_pack_mmdb_reader();

        $selected = CountryRestrictionService::normalizeCountryList($settings["disallowed_countries"] ?? null);
        $countries = (new \WHMCS\Utility\Country())->getCountryNameArray();

        try {
            $recentEvents = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->where("event_type", "country_restriction.blocked")
                ->orderBy("id", "DESC")
                ->limit(10)
                ->get();
        } catch (\Throwable $e) {
            $recentEvents = [];
        }

        $content = TemplateRenderer::render("country-restriction", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "token" => $token,
            "enabled" => $enabled,
            "mode" => $mode,
            "unknownPolicy" => $unknownPolicy,
            "providerRows" => $providerRows,
            "anyProviderAvailable" => $anyProviderAvailable,
            "mmdbLoaded" => $mmdbLoaded,
            "countries" => $countries,
            "selectedCountries" => $selected,
            "recentEvents" => $recentEvents,
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Country Restriction",
            "pageDescription" => "Control access based on visitor country.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    private function save()
    {
        $mode = (string) ($_POST["mode"] ?? "block");
        $mode = CountryRestrictionService::normalizeMode($mode === "allow" ? "allow" : "block");

        $unknownPolicy = (string) ($_POST["unknown_policy"] ?? "allow");
        $unknownPolicy = CountryRestrictionService::normalizeUnknownPolicy($unknownPolicy === "block" ? "block" : "allow");

        // Validate every submitted code against the module's EXISTING
        // authoritative country list (core/countries.json) rather than
        // trusting raw request input — matches how CountryRestrictionService
        // itself only ever recognizes well-formed 2-letter codes.
        $knownCodes = (new \WHMCS\Utility\Country())->getCountryNameArray();
        $submitted = isset($_POST["countries"]) && is_array($_POST["countries"]) ? $_POST["countries"] : [];
        $valid = [];
        foreach ($submitted as $code) {
            if(CountryRestrictionService::isValidCountryCode((string) $code, $knownCodes)) {
                $valid[] = strtoupper((string) $code);
            }
        }
        $valid = array_values(array_unique($valid));

        $before = ["settings" => security_pack_settings()];
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "country_restriction_mode"], ["setting" => "country_restriction_mode", "value" => $mode]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "country_restriction_unknown_policy"], ["setting" => "country_restriction_unknown_policy", "value" => $unknownPolicy]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "disallowed_countries"], ["setting" => "disallowed_countries", "value" => json_encode($valid)]);

        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("country_restriction.settings_updated", "Country Restriction rules were updated from the admin Country Restrictions tab.", ["before" => $before, "mode" => $mode, "unknown_policy" => $unknownPolicy, "country_count" => count($valid)]);
        }

        $_SESSION["nnm_cr_success"] = "Country Restriction settings saved.";
        redir("module=security_pack&c=countryRestriction", "addonmodules.php");
    }

    private function testLookup()
    {
        $ip = trim((string) ($_GET["ip"] ?? ""));
        if(!filter_var($ip, FILTER_VALIDATE_IP)) {
            echo "<span class=\"text-danger\">Enter a valid IP address.</span>";
            exit;
        }
        // Delegates to the SAME shared resolver every other feature
        // uses — no separate MaxMind lookup here.
        $country = function_exists("security_pack_resolve_country") ? security_pack_resolve_country($ip) : "";
        if(!$country) {
            echo "<span class=\"text-muted\">No result for " . $this->e($ip) . " (private/reserved IP, or GeoIP database/providers unavailable).</span>";
            exit;
        }
        $countries = (new \WHMCS\Utility\Country())->getCountryNameArray();
        $name = $countries[$country] ?? $country;
        $settings = security_pack_settings();
        $decision = CountryRestrictionService::evaluate($settings, $country);
        $resultBadge = $decision["blocked"] ? "<span class=\"label label-danger\">Blocked</span>" : "<span class=\"label label-success\">Allowed</span>";
        echo "<span class=\"label label-info\">" . $this->e($country) . "</span> " . $this->e($name) . " &mdash; Result: " . $resultBadge . " <small class=\"text-muted\">(" . $this->e($decision["reason"]) . ")</small>";
        exit;
    }
}
