<?php



//  file for php version 74.
namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * PHASE 3.6C (2026-08-24): migrated to the templates/admin/ presentation
 * layer. index()/overrideSave()/overrideStatus()/overrideDelete()/
 * saveDefaults()/saveAdvanced()/uploadMmdb()/clearCache()/testLookup() —
 * the self-heal check, the CSRF/POST guards, every query, the .mmdb
 * upload validation (unchanged, including the "parse before accept"
 * check via MaxMindDb\Reader), and the security_pack_record_event() call
 * — are copied verbatim, byte-for-byte. Only render() and its 5 private
 * renderXxx() helpers (which echoed HTML directly) were rebuilt to
 * produce a view-model for TemplateRenderer; no query, no validation
 * rule, and no redirect target changed.
 */
class LangCurrencyController
{
    public function index()
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";

        // Self-heal: sites that had security_pack active before this
        // feature was added will already have run past _activate(); make
        // sure the tables/columns exist before we query them either way.
        if(function_exists("security_pack_ensure_tables") && (!\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_lc_overrides") || !\Illuminate\Database\Capsule\Manager::schema()->hasColumn("dctlab_security_pack_lc_overrides", "enabled"))) {
            security_pack_ensure_tables();
        }

        if($action !== "index" && $action !== "test_lookup" && !security_pack_csrf_valid()) {
            $_SESSION["nnm_lc_error"] = "Your session token expired — please try again.";
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        // Security Pack 2.3 (Step 12/14): the destructive/state-changing
        // actions below used to be reachable via a plain GET link with
        // just a CSRF token in the query string. They're now POST-only —
        // a GET request is rejected outright, regardless of token,
        // matching the same fix already applied to PasswordDisabled/
        // IpLimitedClients in 2.2. override_save/save_defaults/
        // save_advanced/upload_mmdb were already POST-only (real HTML
        // forms) and are unaffected.
        $postOnlyActions = ["override_delete", "override_enable", "override_disable", "clear_cache"];
        if(in_array($action, $postOnlyActions, true) && $_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        switch ($action) {
            case "override_save":
                $this->overrideSave();
                return;
            case "override_delete":
                $this->overrideDelete();
                return;
            case "override_enable":
                $this->overrideStatus(true);
                return;
            case "override_disable":
                $this->overrideStatus(false);
                return;
            case "save_defaults":
                $this->saveDefaults();
                return;
            case "save_advanced":
                $this->saveAdvanced();
                return;
            case "upload_mmdb":
                $this->uploadMmdb();
                return;
            case "clear_cache":
                $this->clearCache();
                return;
            case "test_lookup":
                $this->testLookup();
                return;
        }

        $this->render();
    }

    private function render()
    {
        $settings = security_pack_settings();

        $showSavedBanner = isset($_REQUEST["saved"]);
        $errorMessage = null;
        if(isset($_SESSION["nnm_lc_error"])) {
            $errorMessage = (string) $_SESSION["nnm_lc_error"];
            unset($_SESSION["nnm_lc_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_lc_success"])) {
            $successMessage = (string) $_SESSION["nnm_lc_success"];
            unset($_SESSION["nnm_lc_success"]);
        }

        $token = security_pack_csrf_token();
        $languages = class_exists("\\WHMCS\\Language\\ClientLanguage") ? \WHMCS\Language\ClientLanguage::getLanguages() : ["english"];
        $currenciesRaw = \Illuminate\Database\Capsule\Manager::table("tblcurrencies")->orderBy("code")->get();
        $currencies = [];
        foreach ($currenciesRaw as $currency) {
            $currencies[] = (string) $currency->code;
        }
        $countries = (new \WHMCS\Utility\Country())->getCountryNameArray();

        $ipSource = $settings["ip_source"] ?? "auto";
        $seoBotBypass = !isset($settings["seo_bot_bypass"]) || $settings["seo_bot_bypass"] != "0";
        $applyLoggedIn = !empty($settings["lc_apply_logged_in"]) && $settings["lc_apply_logged_in"] != "0";
        $debug = !empty($settings["lc_debug"]) && $settings["lc_debug"] != "0";

        $content = TemplateRenderer::render("lang-currency", [
            "showSavedBanner" => $showSavedBanner,
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "token" => $token,
            "dbStatus" => $this->buildDbStatus(),
            "languages" => $languages,
            "currencies" => $currencies,
            "countries" => $countries,
            "fallbackLanguage" => $settings["fallback_language"] ?? "",
            "fallbackCurrency" => $settings["fallback_currency"] ?? "",
            "overrides" => $this->buildOverrides($countries),
            "advanced" => ["ipSource" => $ipSource, "seoBotBypass" => $seoBotBypass, "applyLoggedIn" => $applyLoggedIn, "debug" => $debug],
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "GeoIP Language & Currency",
            "pageDescription" => "Auto-detect visitor country and switch client area language/currency to match.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /** Same mmdb reader/path/cache-count logic as the original renderDatabaseStatus(), just returned as data instead of echoed. */
    private function buildDbStatus(): array
    {
        $mmdb = function_exists("security_pack_mmdb_reader") ? security_pack_mmdb_reader() : null;
        $path = function_exists("security_pack_mmdb_path") ? security_pack_mmdb_path() : "";
        $cachedLookups = 0;
        try {
            $cachedLookups = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_geo_cache")->count();
        } catch (\Throwable $e) {
        }

        if($mmdb) {
            $meta = $mmdb->metadata;
            $built = isset($meta["build_epoch"]) ? date("Y-m-d", (int) $meta["build_epoch"]) : "unknown";
            return [
                "loaded" => true,
                "type" => $meta["database_type"] ?? "unknown",
                "nodeCount" => $meta["node_count"] ?? "?",
                "built" => $built,
                "path" => $path,
                "cachedLookups" => $cachedLookups,
            ];
        }
        return ["loaded" => false];
    }

    /** Same query/enabled-flag logic as the original renderCountryRules(), just returned as data instead of echoed. */
    private function buildOverrides(array $countries): array
    {
        $overrides = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->orderBy("country_code")->get();
        $rows = [];
        foreach ($overrides as $row) {
            $name = $countries[$row->country_code] ?? $row->country_code;
            $enabled = !isset($row->enabled) || (int) $row->enabled === 1;
            $rows[] = [
                "id" => (int) $row->id,
                "countryCode" => (string) $row->country_code,
                "name" => $name,
                "language" => $row->language ?: "—",
                "currency" => $row->currency ?: "—",
                "enabled" => $enabled,
            ];
        }
        return $rows;
    }

    private function overrideSave()
    {
        $countryCode = strtoupper((string) ($_POST["country_code"] ?? ""));
        if(!preg_match("/^[A-Z]{2}$/", $countryCode)) {
            $_SESSION["nnm_lc_error"] = "Invalid country code.";
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        $language = trim((string) ($_POST["language"] ?? ""));
        $currency = strtoupper(trim((string) ($_POST["currency"] ?? "")));

        $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->where("country_code", $countryCode)->first();
        $enabled = $existing ? (isset($existing->enabled) ? (int) $existing->enabled : 1) : 1;

        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->updateOrInsert(
            ["country_code" => $countryCode],
            ["country_code" => $countryCode, "language" => $language ?: null, "currency" => $currency ?: null, "enabled" => $enabled, "updated_at" => date("Y-m-d H:i:s")]
        );

        $_SESSION["nnm_lc_success"] = "Rule saved.";
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function overrideStatus($enabled)
    {
        $id = (int) ($_REQUEST["id"] ?? 0);
        if($id > 0) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->where("id", $id)->update(["enabled" => $enabled ? 1 : 0, "updated_at" => date("Y-m-d H:i:s")]);
        }
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function overrideDelete()
    {
        $id = (int) ($_REQUEST["id"] ?? 0);
        if($id > 0) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->where("id", $id)->delete();
        }
        redir("module=security_pack&c=langCurrency&deleted=1", "addonmodules.php");
    }

    private function saveDefaults()
    {
        $fallbackLanguage = (string) ($_POST["fallback_language"] ?? "english");
        $fallbackCurrency = strtoupper((string) ($_POST["fallback_currency"] ?? "USD"));

        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "fallback_language"], ["setting" => "fallback_language", "value" => $fallbackLanguage]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "fallback_currency"], ["setting" => "fallback_currency", "value" => $fallbackCurrency]);

        $_SESSION["nnm_lc_success"] = "Defaults saved.";
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function saveAdvanced()
    {
        $ipSource = (string) ($_POST["ip_source"] ?? "auto");
        if(!in_array($ipSource, ["auto", "cloudflare", "xff", "xrealip", "remoteaddr"], true)) {
            $ipSource = "auto";
        }
        $seoBotBypass = isset($_POST["seo_bot_bypass"]) ? "1" : "0";
        $applyLoggedIn = isset($_POST["lc_apply_logged_in"]) ? "1" : "0";
        $debug = isset($_POST["lc_debug"]) ? "1" : "0";

        $save = [
            "ip_source" => $ipSource,
            "seo_bot_bypass" => $seoBotBypass,
            "lc_apply_logged_in" => $applyLoggedIn,
            "lc_debug" => $debug,
        ];
        foreach ($save as $setting => $value) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => $setting], ["setting" => $setting, "value" => $value]);
        }

        $_SESSION["nnm_lc_success"] = "Advanced settings saved.";
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function uploadMmdb()
    {
        if(empty($_FILES["mmdb_file"]["tmp_name"]) || !is_uploaded_file($_FILES["mmdb_file"]["tmp_name"])) {
            $_SESSION["nnm_lc_error"] = "No file uploaded.";
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        $originalName = (string) ($_FILES["mmdb_file"]["name"] ?? "");
        if(strtolower(pathinfo($originalName, PATHINFO_EXTENSION)) !== "mmdb") {
            $_SESSION["nnm_lc_error"] = "Please upload a .mmdb file.";
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        require_once security_pack_module_root . "/lib/MaxMindDb/Reader.php";
        try {
            // Validate before accepting — reject anything that isn't a
            // parseable MaxMind DB rather than silently breaking lookups.
            new \WHMCS\Module\Addon\Security_Pack\MaxMindDb\Reader($_FILES["mmdb_file"]["tmp_name"]);
        } catch (\Throwable $e) {
            $_SESSION["nnm_lc_error"] = "That file doesn't look like a valid MaxMind DB: " . $e->getMessage();
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        $dataDir = security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "data";
        if(!is_dir($dataDir)) {
            @mkdir($dataDir, 0755, true);
        }
        if(!move_uploaded_file($_FILES["mmdb_file"]["tmp_name"], security_pack_mmdb_path())) {
            $_SESSION["nnm_lc_error"] = "Upload validated but the file could not be saved — check folder permissions on modules/addons/security_pack/core/data/.";
            redir("module=security_pack&c=langCurrency", "addonmodules.php");
        }

        $_SESSION["nnm_lc_success"] = "GeoIP database uploaded.";
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function clearCache()
    {
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_geo_cache")->truncate();
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("geo_cache.cleared", "GeoIP lookup cache was cleared by an administrator.", [], "info");
        }
        $_SESSION["nnm_lc_success"] = "Lookup cache cleared.";
        redir("module=security_pack&c=langCurrency", "addonmodules.php");
    }

    private function testLookup()
    {
        $ip = trim((string) ($_GET["ip"] ?? ""));
        if(!filter_var($ip, FILTER_VALIDATE_IP)) {
            echo "<span class=\"text-danger\">Enter a valid IP address.</span>";
            exit;
        }
        $country = function_exists("security_pack_resolve_country") ? security_pack_resolve_country($ip) : "";
        if(!$country) {
            echo "<span class=\"text-muted\">No result for " . htmlspecialchars($ip, ENT_QUOTES, "UTF-8") . " (private/reserved IP, or not found in the database/providers).</span>";
            exit;
        }
        $countries = (new \WHMCS\Utility\Country())->getCountryNameArray();
        $name = $countries[$country] ?? $country;
        $lc = class_exists("SecurityPackLangCurrency") ? new \SecurityPackLangCurrency() : null;
        $extra = "";
        if($lc) {
            $mapping = $lc->mappingFor($country);
            $extra = " &mdash; Language: " . htmlspecialchars($mapping["language"] ?: "(fallback)", ENT_QUOTES, "UTF-8") . ", Currency: " . htmlspecialchars($mapping["currency"] ?: "(fallback)", ENT_QUOTES, "UTF-8");
        }
        echo "<span class=\"label label-info\">" . htmlspecialchars($country, ENT_QUOTES, "UTF-8") . "</span> " . htmlspecialchars($name, ENT_QUOTES, "UTF-8") . $extra;
        exit;
    }
}
