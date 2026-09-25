<?php

declare(strict_types=1);

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

add_hook("ClientAreaPage", 2, function ($vars) {
    if(isset($_SESSION["adminid"])) {
        return NULL;
    }
    if(isset($_SESSION["uid"]) && !security_pack_lc_apply_to_logged_in()) {
        // Default (recommended) behaviour — GeoIP detection only runs for
        // guests/new visitors; logged-in clients keep whatever they
        // already have.
        return NULL;
    }
    if(isset($_GET["language"]) || isset($_GET["currency"])) {
        // Visitor used WHMCS's own language/currency switcher — that
        // choice permanently wins over auto-detection.
        (new SecurityPackLangCurrency())->markManualOverride();
        return NULL;
    }
    if(isset($_GET["security_pack_lc_reset"])) {
        (new SecurityPackLangCurrency())->reset();
    }
    (new SecurityPackLangCurrency())->maybeApply();
});

add_hook("ClientAreaHeaderOutput", 1, function ($vars) {
    if(isset($_SESSION["adminid"])) {
        return "";
    }
    if(isset($_SESSION["uid"]) && !security_pack_lc_apply_to_logged_in()) {
        return "";
    }
    return (new SecurityPackLangCurrency())->banner();
});

/**
 * Whether GeoIP language/currency detection should also run for
 * already-logged-in clients (who haven't manually switched). Off by
 * default/recommended — detection only applies to guests.
 */
function security_pack_lc_apply_to_logged_in()
{
    $settings = security_pack_settings();
    return !empty($settings["lc_apply_logged_in"]) && $settings["lc_apply_logged_in"] != "0";
}

class SecurityPackLangCurrency
{
    public $settings = [];
    private $countryCurrencyMap = null;

    public function __construct()
    {
        $this->settings = security_pack_settings();
    }

    public function enabled()
    {
        return isset($this->settings["lang_currency"]) && $this->settings["lang_currency"] != "0";
    }

    public function maybeApply()
    {
        if(!$this->enabled() || $this->hasManualOverride() || isset($_SESSION["security_pack_lc_applied"])) {
            return;
        }

        $seoBotBypass = !isset($this->settings["seo_bot_bypass"]) || $this->settings["seo_bot_bypass"] != "0";
        if($seoBotBypass && function_exists("security_pack_is_bot") && security_pack_is_bot()) {
            // SEO Bot Bypass (on by default/recommended) — crawlers always
            // see the site default language/currency so search engines
            // don't index the same page as duplicate content per-country.
            security_pack_lc_debug_log("Skipped for bot user agent \"" . ($_SERVER["HTTP_USER_AGENT"] ?? "") . "\".");
            $_SESSION["security_pack_lc_applied"] = 1;
            return;
        }

        $ipSource = $this->settings["ip_source"] ?? "auto";
        $remote_ip = function_exists("security_pack_detect_visitor_ip") ? security_pack_detect_visitor_ip($ipSource) : ($GLOBALS["remote_ip"] ?? "");
        if(!$remote_ip) {
            security_pack_lc_debug_log("Could not determine a visitor IP (source=" . $ipSource . ") — skipping.");
            return;
        }
        $country = security_pack_resolve_country($remote_ip);
        if(!$country) {
            security_pack_lc_debug_log("No GeoIP country resolved for " . $remote_ip . " — leaving language/currency untouched.");
            $_SESSION["security_pack_lc_applied"] = 1;
            return;
        }
        $_SESSION["security_pack_lc_country"] = $country;
        $mapping = $this->mappingFor($country);

        $language = $this->validLanguage($mapping["language"]) ? $mapping["language"] : null;
        if(!$language && $this->validLanguage($this->settings["fallback_language"] ?? "")) {
            $language = $this->settings["fallback_language"];
        }

        $currencyId = $this->activeCurrencyId($mapping["currency"]);
        if(!$currencyId) {
            $currencyId = $this->activeCurrencyId($this->settings["fallback_currency"] ?? "");
        }

        $languageChanged = $language && ($_SESSION["Language"] ?? null) !== $language;

        security_pack_lc_debug_log("IP " . $remote_ip . " (source=" . $ipSource . ") -> country " . $country . ", language=" . ($language ?: "(none)") . ", currencyId=" . ($currencyId ?: "(none)") . ".");

        if($language) {
            $_SESSION["Language"] = $language;
        }
        if($currencyId) {
            $_SESSION["currency"] = $currencyId;
        }
        $_SESSION["security_pack_lc_applied"] = 1;

        if($languageChanged) {
            // $_SESSION['Language'] only takes effect on the next request
            // since Lang is already bootstrapped for this one — reload
            // once, mirroring SecurityPackCountryRestriction::redirect().
            ob_clean();
            ob_start();
            redirSystemURL(isset($_GET) && $_GET ? urldecode(http_build_query($_GET)) : "", App::getCurrentFilename() . ".php");
            exit;
        }
    }

    public function mappingFor($countryCode)
    {
        try {
            $override = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_lc_overrides")->where("country_code", $countryCode)->where("enabled", 1)->first();
        } catch (\Throwable $e) {
            // Table not created yet (module updated without running
            // _upgrade) — fall back to the built-in currency map only.
            $override = null;
        }
        $language = $override->language ?? null;
        $currency = $override->currency ?? null;
        if(!$currency) {
            $currency = $this->coreCurrencyFor($countryCode);
        }
        return ["language" => $language ?: null, "currency" => $currency ?: null];
    }

    private function coreCurrencyFor($countryCode)
    {
        if($this->countryCurrencyMap === null) {
            $file = security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "country_currency.json";
            $this->countryCurrencyMap = file_exists($file) ? (json_decode(file_get_contents($file), true) ?: []) : [];
        }
        return $this->countryCurrencyMap[$countryCode] ?? null;
    }

    public function validLanguage($language)
    {
        if(!$language || !class_exists("WHMCS\\Language\\ClientLanguage")) {
            return false;
        }
        $installed = array_map("strtolower", WHMCS\Language\ClientLanguage::getLanguages());
        return in_array(strtolower($language), $installed, true);
    }

    public function activeCurrencyId($code)
    {
        if(!$code) {
            return null;
        }
        $row = Illuminate\Database\Capsule\Manager::table("tblcurrencies")->where("code", strtoupper($code))->first();
        return $row ? intval($row->id) : null;
    }

    public function hasManualOverride()
    {
        if(isset($_SESSION["security_pack_lc_manual"])) {
            return true;
        }
        return isset($_COOKIE["security_pack_lc_manual"]) && $_COOKIE["security_pack_lc_manual"] == "1";
    }

    public function markManualOverride()
    {
        $_SESSION["security_pack_lc_manual"] = 1;
        $days = isset($this->settings["lc_cookie_days"]) ? max(1, intval($this->settings["lc_cookie_days"])) : 365;
        setcookie("security_pack_lc_manual", "1", ["expires" => time() + ($days * 86400), "path" => "/", "secure" => !empty($_SERVER["HTTPS"]), "httponly" => true, "samesite" => "Lax"]);
    }

    public function reset()
    {
        $this->markManualOverride();
        unset($_SESSION["Language"], $_SESSION["currency"], $_SESSION["security_pack_lc_country"], $_SESSION["security_pack_lc_applied"]);
        redirSystemURL("", "index.php");
        exit;
    }

    public function banner()
    {
        // Checkboxes on the Settings tab are only ever submitted when
        // checked (standard HTML form behaviour), and save() truncates +
        // re-inserts only the keys present in the POST — so "off" means
        // the setting key is simply absent, never stored as "0". Checking
        // for an explicit "0" here meant the banner never actually turned
        // off; isset() is the correct on/off test, same as every other
        // checkbox in this module (lang_currency, login_history, etc).
        if(!$this->enabled() || !isset($this->settings["lc_banner"])) {
            return "";
        }
        if(!isset($_SESSION["security_pack_lc_country"]) || isset($_COOKIE["security_pack_lc_dismiss"])) {
            return "";
        }
        global $CONFIG;
        $language = Lang::getName();
        if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
        }
        $countries = new WHMCS\Utility\Country();
        $names = $countries->getCountryNameArray();
        $country = $_SESSION["security_pack_lc_country"];
        $countryName = $names[$country] ?? $country;
        $text = isset($_ADDONLANG["geoiplc_banner_text"]) ? $_ADDONLANG["geoiplc_banner_text"] : "We set your language/currency based on your location";
        $useDefault = isset($_ADDONLANG["geoiplc_use_default"]) ? $_ADDONLANG["geoiplc_use_default"] : "Use site default";

        return "<div id=\"security-pack-lc-banner\">\r\n<div class=\"container\">\r\n<span>" . htmlspecialchars($text, ENT_QUOTES, "UTF-8") . " (" . htmlspecialchars($countryName, ENT_QUOTES, "UTF-8") . "). </span>"
            . "<a href=\"index.php?security_pack_lc_reset=1\" class=\"security-pack-lc-reset\">" . htmlspecialchars($useDefault, ENT_QUOTES, "UTF-8") . "</a>"
            . " <button type=\"button\" class=\"security-pack-lc-close\" aria-label=\"Dismiss\" onclick=\"document.cookie='security_pack_lc_dismiss=1;path=/;max-age=86400';this.closest('#security-pack-lc-banner').remove();\">&times;</button>"
            . "</div></div>"
            . "<style>#security-pack-lc-banner{background:#f1f6ff;border-bottom:1px solid #d6e4ff;padding:8px 0;font-size:13px;text-align:center;color:#2c3e50;}"
            . "#security-pack-lc-banner .container{display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap;}"
            . "#security-pack-lc-banner a.security-pack-lc-reset{font-weight:600;text-decoration:underline;}"
            . "#security-pack-lc-banner .security-pack-lc-close{background:none;border:0;font-size:16px;line-height:1;cursor:pointer;color:#2c3e50;}</style>";
    }
}

?>
