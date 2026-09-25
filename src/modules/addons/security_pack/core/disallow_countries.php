<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
add_hook("ClientAreaPage", 1, function ($vars) {
    if(isset($_SESSION["adminid"]) || isset($_SESSION["uid"])) {
        return NULL;
    }
    if(isset($_SESSION["security_pack_init"])) {
        return NULL;
    }
    $security_pack = new SecurityPackCountryRestriction();
    $security_pack->check();
});
add_hook("ClientAreaHeaderOutput", 1, function ($vars) {
    if(isset($_SESSION["adminid"]) || isset($_SESSION["uid"])) {
        return "";
    }
    if(isset($_SESSION["security_pack_blocked"])) {
        global $CONFIG;
        $language = Lang::getName();
        if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
        }
        return "<style type=\"text/css\" media=\"screen\">\r\n#goe-tools-blocked-banner {\r\n    color: #856404;\r\n    background-color: #fff3cd;\r\n    border-color: #ffeeba;\r\n    width: 100%;\r\n    padding: 10px;\r\n    text-align: center;\r\n}\r\n</style>\r\n    <div id=\"goe-tools-blocked-banner\">\r\n    " . $_ADDONLANG["blocked_banner"] . "\r\n    </div>";
    }
});
add_hook("ClientDetailsValidation", 1, function ($vars) {
    if(isset($_SESSION["uid"]) || isset($_SESSION["adminid"])) {
        return NULL;
    }
    $security_pack = new SecurityPackCountryRestriction();
    if($security_pack->checkBlocked()) {
        global $CONFIG;
        $language = Lang::getName();
        if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/" . strtolower($CONFIG["Language"]) . ".php";
        } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
            include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
        }
        return [$_ADDONLANG["blocked_message"]];
    }
});
class SecurityPackCountryRestriction
{
    public $reload = false;
    public $settings = [];
    public $visitor_country = "";
    public $countries_data = [];
    public function __construct()
    {
        $this->settings = security_pack_settings();
        $this->countries_data = json_decode(file_get_contents(security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "countries.json"), true);
    }
    public function check()
    {
        if($this->settings["whitelist"]) {
            $ip_list = explode(PHP_EOL, $this->settings["whitelist"]);
            if($ip_list) {
                global $remote_ip;
                if(in_array($remote_ip, $ip_list)) {
                    unset($_SESSION["security_pack_blocked"]);
                    $this->redirect();
                }
            }
        }
        $this->checkBlocked();
        if($this->reload) {
            $this->redirect();
        }
    }
    public function redirect()
    {
        $this->setSession();
        ob_clean();
        ob_start();
        redirSystemURL(isset($_GET) && $_GET ? urldecode(http_build_query($_GET)) : "", App::getCurrentFilename() . ".php");
        exit;
    }
    public function setSession()
    {
        $_SESSION["security_pack_init"] = 1;
    }
    public function checkBlocked()
    {
        if(!$this->settings["country_restriction"]) {
            unset($_SESSION["security_pack_blocked"]);
            return false;
        }
        if(!$this->visitor_country) {
            $this->getCountry();
        }
        // Pure decision logic (mode: block-list/allow-list, unknown-country
        // policy) lives in the shared, unit-tested CountryRestrictionService
        // — this class is only responsible for wiring it up to the real
        // visitor country/session/event-log.
        $decision = \WHMCS\Module\Addon\Security_Pack\Security\CountryRestrictionService::evaluate($this->settings, $this->visitor_country ?: null);
        if($decision["blocked"]) {
            if(!isset($_SESSION["security_pack_blocked"]) && function_exists("security_pack_record_event")) {
                $label = $this->visitor_country ?: "unknown country";
                security_pack_record_event("country_restriction.blocked", "Visitor blocked by Country Restriction (" . $label . ").", ["country" => $this->visitor_country ?: null, "mode" => $decision["mode"], "reason" => $decision["reason"]], "warning");
            }
            $_SESSION["security_pack_blocked"] = 1;
            $this->reload = true;
            return true;
        }
        unset($_SESSION["security_pack_blocked"]);
        return false;
    }
    public function getCountry()
    {
        // Security Pack 2.8 fix: this used to read the raw WHMCS global
        // $remote_ip directly, bypassing the module's own trusted-proxy-
        // aware visitor IP resolver — every other feature (GeoIP Language
        // & Currency, IP Restrictions, Security Events, Security
        // Diagnostics) resolves the visitor IP via
        // security_pack_detect_visitor_ip($settings["ip_source"]), which
        // only trusts a forwarded-for style header (CF-Connecting-IP/
        // X-Forwarded-For/X-Real-IP) when it actually came through a
        // configured Trusted Proxy. Using a different, untrusted-header-
        // aware path here would have let a visitor spoof their apparent
        // country by sending a forged forwarding header. Falls back to
        // $remote_ip only if the shared resolver is unavailable, same
        // fallback already used by security_pack_record_event().
        $ip = function_exists("security_pack_detect_visitor_ip") ? security_pack_detect_visitor_ip($this->settings["ip_source"] ?? "auto") : "";
        if(!$ip) {
            global $remote_ip;
            $ip = $remote_ip ?: "";
        }
        // Shared, DB-cached resolver (defined in hooks.php), backed by
        // GeoIpManager -> the configured GeoProvider(s) -> the SAME
        // MaxMind database used by Language & Currency. Also used by the
        // admin Test-a-Lookup tool. No second GeoIP lookup/cache here.
        $country = security_pack_resolve_country($ip);
        if($country) {
            $this->visitor_country = $country;
            return true;
        }
        return false;
    }
}

?>