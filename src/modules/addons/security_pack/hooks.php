<?php
/*
 
 */

//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
define("security_pack_module_root", __DIR__);
global $SECURITY_PACK_SETTINGS;
$SECURITY_PACK_SETTINGS = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->pluck("value", "setting");
if(!is_array($SECURITY_PACK_SETTINGS)) {
    $SECURITY_PACK_SETTINGS = $SECURITY_PACK_SETTINGS->toArray();
}
if(isset($SECURITY_PACK_SETTINGS["password_reset"]) || isset($SECURITY_PACK_SETTINGS["ip_range_limits"])) {
    require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "user_security.php";
}
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "security_events.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "loginHistory.php";
if(isset($SECURITY_PACK_SETTINGS["country_restriction"]) && defined("CLIENTAREA")) {
    require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "disallow_countries.php";
}
if(isset($SECURITY_PACK_SETTINGS["lang_currency"])) {
    // Loaded in both client and admin area: the add_hook() calls inside
    // only ever fire in the client area, but the admin "Test a Lookup"
    // tool on the Language & Currency page needs the
    // SecurityPackLangCurrency class available too.
    require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "geoip_lang_currency.php";
}
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "content_protection.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "ip_restrictions.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "security_headers.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "csp_reports.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "security_intelligence.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "email_2fa.php";
require __DIR__ . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "two_factor_admin_display.php";
function security_pack_settings()
{
    global $SECURITY_PACK_SETTINGS;
    return $SECURITY_PACK_SETTINGS;
}

/**
 * Self-contained CSRF protection for security_pack's own forms/AJAX
 * calls. Deliberately doesn't rely on WHMCS core's check_token()/
 * generate_token() — different WHMCS builds/versions have shown
 * inconsistent behaviour with custom token names across multiple pages
 * sharing the admin session, so this module manages its own single,
 * stable per-session secret instead (classic double-submit pattern).
 */
function security_pack_csrf_token()
{
    if(empty($_SESSION["security_pack_csrf"])) {
        $_SESSION["security_pack_csrf"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["security_pack_csrf"];
}

function security_pack_csrf_valid()
{
    $token = (string) ($_REQUEST["security_pack_token"] ?? "");
    $expected = (string) ($_SESSION["security_pack_csrf"] ?? "");
    return $token !== "" && $expected !== "" && hash_equals($expected, $token);
}

function security_pack_mmdb_path()
{
    return security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "GeoLite2-Country.mmdb";
}

/**
 * Returns a cached MaxMindDb\Reader instance for the uploaded database, or
 * null if none is uploaded / it fails to load (corrupt file, unsupported
 * format, etc — never fatal, we just fall back to the curl providers).
 */
function security_pack_mmdb_reader()
{
    static $reader = false;
    if($reader !== false) {
        return $reader;
    }
    $path = security_pack_mmdb_path();
    if(!file_exists($path)) {
        $reader = null;
        return $reader;
    }
    require_once security_pack_module_root . "/lib/MaxMindDb/Reader.php";
    try {
        $reader = new \WHMCS\Module\Addon\Security_Pack\MaxMindDb\Reader($path);
    } catch (\Throwable $e) {
        $reader = null;
    }
    return $reader;
}

/**
 * Shared GeoIP country lookup used by both the Country Restriction and the
 * Language & Currency features, so an IP is only ever looked up once (DB
 * cached) no matter how many features are enabled. Tries the uploaded
 * MaxMind GeoLite2-Country.mmdb first (fast, no network call); falls back
 * to the free curl-based providers if no database is uploaded or the
 * lookup misses.
 */
/**
 * Security Pack 2.2: thin backward-compatible wrapper. All the actual
 * caching/provider-selection/fallback logic now lives in
 * \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager (provider-based
 * architecture: GeoProviderInterface, MaxMindProvider, CurlApiProvider) —
 * this function is kept, with the same name and signature, purely so the
 * many existing call sites (Country Restriction, Language & Currency,
 * the admin Test-a-Lookup tool) don't all need touching. Uses the exact
 * same dctlab_security_pack_geo_cache table, so no cached data is lost on
 * upgrade.
 */
function security_pack_resolve_country($remote_ip = "")
{
    static $manager = null;
    if($manager === null) {
        $manager = new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager();
    }
    return (string) $manager->lookup((string) $remote_ip)->countryCode;
}


/**
 * Resolves the "real" visitor IP for the Language & Currency feature per
 * the configured Visitor IP Source setting. "auto" tries common CDN/proxy
 * headers in order (Cloudflare, then X-Forwarded-For, then X-Real-IP)
 * before falling back to REMOTE_ADDR; a specific source can also be forced
 * if the admin knows their exact server/CDN setup.
 */
/**
 * Checks whether $ip (normally $_SERVER['REMOTE_ADDR'], i.e. the actual
 * TCP peer) matches one of the admin-configured "Trusted Proxies"
 * (comma/newline separated single IPs or CIDR ranges, e.g.
 * 173.245.48.0/20 for Cloudflare, or a load balancer's internal IP).
 * Only forwarded-for style headers (CF-Connecting-IP, X-Forwarded-For,
 * X-Real-IP) from a trusted proxy should ever be believed — otherwise any
 * visitor can simply send their own fake X-Forwarded-For header and
 * spoof their country/IP for GeoIP, IP-range limiting, or country
 * restriction purposes.
 */
/**
 * Security Pack 2.1: thin wrapper — the actual CIDR-matching logic now
 * lives in \WHMCS\Module\Addon\Security_Pack\Security\IpUtil (pure,
 * dependency-free, unit-tested in tests/) so there is exactly one
 * authoritative implementation of "does this IP match this list" used by
 * both the Phase 1 trusted-proxy resolver and the Phase 2 IP Restrictions
 * service.
 */
function security_pack_is_trusted_proxy($ip, array $trustedProxies)
{
    return \WHMCS\Module\Addon\Security_Pack\Security\IpUtil::matchesAny((string) $ip, $trustedProxies);
}

/**
 * Parses the "Trusted Proxies" admin setting into an array of entries.
 */
function security_pack_trusted_proxies_list()
{
    $settings = security_pack_settings();
    return \WHMCS\Module\Addon\Security_Pack\Security\IpUtil::parseList((string) ($settings["trusted_proxies"] ?? ""));
}

/**
 * Resolves the "real" visitor IP for GeoIP / IP-range / country
 * restriction purposes, per the configured Visitor IP Source setting.
 *
 * Security Pack 2.0: this is now trusted-proxy aware. When the admin has
 * configured a Trusted Proxies list (Diagnostics/Advanced settings), a
 * forwarded-for style header (CF-Connecting-IP / X-Forwarded-For /
 * X-Real-IP) is only honoured if the direct TCP peer (REMOTE_ADDR) is
 * itself one of those trusted proxies — otherwise any visitor could spoof
 * those headers directly and forge their own apparent IP/country.
 *
 * BACKWARD COMPATIBILITY: if no Trusted Proxies are configured (the
 * default — matches every pre-2.0 install), behaviour is unchanged from
 * 1.2.0: forwarded headers are trusted unconditionally when "auto" or a
 * specific header source is selected. Configuring Trusted Proxies is
 * what opts an install into the hardened behaviour; nothing is silently
 * changed for existing sites that don't set it, since doing so could
 * break sites that rely on a CDN/proxy header with no config UI to
 * express that trust today.
 */
function security_pack_detect_visitor_ip($source = "auto")
{
    $directPeer = isset($_SERVER["REMOTE_ADDR"]) ? $_SERVER["REMOTE_ADDR"] : "";
    $trustedProxies = security_pack_trusted_proxies_list();
    $proxyIsTrusted = $trustedProxies ? security_pack_is_trusted_proxy($directPeer, $trustedProxies) : null;

    if($proxyIsTrusted === false && $source !== "remoteaddr") {
        // Trusted Proxies IS configured but this request didn't come
        // through one of them — never trust a forwarded header from an
        // untrusted/unknown peer, always fall back to REMOTE_ADDR.
        if(function_exists("security_pack_lc_debug_log")) {
            security_pack_lc_debug_log("Untrusted peer {$directPeer} sent a forwarded-for header; ignoring it and using REMOTE_ADDR (Trusted Proxies is configured).");
        }
        return $directPeer ?: "";
    }

    $candidates = [];
    switch ($source) {
        case "cloudflare":
            $candidates = ["HTTP_CF_CONNECTING_IP"];
            break;
        case "xff":
            $candidates = ["HTTP_X_FORWARDED_FOR"];
            break;
        case "xrealip":
            $candidates = ["HTTP_X_REAL_IP"];
            break;
        case "remoteaddr":
            $candidates = ["REMOTE_ADDR"];
            break;
        case "auto":
        default:
            $candidates = ["HTTP_CF_CONNECTING_IP", "HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "REMOTE_ADDR"];
            break;
    }
    foreach ($candidates as $key) {
        if(empty($_SERVER[$key])) {
            continue;
        }
        $value = $_SERVER[$key];
        if($key === "HTTP_X_FORWARDED_FOR") {
            // May be a comma-separated proxy chain. When the direct peer
            // is a trusted proxy we still take the left-most (original
            // client) entry — a fully correct multi-hop trusted-chain walk
            // is intentionally out of scope here to keep this safe and
            // simple; single trusted edge proxy/CDN is the common case.
            $parts = explode(",", $value);
            $value = trim($parts[0]);
        }
        if(filter_var($value, FILTER_VALIDATE_IP)) {
            return $value;
        }
    }
    global $remote_ip;
    return $remote_ip ?: $directPeer;
}

/**
 * Lightweight, dependency-free crawler detection for the SEO Bot Bypass
 * setting — matches common search engine / link-preview bots so they
 * always see the site default language & currency instead of being
 * GeoIP-redirected, which would otherwise fragment indexing as
 * duplicate content.
 */
function security_pack_is_bot($userAgent = "")
{
    if(!$userAgent) {
        $userAgent = $_SERVER["HTTP_USER_AGENT"] ?? "";
    }
    if(!$userAgent) {
        return false;
    }
    return (bool) preg_match(
        "/bot|crawl|spider|slurp|mediapartners|facebookexternalhit|whatsapp|telegrambot|slackbot|discordbot|embedly|quora link preview|showyoubot|outbrain|pinterest\/|baiduspider|yandexbot|duckduckbot|applebot|semrushbot|ahrefsbot|mj12bot/i",
        $userAgent
    );
}

/**
 * Writes GeoIP lookup errors / skip-reasons to the WHMCS Activity Log when
 * the Language & Currency "Debug Logging" setting is turned on. A cheap
 * no-op otherwise, so it's safe to sprinkle liberally.
 */
function security_pack_lc_debug_log($message)
{
    $settings = security_pack_settings();
    if(empty($settings["lc_debug"]) || $settings["lc_debug"] == "0") {
        return;
    }
    // 2026-08-27: routed through security_pack_log_activity() so the
    // Settings page's "Disable System Activity Log" master switch also
    // covers this debug channel — behavior otherwise unchanged (still
    // gated on lc_debug above, still a try/catch no-op on failure).
    security_pack_log_activity("[DCTLAB Security Pack] Language & Currency: " . $message);
}

/**
 * 2026-08-27: single choke point for every logActivity() call this addon
 * makes on its own behalf (audit trail entries, diagnostic markers, etc)
 * — lets an admin turn off "System Activity Log" writes for DCTLAB
 * Security Pack from the Settings page without touching WHMCS's own
 * native logging (WHMCS core and other modules/hooks calling
 * logActivity() directly are completely unaffected; this only gates
 * calls that are routed through this wrapper).
 *
 * Default is ENABLED (matches every existing install's current
 * behavior) — the setting is only ever checked for the OFF state, so an
 * upgrade with no explicit choice made yet changes nothing.
 */
function security_pack_log_activity($message, $relid = 0)
{
    $settings = security_pack_settings();
    if(isset($settings["disable_activity_log"])) {
        return;
    }
    try {
        if($relid) {
            logActivity($message, $relid);
        } else {
            logActivity($message);
        }
    } catch (\Throwable $e) {
    }
}

function security_pack_get_browser($user_agent = "")
{
    $browser = 'Unknown Browser';

    $browsers = [
        '/edg/i'         => 'Microsoft Edge',
        '/opr/i'         => 'Opera',
        '/vivaldi/i'     => 'Vivaldi',
        '/brave/i'       => 'Brave',
        '/chrome/i'      => 'Chrome',
        '/samsungbrowser/i' => 'Samsung Internet',
        '/firefox/i'     => 'Firefox',
        '/msie/i'        => 'Internet Explorer',
        '/trident/i'     => 'Internet Explorer',
        '/safari/i'      => 'Safari',
        '/mobile/i'      => 'Mobile Browser'
    ];

    foreach ($browsers as $regex => $value) {
        if (preg_match($regex, $user_agent)) {
            $browser = $value;
            break;
        }
    }

    return $browser;
}

/*function security_pack_get_browser($user_agent = "")
{
    $browser = "N/A";
    $browsers = ["/msie/i" => "Internet explorer", "/firefox/i" => "Firefox", "/safari/i" => "Safari", "/chrome/i" => "Chrome", "/edge/i" => "Edge", "/opera/i" => "Opera", "/mobile/i" => "Mobile browser"];
    foreach ($browsers as $regex => $value) {
        if(preg_match($regex, $user_agent)) {
            $browser = $value;
        }
    }
    return $browser;
}*/



/*function security_pack_get_os($user_agent)
{
    $os_platform = "N/A";
    $os_array = ["/windows nt 10/i" => "Windows 10", "/windows nt 6.3/i" => "Windows 8.1", "/windows nt 6.2/i" => "Windows 8", "/windows nt 6.1/i" => "Windows 7", "/windows nt 6.0/i" => "Windows Vista", "/windows nt 5.2/i" => "Windows Server 2003/XP x64", "/windows nt 5.1/i" => "Windows XP", "/windows xp/i" => "Windows XP", "/windows nt 5.0/i" => "Windows 2000", "/windows me/i" => "Windows ME", "/win98/i" => "Windows 98", "/win95/i" => "Windows 95", "/win16/i" => "Windows 3.11", "/macintosh|mac os x/i" => "Mac OS X", "/mac_powerpc/i" => "Mac OS 9", "/linux/i" => "Linux", "/ubuntu/i" => "Ubuntu", "/iphone/i" => "iPhone", "/ipod/i" => "iPod", "/ipad/i" => "iPad", "/android/i" => "Android", "/blackberry/i" => "BlackBerry", "/webos/i" => "Mobile"];
    foreach ($os_array as $regex => $value) {
        if(preg_match($regex, $user_agent)) {
            $os_platform = $value;
        }
    }
    return $os_platform;
}
*/
function security_pack_get_os($user_agent)
{
    $os_platform = 'Unknown OS';

    $os_array = [
        '/windows nt 11.0/i'     => 'Windows 11',
        '/windows nt 10.0/i'     => 'Windows 10',
        '/windows nt 6.3/i'      => 'Windows 8.1',
        '/windows nt 6.2/i'      => 'Windows 8',
        '/windows nt 6.1/i'      => 'Windows 7',
        '/windows nt 6.0/i'      => 'Windows Vista',
        '/windows nt 5.2/i'      => 'Windows Server 2003/XP x64',
        '/windows nt 5.1/i'      => 'Windows XP',
        '/windows xp/i'          => 'Windows XP',
        '/windows nt 5.0/i'      => 'Windows 2000',
        '/windows me/i'          => 'Windows ME',
        '/win98/i'               => 'Windows 98',
        '/win95/i'               => 'Windows 95',
        '/win16/i'               => 'Windows 3.11',

        // macOS and Mac OS
        '/macintosh|mac os x/i'  => 'macOS',
        '/mac os x 10[._]15/i'   => 'macOS Catalina',
        '/mac os x 11[._]/i'     => 'macOS Big Sur',
        '/mac os x 12[._]/i'     => 'macOS Monterey',
        '/mac os x 13[._]/i'     => 'macOS Ventura',
        '/mac os x 14[._]/i'     => 'macOS Sonoma',
        '/mac_powerpc/i'         => 'Mac OS 9',

        // Linux distros
        '/ubuntu/i'              => 'Ubuntu',
        '/debian/i'              => 'Debian',
        '/fedora/i'              => 'Fedora',
        '/linux/i'               => 'Linux',

        // Chrome OS and KaiOS
        '/cros/i'                => 'Chrome OS',
        '/kaios/i'               => 'KaiOS',

        // Mobile devices
        '/iphone/i'              => 'iPhone',
        '/ipod/i'                => 'iPod',
        '/ipad/i'                => 'iPad',

        // Android versions
        '/android 14/i'          => 'Android 14',
        '/android 13/i'          => 'Android 13',
        '/android 12/i'          => 'Android 12',
        '/android 11/i'          => 'Android 11',
        '/android 10/i'          => 'Android 10',
        '/android/i'             => 'Android',

        // Others
        '/blackberry/i'          => 'BlackBerry',
        '/webos/i'               => 'Mobile'
    ];

    foreach ($os_array as $regex => $value) {
        if (preg_match($regex, $user_agent)) {
            $os_platform = $value;
            break;
        }
    }

    return $os_platform;
}


?>