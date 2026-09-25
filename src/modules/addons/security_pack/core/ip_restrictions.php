<?php

declare(strict_types=1);

// Security Pack 2.2 — IP Restrictions enforcement.
//
// Step 18 of the 2.2 spec: deliberately scoped to the CLIENT AREA only,
// for guests, mirroring the exact same integration point the existing
// (1.2.0) Country Restriction feature already uses safely
// (core/disallow_countries.php's ClientAreaPage/ClientDetailsValidation
// hooks) — this is a proven-safe hook location for this codebase, not a
// new experiment. Admin area enforcement and login-time enforcement are
// intentionally NOT implemented in this phase (see CHANGELOG "Deferred")
// — blocking the admin area from itself is a much higher-consequence
// mistake than blocking a storefront visitor, and deserves its own
// careful design rather than being folded in here.

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Cheap existence check so a site with zero IP rules (every upgraded
 * install, until an admin opts in) pays for one small indexed COUNT
 * query per request at most — never a bigger scan, and it fails open
 * (treated as "no rules") on any DB error.
 */
function security_pack_ip_restrictions_active()
{
    static $active = null;
    if($active !== null) {
        return $active;
    }
    try {
        $active = (bool) Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")
            ->where("enabled", 1)
            ->where(function ($q) {
                $q->whereNull("expires_at")->orWhere("expires_at", ">", date("Y-m-d H:i:s"));
            })
            ->count();
    } catch (\Throwable $e) {
        $active = false;
    }
    return $active;
}

add_hook("ClientAreaPage", 2, function ($vars) {
    if(isset($_SESSION["adminid"]) || isset($_SESSION["uid"])) {
        // Never enforced against a logged-in client or an admin
        // impersonating/browsing the client area — same scope guard the
        // existing Country Restriction hook already uses.
        return null;
    }
    if(!security_pack_ip_restrictions_active()) {
        return null;
    }
    $settings = security_pack_settings();
    $ip = function_exists("security_pack_detect_visitor_ip") ? security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto") : "";
    if(!$ip) {
        return null;
    }
    $result = \WHMCS\Module\Addon\Security_Pack\Security\IpRestrictionService::evaluate($ip);
    if($result["allowed"]) {
        return null;
    }
    if(function_exists("security_pack_record_event")) {
        security_pack_record_event("ip_rule.blocked", "Visitor blocked by IP Restrictions (" . $result["reason"] . ").", ["ip" => $ip, "matched_rule" => $result["matched_rule"]["target"] ?? null], "warning");
    }
    global $CONFIG;
    $language = class_exists("Lang") ? Lang::getName() : "english";
    $_ADDONLANG = [];
    if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php")) {
        include ROOTDIR . "/modules/addons/security_pack/lang/" . $language . ".php";
    } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
        include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
    }
    ob_clean();
    ob_start();
    header("HTTP/1.1 403 Forbidden");
    echo "<!DOCTYPE html><html><head><title>Access Restricted</title></head><body style=\"font-family:sans-serif;text-align:center;padding:60px 20px;\"><h1>Access Restricted</h1><p>" . htmlspecialchars($_ADDONLANG["blocked_message"] ?? "Your IP address is not permitted to access this site.", ENT_QUOTES, "UTF-8") . "</p></body></html>";
    exit;
});
