<?php


//  file for php version 74.
if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
add_hook("AdminLogin", 1, function ($vars) {
    $settings = security_pack_settings();
    global $remote_ip;
    if(isset($settings["admin_login_notification"]) && $settings["admin_login_notification"] != "0") {
        $login_notification = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("client_id", $vars["adminid"])->where("is_admin", 1)->first();
        if(!$login_notification) {
            $login_notification = new stdClass();
            if(isset($settings["login_notification_default"])) {
                $login_notification->allowed = 1;
            } else {
                $login_notification->allowed = 0;
            }
        }
        if($login_notification->allowed) {
            if($settings["admin_login_notification"] == "1") {
                sendAdminMessage("Security Pack - Admin Login Notification", ["security_pack_email" => $vars["username"], "security_pack_ip" => $remote_ip, "security_pack_os" => security_pack_get_os($_SERVER["HTTP_USER_AGENT"]), "security_pack_browser" => security_pack_get_browser($_SERVER["HTTP_USER_AGENT"])], "system", 0, $vars["adminid"]);
            } else {
                $is_new = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("is_admin", 1)->where("client_id", $vars["adminid"])->where("ip", $remote_ip)->count();
                if(!$is_new) {
                    sendAdminMessage("Security Pack - Admin Login Notification", ["security_pack_email" => $vars["username"], "security_pack_ip" => $remote_ip, "security_pack_os" => security_pack_get_os($_SERVER["HTTP_USER_AGENT"]), "security_pack_browser" => security_pack_get_browser($_SERVER["HTTP_USER_AGENT"])], "system", 0, $vars["adminid"]);
                }
            }
        }
    }
    if(isset($settings["login_history"]) && isset($settings["admin_history"])) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->insert(["client_id" => intval($vars["adminid"]), "ip" => $remote_ip, "is_admin" => 1, "browser" => $_SERVER["HTTP_USER_AGENT"], "logged_at" => date("Y-m-d H:i:s")]);
    }
    if(function_exists("security_pack_record_event")) {
        security_pack_record_event("login.admin.success", "Admin login: " . ($vars["username"] ?? ""), ["username" => $vars["username"] ?? ""]);
    }
});
add_hook("UserLogin", 1, function ($vars) {
    if(isset($_SESSION["adminid"]) || !defined("CLIENTAREA")) {
        return NULL;
    }
    $settings = security_pack_settings();
    if(isset($settings["login_notification"]) && $settings["login_notification"] != "0") {
        global $remote_ip;
        if($vars["user"]->getClientIds()) {
            foreach ($vars["user"]->getClientIds() as $clientId) {
                $login_notification = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("client_id", $clientId)->where("is_admin", 0)->first();
                if(!$login_notification) {
                    $login_notification = new stdClass();
                    if(isset($settings["login_notification_default"])) {
                        $login_notification->allowed = 1;
                    } else {
                        $login_notification->allowed = 0;
                    }
                }
                if($login_notification->allowed) {
                    if($settings["login_notification"] == "1") {
                        sendMessage("Security Pack - Login Notification", $clientId, ["security_pack_email" => $vars["user"]->email, "security_pack_ip" => $remote_ip, "security_pack_os" => security_pack_get_os($_SERVER["HTTP_USER_AGENT"]), "security_pack_browser" => security_pack_get_browser($_SERVER["HTTP_USER_AGENT"])]);
                    } else {
                        $is_new = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("is_admin", 0)->where("client_id", $clientId)->where("ip", $remote_ip)->count();
                        if(!$is_new) {
                            sendMessage("Security Pack - Login Notification", $clientId, ["security_pack_email" => $vars["user"]->email, "security_pack_ip" => $remote_ip, "security_pack_os" => security_pack_get_os($_SERVER["HTTP_USER_AGENT"]), "security_pack_browser" => security_pack_get_browser($_SERVER["HTTP_USER_AGENT"])]);
                        }
                    }
                }
            }
        }
    }
    if(isset($settings["login_history"])) {
        $_SESSION["nnm_start_log_history"] = 1;
    }
    if(function_exists("security_pack_record_event")) {
        security_pack_record_event("login.client.success", "Client login.", []);
    }
});
add_hook("PreDeleteClient", 1, function ($vars) {
    Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("userid", $vars["userid"])->delete();
    Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("is_admin", 0)->where("client_id", $vars["userid"])->delete();
});
add_hook("ClientAreaPage", 1, function ($vars) {
    if(isset($_SESSION["nnm_start_log_history"])) {
        unset($_SESSION["nnm_start_log_history"]);
        $currentUser = new WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if(!$user) {
            return NULL;
        }
        global $remote_ip;
        foreach ($user->getClientIds() as $clientId) {
            logClientLoginHistory($clientId, $remote_ip, $_SERVER["HTTP_USER_AGENT"]);
        }
    }
});
// 2.7.7: the `ClientAreaSecondaryNavbar` hook that used to live here
// (adding items to the "Your Profile" / "Account" dropdown in the
// client area) has been removed entirely, per explicit user request.
// It previously added two items — Login History (added 2.1.0) and
// "Account Security" / Client Security Center (added 2.3.0, already
// removed in 2.7.6) — both are now gone, so the hook itself would be a
// pure no-op if left in place. The underlying pages/controllers
// (`index.php?m=security_pack&page=login_history` and
// `...page=security_center`) are UNCHANGED and still reachable directly
// by URL — only the automatic menu injection was removed. No separate
// "Account Settings" sidebar link/page either (removed 2026-08-15 per
// explicit user request, for the same reason: Login Notification,
// Disable Forgot Password Reset, and Session IP Security Limits render
// directly on Lagom2's native Security Settings page — see
// core/user_security.php).
/**
 * Security Pack 2.7.8 — "Account Security" added back, this time as a
 * CHILD of the existing WHMCS "Account" item inside the client area's
 * PRIMARY sidebar. The earlier 2.7.5 attempt added it as a new
 * top-level primary-sidebar item instead of nesting it (icon-setting
 * API unconfirmed at the time), and the 2.3.0-era secondary-navbar
 * attempt found `getChild("Account")` returned null on this WHMCS/
 * Lagom2 combination for THAT navbar. This hook and its exact
 * addChild()/setAttribute() structure are per user-supplied, confirmed-
 * working reference code — `getChild("Account")` DOES resolve on the
 * PRIMARY sidebar (a real node exists there), unlike the secondary
 * navbar case. Session check mirrors the reference exactly
 * ($_SESSION["uid"], WHMCS's client-area session identity key) rather
 * than the CurrentUser API used elsewhere in this file.
 */
add_hook("ClientAreaPrimarySidebar", 1, function ($primarySidebar) {
    if(!isset($_SESSION["uid"]) || empty($_SESSION["uid"])) {
        return;
    }
    $account = $primarySidebar->getChild("Account");
    if(!$account) {
        return;
    }

    $settings = security_pack_settings();
    global $CONFIG;
    $main_language = Lang::getName();
    if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
        include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
    } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
        include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
    } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
        include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
    }
    $label = $_ADDONLANG["security_center_title"] ?? "Account Security";

    $accountSecurity = $account->addChild(
        "Account Security",
        [
            "label" => $label,
            "uri" => "index.php?m=security_pack&page=security_center",
            "order" => 100,
            "icon" => "fas fa-shield-alt",
        ]
    );
    if($accountSecurity) {
        $accountSecurity->setAttribute(
            "class",
            "account-security-sidebar"
        );
    }
});
add_hook("AdminAreaFooterOutput", 1, function ($vars) {
    if(isset($_REQUEST["userid"]) && is_numeric($_REQUEST["userid"])) {
        $settings = security_pack_settings();
        if(isset($settings["login_history"])) {
            return "<script>var security_pack_userid = \"" . intval($_REQUEST["userid"]) . "\";var security_pack_active = \"" . (App::getCurrentFilename() == "addonmodules" && isset($_REQUEST["module"]) && $_REQUEST["module"] == "security_pack" && isset($_REQUEST["a"]) && $_REQUEST["a"] == "user" ? "active" : "") . "\";</script><script type=\"text/javascript\" src=\"../modules/addons/security_pack/assets/js/user_logs.js\"></script>";
        }
    }
});
add_hook("DailyCronJob", 1, function ($vars) {
    $settings = security_pack_settings();
    $days = isset($settings["auto_delete_days"]) ? intval($settings["auto_delete_days"]) : 30;
    if(isset($settings["auto_delete"]) && $days) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("logged_at", "<", Carbon\Carbon::now()->subDays($days)->toDateTimeString())->delete();
    }
    if(function_exists("security_pack_prune_events")) {
        security_pack_prune_events();
    }
    if(class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\RateLimiter")) {
        \WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::prune();
    }
});
add_hook("AdminAreaPage", 1, function ($vars) {
    if(App::getCurrentFilename() == "myaccount") {
        global $aInt;
        $settings = security_pack_settings();
        if(isset($settings["login_history"]) && isset($settings["allow_disable_notification"])) {
            $login_notification = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("client_id", intval($_SESSION["adminid"]))->where("is_admin", 1)->first();
            if(!$login_notification) {
                $login_notification = new stdClass();
                if(isset($settings["login_notification_default"])) {
                    $login_notification->allowed = 1;
                } else {
                    $login_notification->allowed = 0;
                }
            }
            $newTableHtml = "<tr>\r\n    <td width=\"20%\" class=\"fieldlabel\">Login Email Notification</td>\r\n    <td class=\"fieldarea\" style=\"word-wrap: normal\">\r\n        <label class=\"checkbox-inline\">\r\n                <input type=\"checkbox\" " . ($login_notification->allowed ? "checked=\"\"" : "") . " name=\"nnm_login_notification\" value=\"1\">\r\n                Check this checkbox to get email when login to admin area.\r\n            </label></td></tr>";
            $lastTablePos = strpos($aInt->content, "</table>");
            if($lastTablePos !== false) {
                $aInt->content = substr_replace($aInt->content, $newTableHtml, $lastTablePos, 0);
            }
        }
    }
});
if(defined("ADMINAREA") && isset($_SESSION["adminid"]) && App::getCurrentFilename() == "myaccount" && isset($_REQUEST["action"]) && $_REQUEST["action"] == "save") {
    $settings = security_pack_settings();
    if(isset($settings["login_history"]) && isset($settings["allow_disable_notification"])) {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->updateOrInsert(["client_id" => intval($_SESSION["adminid"]), "is_admin" => 1], ["client_id" => intval($_SESSION["adminid"]), "is_admin" => 1, "allowed" => isset($_REQUEST["nnm_login_notification"]) && $_REQUEST["nnm_login_notification"] ? 1 : 0]);
    }
}
function logClientLoginHistory($clientId = "", $ip = "", $browser = "")
{
    Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->insert(["client_id" => $clientId, "ip" => $ip, "is_admin" => 0, "browser" => $browser, "logged_at" => date("Y-m-d H:i:s")]);
}

?>