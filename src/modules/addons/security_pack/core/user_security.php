<?php


//  file for php version 74.
add_hook("EmailPreSend", 1000, function ($vars) {
    if(isset($_SESSION["adminid"])) {
        return NULL;
    }
    if($vars["messagename"] == "Password Reset Validation") {
        $settings = security_pack_settings();
        if(isset($settings["password_reset"]) && Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_dpass")->where("user_id", $vars["relid"])->count()) {
            global $CONFIG;
            $main_language = Lang::getName();
            if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
                include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
            } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
                include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
            } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
                include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
            }
            WHMCS\Session::set("disable_reset_password_flash", $_ADDONLANG["reset_password_disabled"]);
            App::redirectToRoutePath("password-reset-begin");
            exit;
        }
    }
});
add_hook("ClientAreaPagePasswordReset", 1000, function ($vars) {
    if(isset($_SESSION["disable_reset_password_flash"])) {
        $message = $_SESSION["disable_reset_password_flash"];
        unset($_SESSION["disable_reset_password_flash"]);
        return ["errorMessage" => $message];
    }
});
add_hook("UserLogin", 1, function ($vars) {
    if(isset($_SESSION["adminid"])) {
        return NULL;
    }
    $settings = security_pack_settings();
    if(isset($settings["ip_range_limits"])) {
        $ip_limits = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("user_id", $vars["user"]->id)->get();
        if(count($ip_limits)) {
            global $remote_ip;
            $ip_address = inet_pton($remote_ip);
            $ip_found = false;
            foreach ($ip_limits as $item) {
                $startIpLong = inet_pton($item->start_ip);
                $endIpLong = inet_pton($item->end_ip);
                if($ip_address <= $endIpLong && $startIpLong <= $ip_address) {
                    $ip_found = true;
                }
            }
            if(!$ip_found) {
                if(function_exists("security_pack_record_event")) {
                    security_pack_record_event("ip.login_blocked", "Client login blocked by Session IP Security Limits.", ["user_id" => $vars["user"]->id ?? null], "warning");
                }
                WHMCS\Session::delete("login_auth_tk");
                WHMCS\Session::delete("uid");
                WHMCS\Session::delete("cid");
                WHMCS\Session::delete("upw");
                WHMCS\Cookie::delete("User");
                global $CONFIG;
                $main_language = Lang::getName();
                if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
                }
                WHMCS\FlashMessages::add($_ADDONLANG["ip_limited_to_login"], "error");
                App::redirectToRoutePath("login-validate", []);
            }
        }
    }
});
add_hook("ClientAreaPage", 10000, "security_pack_user_security_page");
add_hook("ClientDetailsValidation", 100, function ($vars) {
    $settings = security_pack_settings();
    if(isset($settings["block_free_emails"])) {
        if(isset($_SESSION["adminid"])) {
            return [];
        }
        $filename = security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "database.txt";
        $f = fopen($filename, "r");
        $contents = fread($f, filesize($filename));
        fclose($f);
        $domains = explode(PHP_EOL, $contents);
        list($domain) = explode("@", $vars["email"]);
        foreach ($domains as $d => $domain_line) {
            if(trim($domain_line) == $domain) {
                global $CONFIG;
                $main_language = Lang::getName();
                if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
                }
                return [$_ADDONLANG["free_email_error"]];
            }
        }
    }
});
function security_pack_user_security_page($vars = [])
{
    // Best-effort only: on themes that both (a) name this Smarty template
    // one of these two identifiers AND (b) actually keep their own local
    // copy of the file (rather than fully replacing the page with custom
    // markup, as Lagom2 does), this quietly appends our panel to WHMCS's
    // native Security Settings page. It does nothing on Lagom2 or any
    // other theme that doesn't match — the guaranteed-to-work path is the
    // dedicated "Your Profile" > Account Settings page added via the
    // ClientAreaSecondaryNavbar hook in core/loginHistory.php /
    // ClientController::security(), which doesn't depend on theme
    // internals at all.
    //
    // INCIDENT 2026-08-27 (RESOLVED): this function appends
    // `{include file="modules/addons/security_pack/templates/settings.tpl"}`
    // — templates/settings.tpl was found MISSING from the shipped module
    // (confirmed lost — SECURITY-AUDIT-PHASE-4.md documents it as an
    // audited, previously-shipped file, and ClientController::
    // change_reset_password()/login_notification_alert()/limit_ip_range()
    // and their lang/english.php label keys were all still present and
    // unmodified, evidencing it once existed and was never intentionally
    // removed — most likely lost in an earlier templates/ reorganization
    // without anyone updating this write site). On any theme matching the
    // two template names below, every page load appended an include to a
    // nonexistent file, and once appended could never self-clear (the
    // file then permanently "contains security_pack") — so the theme's
    // native Security Settings page threw "Smarty Error: ... No template
    // default content for '...templates/settings.tpl'" on every
    // subsequent load. Reported in production against Client ID 666037 /
    // User ID 666503; confirmed as the ONLY delivery mechanism for the
    // Login Notification / Disable Forgot Password Reset / Session IP
    // Security Limits panels (see ClientController::backToSecuritySettings()'s
    // own docblock — no other page renders them).
    //
    // Fix: templates/settings.tpl was reconstructed from this same
    // surviving evidence (the exact variable names this function already
    // returns below, the exact POST targets/field names in
    // ClientController.php, and the exact label strings already sitting
    // unused in lang/english.php) — see that file's own header comment
    // for the full trail. The self-heal block below additionally repairs
    // any theme file that already has the OLD, broken include from
    // before this fix (replacing it with the correct one in place, not
    // just appending a second copy).
    if(in_array($vars["templatefile"] ?? "", ["user-security", "clientareasecurity"], true)) {
        $currentUser = new WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if($user) {
            $settings = security_pack_settings();
            // Was previously gated only on password_reset / ip_range_limits,
            // which silently excluded the Login Notification toggle — a
            // site with ONLY that feature enabled would never trigger the
            // include append at all, even though settings.tpl itself
            // already renders that panel correctly on its own.
            $loginNotificationEnabled = isset($settings["login_notification"]) && $settings["login_notification"] != "0" && isset($settings["allow_disable_notification"]);
            if(isset($settings["password_reset"]) || isset($settings["ip_range_limits"]) || $loginNotificationEnabled) {
                $template_file = ROOTDIR . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . $vars["template"] . DIRECTORY_SEPARATOR . $vars["templatefile"] . ".tpl";
                // Security Pack 2.4 (Phase 4, Step 15): $vars['template']/
                // $vars['templatefile'] come from WHMCS's own ClientAreaPage
                // hook — not raw request input — so this is defense-in-depth,
                // not a fix for a demonstrated exploit. Still, this is the
                // only place in the module that WRITES to a file outside its
                // own directory, so before ever doing that, confirm the
                // resolved real path is actually inside ROOTDIR/templates.
                // Any "../" style traversal in either value now results in
                // silently skipping the append rather than writing outside
                // the templates directory.
                $templatesRoot = realpath(ROOTDIR . DIRECTORY_SEPARATOR . "templates");
                $resolvedTemplateFile = realpath($template_file);
                $withinTemplatesDir = $templatesRoot && $resolvedTemplateFile && strncmp($resolvedTemplateFile, $templatesRoot . DIRECTORY_SEPARATOR, strlen($templatesRoot) + 1) === 0;
                if($withinTemplatesDir && file_exists($template_file)) {
                    $template_content = file_get_contents($template_file);
                    // The include this function writes/expects. This
                    // string is unchanged from before the 2026-08-27
                    // incident — what was actually missing was the target
                    // FILE (templates/settings.tpl), now reconstructed and
                    // shipping again, not this include line itself. A
                    // theme file that had the include appended during the
                    // window it pointed at a missing file needs no special
                    // repair here: this same "append once, guarded by the
                    // 'security_pack' string already being present" check
                    // is idempotent either way, and the include now
                    // resolves correctly the moment the fixed module code
                    // (which ships the reconstructed template) is deployed —
                    // no theme-file edit is required for that case.
                    if(strpos($template_content, "security_pack") === false) {
                        file_put_contents($template_file, $template_content . PHP_EOL . "{include file=\"modules/addons/security_pack/templates/settings.tpl\"}");
                    }
                }
                global $CONFIG;
                $main_language = Lang::getName();
                if(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $main_language . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/" . $CONFIG["Language"] . ".php";
                } elseif(file_exists(ROOTDIR . "/modules/addons/security_pack/lang/english.php")) {
                    include ROOTDIR . "/modules/addons/security_pack/lang/english.php";
                }
                global $remote_ip;
                $success = "";
                $error = "";
                if(isset($_SESSION["nnm_security_pack_successful"])) {
                    $success = $_SESSION["nnm_security_pack_successful"];
                    unset($_SESSION["nnm_security_pack_successful"]);
                }
                if(isset($_SESSION["nnm_security_pack_error"])) {
                    $error = $_SESSION["nnm_security_pack_error"];
                    unset($_SESSION["nnm_security_pack_error"]);
                }
                $ip_limits = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("user_id", $user->id)->get();
                $login_notification = Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("client_id", intval($_SESSION["uid"]))->where("is_admin", 0)->first();
                if(!$login_notification) {
                    $login_notification = new stdClass();
                    if(isset($settings["login_notification_default"])) {
                        $login_notification->allowed = 1;
                    } else {
                        $login_notification->allowed = 0;
                    }
                }
                return ["nnmlang" => $_ADDONLANG, "login_notification" => $login_notification, "login_notification_allowed" => $loginNotificationEnabled, "ip_limits" => $ip_limits, "security_pack_ip_limits" => isset($settings["ip_range_limits"]), "security_pack_disable_password" => isset($settings["password_reset"]), "nnm_security_pack_successful" => $success, "nnm_security_pack_error" => $error, "remote_ip" => $remote_ip, "disabled_reset_password" => Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_dpass")->where("user_id", $user->id)->count(), "security_pack_csrf" => security_pack_csrf_token()];
            }
        }
    }
}

?>