<?php


//  file for php version 74.
namespace WHMCS\Module\Addon\Security_Pack\Client;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}
class ClientController
{
    public function login_history($vars = [])
    {
        $settings = security_pack_settings();
        if(!isset($settings["client_history"]) || !isset($settings["login_history"])) {
            redir("", "clientarea.php");
        }
        $lang = $vars["_lang"];
        $logs = [];
        foreach (\Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("is_admin", 0)->where("client_id", intval($_SESSION["uid"]))->orderBy("id", "DESC")->get() as $item) {
            $logs[] = ["ip_address" => $item->ip, "os" => security_pack_get_os($item->browser), "browser" => security_pack_get_browser($item->browser), "date_time" => fromMySQLDate($item->logged_at, true)];
        }
        \Menu::primarySidebar("clientView");
        \Menu::secondarySidebar("clientView");
        return ["pagetitle" => $lang["login_history"], "breadcrumb" => ["clientarea.php" => $lang["client_area"], "index.php?m=security_pack&page=login_history" => $lang["login_history"]], "templatefile" => "templates/" . (file_exists(security_pack_module_root . DIRECTORY_SEPARATOR . "templates" . DIRECTORY_SEPARATOR . "custom-logs") ? "custom-logs" : "logs"), "requirelogin" => true, "vars" => ["logs" => $logs, "nnmlang" => $lang]];
    }
    /**
     * Security Pack 2.3 — Client Security Center ("Account Security").
     *
     * AUTHORIZATION (Step 11 of the 2.3 spec): every piece of data here
     * is scoped to \WHMCS\Authentication\CurrentUser()'s own resolved
     * client id, taken from the authenticated session — never from
     * $_REQUEST/$_GET/$_POST. There is no "client_id" parameter this
     * page reads at all, so there is nothing for another client to
     * tamper with to see someone else's data.
     *
     * SESSION MANAGEMENT (Step 10): WHMCS does not expose a supported,
     * addon-safe API for listing or remotely terminating a client's
     * *other* active sessions in this version — it uses PHP's native
     * server-side session handling, not a queryable multi-device session
     * table. Rather than fabricate an "Other Sessions" list from login
     * history rows (which are login EVENTS, not active sessions, and
     * would misrepresent stale/one-time entries as live sessions this
     * page could terminate), only the CURRENT request's own
     * browser/OS/IP/country is shown, clearly labeled, with the
     * limitation documented directly in the page (see the template).
     */
    public function security_center($vars = [])
    {
        $lang = $vars["_lang"];
        $settings = security_pack_settings();
        $currentUser = new \WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if(!$user) {
            redir("", "clientarea.php");
        }
        $clientId = (int) $user->id;

        global $remote_ip;
        $userAgent = $_SERVER["HTTP_USER_AGENT"] ?? "";
        $currentSession = [
            "browser" => security_pack_get_browser($userAgent),
            "os" => security_pack_get_os($userAgent),
            "ip" => $remote_ip ?: ($_SERVER["REMOTE_ADDR"] ?? ""),
            "country" => "",
        ];
        if($currentSession["ip"] && function_exists("security_pack_resolve_country")) {
            try {
                $currentSession["country"] = security_pack_resolve_country($currentSession["ip"]);
            } catch (\Throwable $e) {
            }
        }

        // Authentication status — only ever reflects real state, never
        // assumed. Each feature is only shown if the admin has actually
        // enabled the underlying setting.
        $loginNotificationAllowed = isset($settings["login_notification"]) && $settings["login_notification"] != "0" && isset($settings["allow_disable_notification"]);
        $loginNotificationOn = false;
        if($loginNotificationAllowed) {
            $opt = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->where("client_id", $clientId)->where("is_admin", 0)->first();
            $loginNotificationOn = $opt ? (bool) $opt->allowed : (bool) ($settings["login_notification_default"] ?? false);
        }

        $passwordResetProtectionAvailable = isset($settings["password_reset"]);
        $passwordResetDisabled = $passwordResetProtectionAvailable
            ? (bool) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_dpass")->where("user_id", $clientId)->count()
            : false;

        // WHMCS core Two-Factor Authentication status — deliberately
        // defensive. This module does not own WHMCS's own 2FA feature,
        // and guessing at an internal table/column name that turns out
        // wrong would risk either a fatal error or, worse, incorrectly
        // claiming 2FA is off when it's on (or vice versa). If it can't
        // be determined safely, the section is simply omitted rather
        // than showing a guess.
        $twoFactorStatus = null; // null = unknown/not shown, true/false = known
        try {
            if(method_exists($user, "hasTwoFactorAuthenticationEnabled")) {
                $twoFactorStatus = (bool) $user->hasTwoFactorAuthenticationEnabled();
            } elseif(\Illuminate\Database\Capsule\Manager::schema()->hasTable("tbltwofactor")) {
                $twoFactorStatus = (bool) \Illuminate\Database\Capsule\Manager::table("tbltwofactor")->where("user_id", $clientId)->count();
            }
        } catch (\Throwable $e) {
            $twoFactorStatus = null;
        }

        $ipLimitsAvailable = isset($settings["ip_range_limits"]);
        $ipLimitCount = $ipLimitsAvailable
            ? \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("user_id", $clientId)->count()
            : 0;

        // Security Pack 2.6 — Email Two-Factor Authentication (THE
        // authoritative Email 2FA implementation — see
        // Email2faService). ARCHITECTURE CORRECTION (2.6.1): this is now
        // a native WHMCS Security Module (modules/security/dct_email_2fa)
        // rather than an addon-settings-gated feature — WHETHER it is
        // offered at all is controlled by WHMCS itself (Setup > Security
        // > Two-Factor Authentication, "Activate"), not by any setting
        // this addon owns. This section is therefore read-only status
        // display only, shown whenever the tracking table is reachable
        // (i.e. this addon's tables exist) — never a control surface.
        $email2faAvailable = false;
        $whatsapp2faAvailable = false;
        $totp2faAvailable = false;
        try {
            $email2faAvailable = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa");
            $whatsapp2faAvailable = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_whatsapp2fa");
            $totp2faAvailable = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_totp2fa");
        } catch (\Throwable $e) {
        }

        // Security Pack 3.0/post-3.1.0 — Email/DCTLAB WhatsApp/Time-Based
        // Token status is read EXCLUSIVELY through the ONE authoritative
        // TwoFactorAuthenticationService::status() call below — this
        // controller does NOT independently query each method's own
        // table anymore (that was the root cause of a real bug where
        // this page could show more than one method as "Active" at
        // once: each row was computed from its own table in isolation,
        // with nothing enforcing that only one method may actually be
        // active). status() also self-heals any account left in that
        // inconsistent state from before this fix (see that method's
        // own docblock) — the DB itself, not just this display, ends up
        // with at most one active method. WHETHER each method is
        // offered at all is still controlled by WHMCS's own native
        // Setup > Security > Two-Factor Authentication screen, not by
        // this addon; this remains status display only, never a
        // control surface.
        $twoFaStatus = ($email2faAvailable || $whatsapp2faAvailable || $totp2faAvailable)
            ? \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService::status($clientId, "client")
            : ["email" => ["active" => false, "pending" => false], "whatsapp" => ["active" => false, "pending" => false], "totp" => ["active" => false, "pending" => false], "active_method" => null, "recovery_codes_remaining" => 0];

        $email2faStatus = $twoFaStatus["email"]["active"] ? "active" : ($twoFaStatus["email"]["pending"] ? "pending" : "disabled");
        $email2faConfig = $email2faAvailable
            ? \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::getConfig($clientId, "client")
            : null;
        $email2faMaskedEmail = $email2faConfig ? \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::maskEmail((string) $email2faConfig->email) : "";
        $email2faBypass = $email2faStatus === "active"
            ? \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::findActiveBypass($clientId, "client", $this->e2faIp())
            : null;

        $whatsapp2faStatus = $twoFaStatus["whatsapp"]["active"] ? "active" : ($twoFaStatus["whatsapp"]["pending"] ? "pending" : "disabled");
        $totp2faStatus = $twoFaStatus["totp"]["active"] ? "active" : ($twoFaStatus["totp"]["pending"] ? "pending" : "disabled");
        $totp2faActive = $twoFaStatus["totp"]["active"]; // kept for backward-compat template use below
        $activeTwoFactorMethod = $twoFaStatus["active_method"]; // "email"|"whatsapp"|"totp"|null — at most one, enforced server-side
        $recoveryCodesRemaining = (int) ($twoFaStatus["recovery_codes_remaining"] ?? 0);

        // 2026-08-22 — Requirements doc Section 3: "if there is already
        // an appropriate client security/settings page, expose the
        // user's trusted browsers there" — this IS that page. Read-only
        // list here; revocation is its own CSRF+rate-limited POST action
        // below (revoke_trusted_browser()), same pattern as every other
        // toggle/action on this page. Never displays the token itself —
        // only the non-sensitive display metadata TrustedBrowserService
        // stores (device_label/created_ip/timestamps).
        $trustedBrowsers = [];
        if(class_exists(\WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::class)) {
            $currentTrustedToken = \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::readCookieToken();
            $currentTrustedHash = $currentTrustedToken !== "" ? \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::hashToken($currentTrustedToken) : "";
            foreach (\WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::listForIdentity($clientId, "client") as $row) {
                $trustedBrowsers[] = [
                    "id" => (int) $row->id,
                    "device_label" => (string) ($row->device_label ?? ""),
                    "created_ip" => (string) ($row->created_ip ?? ""),
                    "created_at" => fromMySQLDate($row->created_at, true),
                    "last_used_at" => $row->last_used_at ? fromMySQLDate($row->last_used_at, true) : "",
                    "expires_at" => fromMySQLDate($row->expires_at, true),
                    "is_this_browser" => $currentTrustedHash !== "" && hash_equals((string) $row->token_hash, $currentTrustedHash),
                ];
            }
        }

        // Recent activity — reuses the EXISTING login history table/
        // query pattern from login_history() above, scoped to this
        // client's own id only. Capped at 10 rows (bounded query, Step
        // 30 of the 2.3 spec) rather than loading full history here; the
        // full paginated list is still available via the separate Login
        // History page when enabled.
        $recentActivity = [];
        if(isset($settings["client_history"]) && isset($settings["login_history"])) {
            foreach (\Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_logins")->where("is_admin", 0)->where("client_id", $clientId)->orderBy("id", "DESC")->limit(10)->get() as $item) {
                $recentActivity[] = [
                    "ip_address" => $item->ip,
                    "os" => security_pack_get_os($item->browser),
                    "browser" => security_pack_get_browser($item->browser),
                    "date_time" => fromMySQLDate($item->logged_at, true),
                ];
            }
        }

        // Simplified client-facing "Your Security" status — deliberately
        // NOT the admin's internal 0-100 Security Score (that reflects
        // sitewide configuration an ordinary client has no control over
        // and no reason to see). Based only on this client's own
        // account state.
        $strengthPoints = 0;
        $strengthMax = 0;
        $recommendations = [];
        if($loginNotificationAllowed) {
            $strengthMax++;
            if($loginNotificationOn) {
                $strengthPoints++;
            } else {
                $recommendations[] = $lang["security_center_rec_enable_login_notification"] ?? "Turn on login alerts so you're notified of new sign-ins.";
            }
        }
        if($twoFactorStatus !== null) {
            $strengthMax++;
            if($twoFactorStatus) {
                $strengthPoints++;
            } else {
                $recommendations[] = $lang["security_center_rec_enable_2fa"] ?? "Two-factor authentication is not enabled — turn it on for stronger protection.";
            }
        }
        if($passwordResetProtectionAvailable) {
            $strengthMax++;
            $strengthPoints++; // available either way — client controls it directly below, not a warning state
        }
        // Security Pack 3.1.2 — FIX: this used to award the point (and
        // choose its recommendation text) purely from $email2faStatus,
        // ignoring WhatsApp/TOTP entirely. That meant a client with
        // DCTLAB WhatsApp 2FA (or TOTP) actively protecting their
        // account was still told "Email Two-Factor Authentication is
        // disabled — enable it", contradicting the Authentication
        // section immediately below it, which (since 3.1.1) already
        // correctly reads the ONE authoritative
        // TwoFactorAuthenticationService::status() active_method. This
        // block now consumes that SAME $activeTwoFactorMethod value
        // (computed once above, not re-derived here) via the pure,
        // unit-tested twoFactorRecommendation() helper below, so the
        // banner and the Authentication section can never disagree
        // again. The requirement is "at least one of the three methods
        // is active", not "Email specifically" — see that method's own
        // docblock.
        $twoFactorMethodAvailable = $email2faAvailable || $whatsapp2faAvailable || $totp2faAvailable;
        $twoFaRecommendation = self::twoFactorRecommendation(
            $twoFactorMethodAvailable,
            $activeTwoFactorMethod,
            $lang["security_center_rec_enable_2fa_unified"] ?? "Two-factor authentication is not enabled. Enable Email, DCTLAB WhatsApp, or Time-Based Tokens."
        );
        if($twoFaRecommendation["counts"]) {
            $strengthMax++;
            if($twoFaRecommendation["earns_point"]) {
                $strengthPoints++;
            } else {
                $recommendations[] = $twoFaRecommendation["recommendation"];
            }
        }
        $strengthLabel = $lang["security_center_strength_unknown"] ?? "Not enough data";
        if($strengthMax > 0) {
            $pct = $strengthPoints / $strengthMax;
            if($pct >= 0.99) {
                $strengthLabel = $lang["security_center_strength_strong"] ?? "Strong";
            } elseif($pct >= 0.5) {
                $strengthLabel = $lang["security_center_strength_good"] ?? "Good";
            } else {
                $strengthLabel = $lang["security_center_strength_weak"] ?? "Needs Attention";
            }
        }

        \Menu::primarySidebar("clientView");
        \Menu::secondarySidebar("clientView");

        return [
            "pagetitle" => $lang["security_center_title"] ?? "Account Security",
            "breadcrumb" => ["clientarea.php" => $lang["client_area"], "index.php?m=security_pack&page=security_center" => $lang["security_center_title"] ?? "Account Security"],
            "templatefile" => "templates/security_center",
            "requirelogin" => true,
            "vars" => [
                "nnmlang" => $lang,
                "current_session" => $currentSession,
                "login_notification_allowed" => $loginNotificationAllowed,
                "login_notification_on" => $loginNotificationOn,
                "password_reset_protection_available" => $passwordResetProtectionAvailable,
                "password_reset_disabled" => $passwordResetDisabled,
                "two_factor_status" => $twoFactorStatus,
                "email2fa_available" => $email2faAvailable,
                "email2fa_status" => $email2faStatus,
                "email2fa_masked_email" => $email2faMaskedEmail,
                "email2fa_bypass_active" => (bool) $email2faBypass,
                "email2fa_bypass_expires" => $email2faBypass ? fromMySQLDate($email2faBypass->expires_at, true) : "",
                "whatsapp2fa_available" => $whatsapp2faAvailable,
                "whatsapp2fa_status" => $whatsapp2faStatus,
                "totp2fa_available" => $totp2faAvailable,
                "totp2fa_active" => $totp2faActive,
                "totp2fa_status" => $totp2faStatus,
                "active_two_factor_method" => $activeTwoFactorMethod,
                "recovery_codes_remaining" => $recoveryCodesRemaining,
                "trusted_browsers" => $trustedBrowsers,
                "ip_limits_available" => $ipLimitsAvailable,
                "ip_limit_count" => $ipLimitCount,
                "recent_activity" => $recentActivity,
                "recent_activity_available" => isset($settings["client_history"]) && isset($settings["login_history"]),
                "strength_label" => $strengthLabel,
                "strength_recommendations" => $recommendations,
                "security_pack_csrf" => security_pack_csrf_token(),
            ],
        ];
    }

    /**
     * Security Pack 3.1.2 — the ONE decision behind the Authentication
     * banner's "is 2FA covered" contribution and recommendation text.
     * PURE (no DB access — unit tested directly, see tests/run.php):
     * takes only whether any of the three methods is even offered on
     * this install ($anyMethodAvailable) and which single method (if
     * any) TwoFactorAuthenticationService::status() already resolved as
     * authoritatively active ($activeMethod — "email"|"whatsapp"|"totp"|
     * null), and never re-derives that from any method-specific table
     * itself. Provider-neutral by construction: Email, DCTLAB WhatsApp,
     * and Time-Based Token all satisfy the requirement equally, and a
     * PENDING (not-yet-verified) enrollment on an unused method never
     * counts as active here — matching TwoFactorAuthenticationService's
     * own ACTIVE/PENDING/INACTIVE model.
     *
     * @return array{counts:bool,earns_point:bool,recommendation:?string}
     */
    public static function twoFactorRecommendation(bool $anyMethodAvailable, ?string $activeMethod, string $genericMessage): array
    {
        if(!$anyMethodAvailable) {
            // No Email/WhatsApp/TOTP method is even offered on this
            // install — nothing to score or recommend here (mirrors
            // every other "$xAvailable" gated block in this method).
            return ["counts" => false, "earns_point" => false, "recommendation" => null];
        }
        if($activeMethod !== null) {
            return ["counts" => true, "earns_point" => true, "recommendation" => null];
        }
        return ["counts" => true, "earns_point" => false, "recommendation" => $genericMessage];
    }

    public function change_reset_password($vars = [])
    {
        $settings = security_pack_settings();
        if(!isset($settings["password_reset"])) {
            echo "This feature disabled";
            exit;
        }
        if(!security_pack_csrf_valid()) {
            ob_end_clean();
            echo 0;
            exit;
        }
        // Security Pack 2.1: this AJAX endpoint is CSRF-protected but a
        // valid session could still hammer it — rate limit per logged-in
        // client (20 requests / 10 minutes is generous enough that no
        // legitimate user will ever hit it while toggling a switch).
        if(!\WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::hit("change_reset_password:" . ($_SESSION["uid"] ?? "0"), 20, 600)) {
            ob_end_clean();
            echo 0;
            exit;
        }
        $currentUser = new \WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if(isset($_REQUEST["status"]) && $_REQUEST["status"]) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_dpass")->updateOrInsert(["user_id" => $user->id], ["user_id" => $user->id]);
        } else {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_dpass")->where("user_id", $user->id)->delete();
        }
        ob_end_clean();
        echo 1;
        exit;
    }
    public function login_notification_alert($vars = [])
    {
        $settings = security_pack_settings();
        if(!isset($settings["allow_disable_notification"])) {
            echo "This feature disabled";
            exit;
        }
        if(!security_pack_csrf_valid()) {
            ob_end_clean();
            echo 0;
            exit;
        }
        if(!\WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::hit("login_notification_alert:" . ($_SESSION["uid"] ?? "0"), 20, 600)) {
            ob_end_clean();
            echo 0;
            exit;
        }
        $currentUser = new \WHMCS\Authentication\CurrentUser();
        $user = $currentUser->client();
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_opt")->updateOrInsert(["client_id" => $user->id, "is_admin" => 0], ["client_id" => $user->id, "is_admin" => 0, "allowed" => isset($_REQUEST["status"]) && $_REQUEST["status"] ? 1 : 0]);
        ob_end_clean();
        echo 1;
        exit;
    }
    /**
     * 2026-08-22 — Requirements doc Section 3: client-facing revocation.
     * The Security Center template has no existing AJAX/JS plumbing
     * (unlike the native clientarea.php?action=security toggles), so
     * this follows the OTHER established action shape on this same
     * controller — limit_ip_range()'s POST-only, CSRF-checked,
     * redirect-back-with-flash-message pattern — rather than the
     * echo-1/0 AJAX shape.
     *
     * OWNERSHIP CHECK (identity isolation, same discipline as
     * security_center()'s own authorization docblock): the row is only
     * revoked if it actually belongs to THIS authenticated client's own
     * (user_id, user_type) — never trusts the submitted id alone to
     * imply ownership, so one client cannot revoke another's trusted
     * browser by guessing/enumerating ids. "Revoke all" is offered the
     * same way, scoped to this client's own identity only.
     */
    public function revoke_trusted_browser($vars = [])
    {
        if(!class_exists(\WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::class)) {
            redir("", "index.php?m=security_pack&page=security_center");
        }
        if($_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("", "index.php?m=security_pack&page=security_center");
        }
        if(!security_pack_csrf_valid()) {
            $_SESSION["nnm_security_pack_error"] = "Your session expired, please try again.";
            redir("", "index.php?m=security_pack&page=security_center");
        }
        if(!\WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::hit("revoke_trusted_browser:" . ($_SESSION["uid"] ?? "0"), 20, 600)) {
            $_SESSION["nnm_security_pack_error"] = "Please wait a moment before trying again.";
            redir("", "index.php?m=security_pack&page=security_center");
        }
        $currentUser = new \WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if(!$user) {
            redir("", "index.php?m=security_pack&page=security_center");
        }
        $clientId = (int) $user->id;

        if(!empty($_POST["revoke_all"])) {
            \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::revokeAll($clientId, "client", "client:" . $clientId);
            $_SESSION["nnm_security_pack_successful"] = "All trusted browsers have been revoked.";
            redir("", "index.php?m=security_pack&page=security_center");
        }

        $id = (int) ($_POST["id"] ?? 0);
        if($id > 0) {
            $owned = false;
            foreach (\WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::listForIdentity($clientId, "client") as $row) {
                if((int) $row->id === $id) {
                    $owned = true;
                    break;
                }
            }
            if($owned) {
                \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService::revoke($id, "client:" . $clientId);
                $_SESSION["nnm_security_pack_successful"] = "Trusted browser revoked.";
            }
        }
        redir("", "index.php?m=security_pack&page=security_center");
    }
    public function limit_ip_range($vars = [])
    {
        $lang = $vars["_lang"];
        $settings = security_pack_settings();
        if(!isset($settings["ip_range_limits"])) {
            redir("", "index.php");
        }
        // Security Pack 2.4 (Phase 4, Step 11): this whole action — both
        // the add and the remove path — must be POST-only. The remove
        // path used to be reachable via a plain GET link (still requiring
        // the CSRF token, so not classic-CSRF-exploitable, but the same
        // "soft" GET-destructive-action pattern already closed for every
        // admin controller in Phase 3B and missed here since this is a
        // client controller). A GET request now bounces back to the
        // Security Center rather than executing anything.
        if($_SERVER["REQUEST_METHOD"] !== "POST") {
            $this->backToSecuritySettings();
        }
        if(!security_pack_csrf_valid()) {
            $_SESSION["nnm_security_pack_error"] = $lang["invalid_ips"] ?? "Your session expired, please try again.";
            $this->backToSecuritySettings();
        }
        $currentUser = new \WHMCS\Authentication\CurrentUser();
        $user = $currentUser->user();
        if(isset($_POST["remove_ips"]) && $_POST["remove_ips"]) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->where("user_id", $user->id)->where("id", intval($_POST["remove_ips"]))->delete();
            $_SESSION["nnm_security_pack_successful"] = "Deleted Successfully.";
            $this->backToSecuritySettings();
        }
        $startIp = filter_input(INPUT_POST, "ip_start_rang", FILTER_VALIDATE_IP);
        $endIp = filter_input(INPUT_POST, "ip_end_rang", FILTER_VALIDATE_IP);
        $startIpLong = inet_pton($startIp);
        $endIpLong = inet_pton($endIp);
        if($startIpLong === false || $endIpLong === false) {
            $_SESSION["nnm_security_pack_error"] = $lang["invalid_ips"];
            $this->backToSecuritySettings();
        }
        if($endIpLong <= $startIpLong) {
            $_SESSION["nnm_security_pack_error"] = $lang["invalid_start_ip"];
            $this->backToSecuritySettings();
        }
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ips")->updateOrInsert(["user_id" => $user->id, "start_ip" => $_REQUEST["ip_start_rang"], "end_ip" => $_REQUEST["ip_end_rang"]], ["user_id" => $user->id, "start_ip" => $_REQUEST["ip_start_rang"], "end_ip" => $_REQUEST["ip_end_rang"]]);
        $_SESSION["nnm_security_pack_successful"] = $lang["saved"];
        $this->backToSecuritySettings();
    }

    /**
     * Login Notification / Disable Forgot Password Reset / Session IP
     * Security Limits render directly on WHMCS/Lagom2's own native
     * Security Settings page (see core/user_security.php, which appends
     * templates/settings.tpl there) — that's the "user-security" named
     * route, so redirect back to it after any of the actions above.
     * (A separate dedicated "Account Settings" client-area page/sidebar
     * link used to exist here but was removed 2026-08-15 per user request
     * once the native-page integration was confirmed working, since it
     * duplicated the same content.)
     */
    private function backToSecuritySettings()
    {
        if(class_exists("\\App") && method_exists("\\App", "redirectToRoutePath")) {
            \App::redirectToRoutePath("user-security", []);
            exit;
        }
        redir("", "clientarea.php");
    }

    // -----------------------------------------------------------------
    // Security Pack 2.6 — Email Two-Factor Authentication (client side)
    //
    // ARCHITECTURE CORRECTION (2.6.1): enabling/disabling/verifying
    // Email 2FA is no longer handled by this controller. It is now a
    // native WHMCS Security Module (modules/security/dct_email_2fa),
    // managed entirely through WHMCS's own Setup > Security >
    // Two-Factor Authentication / client "Security Settings" screens —
    // see that module's file header for why. The email2fa_enable,
    // email2fa_activate, email2fa_disable, and email2fa_verify actions
    // that used to live here were removed for that reason; only the
    // read-only status display in security_center() below, and the IP
    // helper it depends on, remain.
    // -----------------------------------------------------------------

    private function e2faIp(): string
    {
        global $remote_ip;
        $settings = security_pack_settings();
        if(function_exists("security_pack_detect_visitor_ip")) {
            $ip = security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto");
            if($ip) {
                return $ip;
            }
        }
        return $remote_ip ?: ($_SERVER["REMOTE_ADDR"] ?? "");
    }
}

?>