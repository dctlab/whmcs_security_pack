<?php

/**
 * Security Pack 3.0 — Time-Based Token (TOTP) Two-Factor Authentication,
 * as a native WHMCS "Security Module" (Setup > Security > Two-Factor
 * Authentication). Structurally parallel to the sibling
 * dct_email_2fa.php / dct_whatsapp_2fa.php modules — same undocumented-
 * interface disclosure applies (see dct_email_2fa.php's header). This
 * file is integration/wiring only; the actual RFC 6238 math lives in
 * TotpService, and the enrollment/verification lifecycle in
 * TotpEnrollmentService.
 *
 * Unlike Email/WhatsApp, TOTP never SENDS a code — the authenticator
 * app computes it locally (Section 26: "Do not create a 'resend TOTP'
 * mechanism"). challenge() therefore renders the code-entry form
 * immediately, with no send step.
 */

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpEnrollmentService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpQrGenerator;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorBypassService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorIpExemptionService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;

const DCT_TOTP_2FA_DEFAULT_BYPASS_DAYS = 7;

/**
 * As of the mutual-exclusion fix, this ALSO requires Email/WhatsApp's
 * own services + all three TwoFactorProviderInterface implementations +
 * TwoFactorAuthenticationService — dct_totp_2fa_activateverify() calls
 * TwoFactorAuthenticationService::activateExclusive() on successful
 * activation (see that class's docblock). Same combined require list
 * dct_email_2fa.php/dct_whatsapp_2fa.php's bootstrap()s use.
 */
function dct_totp_2fa_bootstrap(): void
{
    static $booted = false;
    if($booted) {
        return;
    }
    $booted = true;

    $addonLib = __DIR__ . "/../../addons/security_pack/lib/Security";
    if(!defined("WHMCS")) {
        define("WHMCS", true);
    }
    // robthree/twofactorauth (vendored below, via TotpService.php) requires
    // PHP >=8.2 (its own composer.json) — WHMCS 9.x itself already requires
    // PHP 8.2+, so any WHMCS 9.x install satisfies this automatically. Guarded
    // explicitly anyway so an older PHP 8.1 host (still valid for WHMCS 8.x)
    // gets a clear, actionable message instead of a raw fatal the first time
    // this security module actually runs — config() (module listing) never
    // calls bootstrap(), so the module stays listable either way.
    if(PHP_VERSION_ID < 80200) {
        throw new \RuntimeException("This module requires PHP 8.2 or later (this server is running " . PHP_VERSION . "). Its TOTP engine (robthree/twofactorauth) requires PHP 8.2+.");
    }
    foreach ([
        "IpUtil.php",
        "RateLimiter.php",
        "Email2faService.php",
        "TwoFactor/OtpEngine.php",
        "TwoFactor/TwoFactorBypassService.php",
        "TwoFactor/RecoveryCodeService.php",
        "TwoFactor/Providers/DctWhatsAppNotificationsBridge.php",
        "TwoFactor/WhatsAppTwoFactorService.php",
        "TwoFactor/vendor/robthree/twofactorauth/TwoFactorAuthException.php",
        "TwoFactor/vendor/robthree/twofactorauth/Algorithm.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Qr/IQRCodeProvider.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Rng/RNGException.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Rng/IRNGProvider.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Rng/CSRNGProvider.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Time/TimeException.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Time/ITimeProvider.php",
        "TwoFactor/vendor/robthree/twofactorauth/Providers/Time/LocalMachineTimeProvider.php",
        "TwoFactor/vendor/robthree/twofactorauth/TwoFactorAuth.php",
        "TwoFactor/NullQrCodeProvider.php",
        "TwoFactor/TotpService.php",
        "TwoFactor/TotpKeyStore.php",
        "TwoFactor/TotpEnrollmentService.php",
        "TwoFactor/TotpQrGenerator.php",
        "TwoFactor/TwoFactorProviderInterface.php",
        "TwoFactor/Providers/EmailTwoFactorProvider.php",
        "TwoFactor/Providers/WhatsAppTwoFactorProvider.php",
        "TwoFactor/Providers/TotpTwoFactorProvider.php",
        "TwoFactor/TwoFactorAuthenticationService.php",
        "TwoFactor/TwoFactorIpExemptionService.php",
        "TwoFactor/TrustedBrowserService.php",
    ] as $file) {
        $path = $addonLib . DIRECTORY_SEPARATOR . $file;
        if(is_file($path)) {
            require_once $path;
        }
    }
}

function dct_totp_2fa_settings_from_params(array $params): array
{
    return [
        "totp_2fa_bypass_same_ip" => $params["BypassSameIp"] ?? "1",
        "totp_2fa_bypass_days" => $params["BypassDays"] ?? DCT_TOTP_2FA_DEFAULT_BYPASS_DAYS,
    ];
}

/**
 * Resolves whether a given WHMCS ID belongs to an admin (tbladmins) or a
 * client (default assumption otherwise). DB-based, never session-based —
 * shared by dct_totp_2fa_context()'s own fallback branch and by
 * dct_totp_2fa_login_identity() below.
 */
function dct_totp_2fa_resolve_type_for_id(int $id): string
{
    try {
        $isAdmin = \Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $id)->exists();
    } catch (\Throwable $e) {
        $isAdmin = false;
    }
    return $isAdmin ? "admin" : "client";
}

/**
 * Session-based identity resolution — correct for POST-authentication
 * flows only (activate()/activateverify(), where the account owner is
 * already logged in and is enabling 2FA on their OWN account). Do NOT
 * use this for challenge()/verify() — see dct_totp_2fa_login_identity().
 */
function dct_totp_2fa_context(?int $fallbackUserId = null): array
{
    if(!empty($_SESSION["adminid"])) {
        return ["type" => "admin", "id" => (int) $_SESSION["adminid"]];
    }
    if(!empty($_SESSION["uid"])) {
        return ["type" => "client", "id" => (int) $_SESSION["uid"]];
    }
    if($fallbackUserId !== null && $fallbackUserId > 0) {
        return ["type" => dct_totp_2fa_resolve_type_for_id($fallbackUserId), "id" => $fallbackUserId];
    }
    return ["type" => "client", "id" => (int) ($fallbackUserId ?? 0)];
}

/**
 * 3.1.14 fix — identity resolution for the PRE-authentication login
 * callbacks (challenge()/verify()) ONLY. Confirmed via a live production
 * diagnostic event (2fa.totp.challenge_identity_mismatch): a real login
 * attempt for client #666037 (params_user_info_id: 666037 — exactly
 * correct, and the only identity WHMCS actually supplied for THIS login
 * request) was being resolved as admin #9 instead, because
 * dct_totp_2fa_context() checks $_SESSION["adminid"]/["uid"] FIRST — and
 * WHMCS shares one PHP session between the admin area and the client
 * area on the same domain, so an unrelated, already-open admin panel
 * session in the same browser silently overrode the real login's
 * identity. That session state is meaningless at this pre-authentication
 * point in the flow anyway: for a genuine admin login, 2FA is challenged
 * BEFORE $_SESSION["adminid"] is ever set, so trusting it here can only
 * ever pick up STALE state from a different, unrelated login. The fix:
 * challenge()/verify() now resolve identity exclusively from
 * $params["user_info"]["id"] (the one value WHMCS actually supplies for
 * THIS specific login attempt) plus a DB-based type check — never from
 * ambient session state.
 */
function dct_totp_2fa_login_identity(array $params): array
{
    $id = (int) ($params["user_info"]["id"] ?? 0);
    if($id <= 0) {
        return ["type" => "client", "id" => 0];
    }
    return ["type" => dct_totp_2fa_resolve_type_for_id($id), "id" => $id];
}

/**
 * 3.1.15 fix — identity resolution for the SELF-SERVICE enrollment
 * callbacks (activate()/activateverify()) ONLY. A real client, actively
 * signed in and on their own client-area Security Settings page,
 * clicked "Enable Two-Factor Authentication" and got "Could not
 * identify your account." — i.e. dct_totp_2fa_context()'s pure
 * $_SESSION["uid"] lookup returned nothing for a genuinely authenticated
 * client-area visitor. WHMCS's own Security Module contract already
 * supplies the currently-authenticated user's identity via
 * $params["user_info"]["id"] for THIS call — the same field that 3.1.14
 * proved is the one value that reliably identifies who a given Security
 * Module call is actually for, since WHMCS builds it itself rather than
 * relying on this module's own guess at which raw session key holds the
 * right value (a guess that can miss real cases, e.g. sub-account/
 * contact logins that don't use the same session key as a primary
 * client). Prefers $params["user_info"]["id"] (DB-checked for type);
 * falls back to the session-based dct_totp_2fa_context() only if WHMCS
 * didn't supply a usable id, preserving prior behavior for any install
 * where that was already working.
 */
function dct_totp_2fa_account_identity(array $params): array
{
    $id = (int) ($params["user_info"]["id"] ?? 0);
    if($id > 0) {
        return ["type" => dct_totp_2fa_resolve_type_for_id($id), "id" => $id];
    }
    return dct_totp_2fa_context();
}

function dct_totp_2fa_ip(array $settings = []): string
{
    if(function_exists("security_pack_detect_visitor_ip")) {
        $ip = security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto");
        if($ip !== "") {
            return $ip;
        }
    }
    return (string) ($_SERVER["REMOTE_ADDR"] ?? "");
}

function dct_totp_2fa_e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}

function dct_totp_2fa_config()
{
    return [
        "FriendlyName" => ["Type" => "System", "Value" => "Time-Based Token"],
        "ShortDescription" => ["Type" => "System", "Value" => "Two-Factor Authentication via an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, ...)"],
        "Description" => ["Type" => "System", "Value" => "Standard RFC 6238-compatible time-based one-time codes. Algorithm/digits/period are standards-based and not user-configurable by design."],
        "BypassSameIp" => ["FriendlyName" => "Allow Same-IP Bypass", "Type" => "yesno", "Description" => "Skip the code on later logins from the same account + same IP"],
        "BypassDays" => ["FriendlyName" => "Bypass Duration", "Type" => "text", "Size" => "5", "Default" => (string) DCT_TOTP_2FA_DEFAULT_BYPASS_DAYS, "Description" => "Days (1-90)"],
    ];
}

/**
 * Renders the enrollment step. Shows the manual-entry secret, the
 * otpauth:// link, and — via TotpQrGenerator — an inline scannable QR
 * image built entirely server-side (no third-party QR API call, so the
 * secret never leaves this server). If the otpauth:// URI is too long to
 * fit the encoder's supported range, the QR image is silently omitted and
 * manual entry / the link remain the fallback (never a hard error).
 *
 * SECRET STABILITY (incident fix, 2026-08-27): WHMCS core re-invokes this
 * exact function after EVERY failed _activateverify() submission, purely
 * to re-render the form with an error message (see $params["verifyError"]
 * below) — there is no separate "retry" entry point. TotpEnrollmentService::
 * beginEnrollment() therefore now REUSES the existing secret for a still-
 * pending enrollment rather than minting a new one on each call, so
 * entering a wrong code no longer invalidates the QR/secret the user
 * already scanned. This still fully honors Section 13 — "Do NOT activate
 * TOTP before successful verification": the row's status stays "pending"
 * regardless of whether the secret is reused or freshly generated: an
 * abandoned enrollment is still never silently activated, only its
 * secret's stability during retries changed. See that method's own
 * docblock for the full detail.
 */
function dct_totp_2fa_activate($params)
{
    dct_totp_2fa_bootstrap();
    if(!class_exists(TotpEnrollmentService::class)) {
        return "<div class=\"alert alert-danger\">Time-Based Token 2FA is unavailable — the Security Pack addon module is not installed or active.</div>";
    }

    $context = dct_totp_2fa_account_identity($params);
    if($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    $label = $context["type"] . "#" . $context["id"];
    try {
        $email = $context["type"] === "admin"
            ? (string) (\Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $context["id"])->value("email") ?? "")
            : (string) (\Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $context["id"])->value("email") ?? "");
        if($email !== "") {
            $label = $email;
        }
    } catch (\Throwable $e) {
    }

    $enrollment = TotpEnrollmentService::beginEnrollment($context["id"], $context["type"], $label);
    if(isset($enrollment["error"])) {
        return "<div class=\"alert alert-danger\">" . dct_totp_2fa_e($enrollment["error"]) . "</div>";
    }

    $secret = dct_totp_2fa_e($enrollment["formatted"]);
    $uri = dct_totp_2fa_e($enrollment["uri"]);

    $qrHtml = "";
    try {
        $svg = TotpQrGenerator::generateSvg($enrollment["uri"], 5);
        $qrHtml = '<div style="display:inline-block;max-width:260px;">' . $svg . '</div><br>';
    } catch (\Throwable $e) {
        // Encoder couldn't fit this URI (e.g. unusually long issuer/account
        // label) — manual entry and the otpauth:// link below still work.
    }

    // WHMCS core re-invokes _activate() after a failed _activateverify()
    // and passes the caught exception's message back in as
    // $params["verifyError"] — confirmed against native totp.php's own
    // totp_activate(). Previously never read here, so a wrong code
    // silently reset the form with no explanation.
    $verifyErrorHtml = "";
    $verifyError = (string) ($params["verifyError"] ?? "");
    if ($verifyError !== "") {
        $verifyErrorHtml = '<div class="alert alert-danger">' . dct_totp_2fa_e($verifyError) . '</div>';
    }

    return <<<HTML
        <p>Scan or manually enter this secret in your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, or any RFC 6238-compatible app), then enter the 6-digit code it shows.</p>
        <div class="well text-center">
            {$qrHtml}
            <p><strong>Manual entry secret:</strong></p>
            <p style="font-size: 20px; letter-spacing: 2px; font-family: monospace;">{$secret}</p>
            <p><a href="{$uri}">Open in authenticator app</a></p>
        </div>
        {$verifyErrorHtml}
        <div class="form-group">
            <label for="dct_totp_2fa_code">6-digit code from your app</label>
            <input type="text" class="form-control" name="dct_totp_2fa_code" id="dct_totp_2fa_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" autofocus required>
        </div>
        <hr>
        <input type="submit" value="Submit" class="btn btn-primary">
        HTML;
}

/**
 * CRITICAL CONTRACT FIX (confirmed against the real, decoded native
 * modules/security/totp/totp.php's own totp_activateverify()): WHMCS
 * core decides success/failure for this call PURELY by whether an
 * exception was thrown — NOT by inspecting any "msg" key in a returned
 * array. Native throws `new WHMCS\Exception(...)` on an incorrect code
 * and returns `['settings' => [...]]` (no "msg" key at all) on success.
 * The previous implementation here returned `["msg" => "..."]` on BOTH
 * the success AND every failure path with no exception either way —
 * WHMCS core therefore saw "no exception" on every submission,
 * regardless of whether the code was actually correct, and activated
 * 2FA at the WHMCS-core level (tblusers.second_factor, WHMCS's own
 * backup code) even for a wrong/fake code. This module's OWN internal
 * TotpEnrollmentService correctly refused to flip the enrollment row to
 * "active" for an invalid code — so the account ended up in a broken
 * split state: WHMCS core believed 2FA was enabled, while this module's
 * own challenge()/verify() at the next real login correctly found no
 * active enrollment and blocked the account entirely ("not currently
 * active for this account, contact administrator"). Confirmed live via
 * a real enrollment attempt with an intentionally wrong code, which
 * produced exactly that contradictory "now enabled" + "code is
 * incorrect" + a WHMCS-generated backup code, all at once.
 */
function dct_totp_2fa_activateverify($params)
{
    dct_totp_2fa_bootstrap();
    if(!class_exists(TotpEnrollmentService::class)) {
        throw new \WHMCS\Exception("Time-Based Token 2FA is unavailable — the Security Pack addon module is not installed or active.");
    }

    $context = dct_totp_2fa_account_identity($params);
    if($context["id"] <= 0) {
        throw new \WHMCS\Exception("Could not identify your account.");
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_totp_2fa_code"] ?? ""));
    if($submitted === "") {
        throw new \WHMCS\Exception("Please enter the 6-digit code from your authenticator app.");
    }

    $ip = dct_totp_2fa_ip();
    $result = TotpEnrollmentService::verifyAndActivate($context["id"], $context["type"], $submitted, $ip);

    if($result["status"] !== "valid") {
        $messages = [
            "invalid" => "That code is incorrect. Make sure your device's clock is accurate.",
            "no_pending_enrollment" => "No pending enrollment found — click Enable again to start over.",
            "rate_limited" => "Too many attempts — please wait a moment and try again.",
            "error" => "Time-Based Token could not be verified right now.",
        ];
        throw new \WHMCS\Exception($messages[$result["status"]] ?? "Verification failed.");
    }

    // Mutual exclusion: only one primary 2FA method may be active at a
    // time — activating TOTP here automatically deactivates Email/
    // WhatsApp if either was active (enrollment preserved, not
    // deleted). Server-side, not a UI label — see
    // TwoFactorAuthenticationService.
    if(class_exists(TwoFactorAuthenticationService::class)) {
        TwoFactorAuthenticationService::activateExclusive("totp", $context["id"], $context["type"], "user");
    }

    // "settings" (never "msg") is the confirmed native success contract
    // — deliberately EMPTY: this module manages the encrypted secret
    // entirely in its own nnm_security_pack_totp2fa table, never via
    // WHMCS's own user_settings storage, so there is nothing sensitive
    // (or otherwise) to hand back here.
    return ["settings" => []];
}

/**
 * No send step — the authenticator app already has a live code.
 *
 * CRITICAL (rebuild fix, confirmed against the real native WHMCS
 * modules/security/totp/totp.php reference — its own totp_challenge()
 * returns a BARE `<div><input>...<input type="submit">...</div>` with NO
 * `<form>` tag at all): WHMCS's own login page already supplies the
 * enclosing `<form action="dologin.php">`, its CSRF token, and its
 * submit handling. A Security Module's challenge() must return ONLY
 * bare form controls — never its own nested `<form action="dologin.php">`.
 * The previous implementation nested a second `<form>` inside WHMCS's
 * own outer form (both for the main code-entry path and the same-IP
 * bypass auto-submit path), which corrupts the outer form's native
 * behavior. Neither branch below creates a `<form>` element anymore.
 */
function dct_totp_2fa_challenge($params)
{
    dct_totp_2fa_bootstrap();
    if(!class_exists(TotpEnrollmentService::class)) {
        return "<p class=\"text-danger\">Time-Based Token 2FA is unavailable — the Security Pack addon module is not installed or active.</p>";
    }

    $context = dct_totp_2fa_login_identity($params);
    if($context["id"] <= 0) {
        return "<p class=\"text-danger\">Could not identify your account.</p>";
    }

    if(!TotpEnrollmentService::isActive($context["id"], $context["type"])) {
        // 3.1.13 diagnostic capture confirmed the root cause (see
        // dct_totp_2fa_login_identity()'s docblock): $context here is
        // now resolved from $params["user_info"]["id"] alone, never
        // from ambient session state, so this branch should now only
        // fire for a GENUINELY inactive/never-enrolled account. The
        // non-sensitive diagnostic log is kept as a safety net in case
        // a different identity-resolution edge case surfaces later.
        dct_totp_2fa_log_challenge_mismatch($params, $context);
        return "<p class=\"text-warning\">Time-Based Token Two-Factor Authentication is not currently active for this account. Please contact an administrator.</p>";
    }

    $settings = dct_totp_2fa_settings_from_params($params);
    $ip = dct_totp_2fa_ip($settings);

    // 2026-08-22 — Requirements doc Section 3: trusted-browser check.
    // Same bare-hidden-input-on-the-enclosing-form pattern as the bypass
    // branch immediately below (this module never opens its own
    // <form>), but its own field name/service — never merged with the
    // bypass/IP-exemption OR-chain. See TrustedBrowserService's class
    // docblock for the full rationale.
    $trustedBrowserToken = TrustedBrowserService::readCookieToken();
    if($trustedBrowserToken !== "" && TrustedBrowserService::isValidForIdentity($trustedBrowserToken, $context["id"], $context["type"])) {
        return <<<HTML
            <p>Trusted browser recognized — continuing automatically.</p>
            <input type="hidden" name="dct_totp_2fa_trusted_browser" value="1">
            <script>
            (function () {
                var currentScript = document.currentScript;
                var form = (currentScript && currentScript.closest) ? currentScript.closest("form") : null;
                if (!form && document.forms.length) {
                    form = document.forms[0];
                }
                if (form) {
                    form.submit();
                }
            })();
            </script>
            HTML;
    }

    if(dct_totp_2fa_bypass_active($context["id"], $context["type"], $ip)) {
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.bypass.used", "2FA bypass or IP exemption used — no code required for this login.", ["user_id" => $context["id"], "user_type" => $context["type"], "method" => "totp"]);
        }
        // Bare hidden input on WHMCS's OWN outer form — no second
        // <form>. The script submits the ENCLOSING form
        // (document.currentScript.closest("form")), falling back to the
        // page's first <form> if the browser lacks Element.closest()
        // support, rather than creating and submitting a form of its
        // own.
        return <<<HTML
            <p>Trusted sign-in recognized for this device — continuing automatically.</p>
            <input type="hidden" name="dct_totp_2fa_bypass" value="1">
            <script>
            (function () {
                var currentScript = document.currentScript;
                var form = (currentScript && currentScript.closest) ? currentScript.closest("form") : null;
                if (!form && document.forms.length) {
                    form = document.forms[0];
                }
                if (form) {
                    form.submit();
                }
            })();
            </script>
            HTML;
    }

    // Bare controls only (see docblock above) — matches the native
    // reference's own <input type="text">...<input type="submit"> shape,
    // just styled to match this project's existing markup. maxlength is
    // 19 (not 6) and there is no numeric-only pattern/inputmode because
    // this single field also accepts a recovery code
    // (XXXX-XXXX-XXXX-XXXX, Section 12 — "supports recovery codes") —
    // see dct_totp_2fa_verify() for how the two are distinguished.
    return <<<HTML
        <div class="form-group text-center">
            <p>Enter the 6-digit code from your authenticator app.</p>
            <input
                type="text"
                name="dct_totp_2fa_code"
                class="form-control text-center"
                style="font-size: 24px; letter-spacing: 4px; margin-bottom: 12px;"
                maxlength="19"
                placeholder="000000"
                autocomplete="one-time-code"
                autofocus
                required
            >
            <div class="checkbox" style="text-align: left;">
                <label>
                    <input type="checkbox" name="dct_totp_2fa_remember_browser" value="1"> Remember this browser for 30 days
                </label>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Verify</button>
            <p class="text-muted small" style="margin-top: 8px;">Lost your device? Enter one of your recovery codes instead of a 6-digit code.</p>
        </div>
        HTML;
}

function dct_totp_2fa_verify($params)
{
    dct_totp_2fa_bootstrap();
    if(!class_exists(TotpEnrollmentService::class)) {
        return false;
    }

    $context = dct_totp_2fa_login_identity($params);
    if($context["id"] <= 0) {
        return false;
    }

    $settings = dct_totp_2fa_settings_from_params($params);
    $ip = dct_totp_2fa_ip($settings);

    if(!empty($params["post_vars"]["dct_totp_2fa_trusted_browser"])) {
        $token = TrustedBrowserService::readCookieToken();
        return $token !== "" && TrustedBrowserService::consume($token, $context["id"], $context["type"]);
    }

    if(!empty($params["post_vars"]["dct_totp_2fa_bypass"])) {
        return dct_totp_2fa_bypass_active($context["id"], $context["type"], $ip);
    }

    $raw = trim((string) ($params["post_vars"]["dct_totp_2fa_code"] ?? ""));
    if($raw === "") {
        return false;
    }
    $digitsOnly = preg_replace("/\s+/", "", $raw) ?? "";

    // The single challenge field accepts EITHER a 6-digit authenticator
    // code OR a recovery code (Section 12 — "supports recovery codes").
    // Exactly 6 digits is always tried as a TOTP code (the common path,
    // via TotpEnrollmentService's own replay-protected verifyLogin());
    // anything else is tried against Security Pack's EXISTING, shared
    // TwoFactorAuthenticationService::attemptRecoveryCode() —
    // RecoveryCodeService's own single-use consumption + its own
    // rate-limiting — rather than a new, duplicate recovery-code path.
    // (Audit note: this call site is what actually wires TOTP login into
    // recovery codes — previously attemptRecoveryCode()/attemptConsume()
    // had no caller anywhere in the codebase; recovery codes were
    // generable/displayable in the Client Security Center but could not
    // actually be used to sign in. See TOTP-REBUILD-AUDIT.md.)
    if(preg_match('/^\d{6}$/', $digitsOnly)) {
        $result = TotpEnrollmentService::verifyLogin($context["id"], $context["type"], $digitsOnly, $ip);
        if($result["status"] === "no_challenge") {
            // Same diagnostic as challenge() above — the enrollment
            // wasn't found under the identity this call resolved. Never
            // logs the submitted code.
            dct_totp_2fa_log_challenge_mismatch($params, $context);
        }
        // "replayed" (Section 11 — replay protection) and "invalid"/
        // "rate_limited"/"no_challenge"/"error" all fail the same way
        // here — TotpEnrollmentService::verifyLogin() already recorded
        // the specific 2fa.totp.replay_rejected / 2fa.verification.failed
        // security event for whichever case occurred.
        if($result["status"] !== "valid") {
            return false;
        }
    } else {
        if(!class_exists(TwoFactorAuthenticationService::class)) {
            return false;
        }
        if(!TwoFactorAuthenticationService::attemptRecoveryCode($context["id"], $context["type"], $raw, $ip)) {
            return false;
        }
        // 2026-08-22 (Step 4 OTP-parity audit): a successful RECOVERY
        // CODE login is a genuinely successful 2FA verification — see
        // Section 6's "last successful verification date" requirement —
        // but attemptRecoveryCode()/RecoveryCodeService are deliberately
        // method-agnostic (one shared recovery-code pool, not owned by
        // any single provider's table), so they have no way to know
        // which provider's own last_verified_at column to update. This
        // module DOES know (it's the TOTP module, and this branch only
        // runs after a TOTP-scoped recovery-code success), so it updates
        // its own table here directly — same pattern
        // dct_email_2fa_verify()/dct_whatsapp_2fa_verify() already use
        // for their own successful-verification writes. Previously this
        // branch left "last successful verification" stale after a
        // recovery-code sign-in, which would have under-reported real
        // 2FA usage on the Step 6 admin reporting screen.
        try {
            \Illuminate\Database\Capsule\Manager::table("nnm_security_pack_totp2fa")
                ->where("user_id", $context["id"])->where("user_type", $context["type"])
                ->update(["last_verified_at" => date("Y-m-d H:i:s")]);
        } catch (\Throwable $e) {
        }
    }

    if(!empty($settings["totp_2fa_bypass_same_ip"]) && $settings["totp_2fa_bypass_same_ip"] !== "0") {
        $days = \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine::clampBypassDays($settings["totp_2fa_bypass_days"] ?? DCT_TOTP_2FA_DEFAULT_BYPASS_DAYS);
        TwoFactorBypassService::grantSameIpBypass($context["id"], $context["type"], $ip, $days, "totp", "2fa");
    }

    // 2026-08-22 — Requirements doc Section 3: this is the single
    // convergence point reached by BOTH the TOTP-code branch and the
    // recovery-code branch above (never by the trusted-browser or
    // admin/IP-bypass shortcuts, which both return earlier) — a REAL
    // verification of either kind may create a trusted-browser token
    // when the user explicitly opted in, matching the requirement that
    // recovery-code verification counts as successful 2FA for this
    // purpose too.
    if(!empty($params["post_vars"]["dct_totp_2fa_remember_browser"])) {
        $deviceLabel = mb_substr((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""), 0, 255);
        $rawToken = TrustedBrowserService::create($context["id"], $context["type"], $deviceLabel, $ip);
        if($rawToken !== null) {
            TrustedBrowserService::setCookie($rawToken);
        }
    }

    return true;
}

function dct_totp_2fa_bypass_active(int $userId, string $userType, string $ip): bool
{
    if(TwoFactorBypassService::findActive($userId, $userType, $ip) !== null) {
        return true;
    }
    // 2026-08-22: dedicated 2FA IP exemption (Requirements doc Section
    // 1) — see dct_email_2fa.php's matching function for full rationale.
    return $ip !== "" && class_exists(TwoFactorIpExemptionService::class) && TwoFactorIpExemptionService::isExempt($ip, $userId, $userType);
}

/**
 * 3.1.13 diagnostic-only helper — records a single, strictly
 * NON-SENSITIVE Security Event describing exactly what identity this
 * login-time security-module call resolved, for the case where
 * TotpEnrollmentService::isActive()/verifyLogin() reports "not active"/
 * "no_challenge" even though an active enrollment exists (per Security
 * Pack's own admin Enrollment Overview). NEVER logs: the submitted TOTP
 * code, post_vars, the TOTP secret, or any other 2FA credential —
 * only the raw `user_info.id` WHMCS supplied (a WHMCS User/Client ID,
 * not a secret), the top-level $params keys actually present (to see
 * what WHMCS's own undocumented Security Module contract really passed
 * at this exact call, since that has been a disclosed-but-unverified
 * risk since 2.6.1), and the (type, id) this module resolved from it.
 * Fully fail-soft — if security_pack_record_event() itself is
 * unavailable, this is a silent no-op and never blocks the login flow.
 */
function dct_totp_2fa_log_challenge_mismatch(array $params, array $context): void
{
    if(!function_exists("security_pack_record_event")) {
        return;
    }
    try {
        $rawUserInfoId = $params["user_info"]["id"] ?? "MISSING";
        $topLevelKeys = implode(",", array_keys($params));
        security_pack_record_event(
            "2fa.totp.challenge_identity_mismatch",
            "Time-Based Token login challenge could not find an active enrollment under the resolved identity — diagnostic only, no credentials logged.",
            [
                "params_user_info_id" => is_scalar($rawUserInfoId) ? $rawUserInfoId : gettype($rawUserInfoId),
                "params_top_level_keys" => $topLevelKeys,
                "resolved_type" => $context["type"] ?? "",
                "resolved_id" => $context["id"] ?? 0,
            ],
            "warning"
        );
    } catch (\Throwable $e) {
        // Diagnostics must never break the login flow.
    }
}
