<?php

/**
 * Security Pack 3.0/3.1 — DCTLAB WhatsApp Two-Factor Authentication, as a
 * native WHMCS "Security Module" (Setup > Security > Two-Factor
 * Authentication). Structurally identical to the sibling
 * modules/security/dct_email_2fa/dct_email_2fa.php — same undocumented-
 * interface disclosure applies (see that file's header comment; not
 * repeated here). This file is integration/wiring only; all real logic
 * lives in WhatsAppTwoFactorService and (as of 3.1)
 * DctWhatsAppNotificationsBridge.
 *
 * As of 3.1, WhatsApp delivery is a REAL integration with the actual
 * DCTLAB WhatsApp platform: github.com/dctlab/WHMCS-WhatsApp-Notifications
 * (the "dct_whatsapp_notifications" addon module) — Botms.in, Baileys, or
 * Meta WhatsApp Cloud API, whichever that addon has configured. That
 * addon must be installed (modules/addons/dct_whatsapp_notifications,
 * with `composer install` run so vendor/autoload.php exists) for codes to
 * actually send; if it isn't, activation/challenge screens surface a
 * clear failure rather than a fatal error, per DctWhatsAppNotificationsBridge's
 * own fail-closed discipline.
 *
 * DISCLOSED LIMITATION (Section 11): this release resolves the WhatsApp
 * destination number ONLY from the account's own on-file record
 * (tblclients.phonenumber for clients — WHMCS admins have no native
 * phone field). It does NOT yet offer an in-module "add/change my
 * number" wizard, because that would require a second confirmed POST
 * round-trip whose exact WHMCS security-module control-flow contract
 * (activate() -> activateverify() -> ??) is unverified in this
 * environment (same class of undocumented-interface uncertainty as the
 * modules/security/ interface itself — see dct_email_2fa.php's header).
 * Rather than ship an unverified two-step flow, activation simply
 * requires a phone number to already be present on the account; add one
 * via your account profile first. This is a disclosed, deliberate
 * simplification, not an oversight.
 */

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\WhatsAppTwoFactorService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorIpExemptionService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;

const DCT_WHATSAPP_2FA_DEFAULT_CODE_LENGTH = 6;
const DCT_WHATSAPP_2FA_DEFAULT_VALID_MINUTES = 10;
const DCT_WHATSAPP_2FA_DEFAULT_MAX_ATTEMPTS = 5;
const DCT_WHATSAPP_2FA_DEFAULT_MAX_RESENDS = 3;
// FIX (2026-08-25): same change and same caveat as
// DCT_EMAIL_2FA_DEFAULT_RESEND_COOLDOWN's docblock in dct_email_2fa.php
// — raised from 60 to 300, only takes effect where this module's own
// "Resend Cooldown" config field was never explicitly saved for this
// install. Still within clampResendCooldownSeconds()'s existing
// 30-600s bounds.
const DCT_WHATSAPP_2FA_DEFAULT_RESEND_COOLDOWN = 300;

/**
 * As of the mutual-exclusion fix, this ALSO requires Email/TOTP's own
 * services + all three TwoFactorProviderInterface implementations +
 * TwoFactorAuthenticationService — dct_whatsapp_2fa_activateverify()
 * calls TwoFactorAuthenticationService::activateExclusive() on
 * successful activation (see that class's docblock). Same combined
 * require list dct_email_2fa.php/dct_totp_2fa.php's bootstrap()s use.
 */
function dct_whatsapp_2fa_bootstrap(): void
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
        "TwoFactor/Providers/DctWhatsAppTwoFactorLogBridge.php",
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

function dct_whatsapp_2fa_settings_from_params(array $params): array
{
    return [
        "whatsapp_2fa_length" => $params["CodeLength"] ?? DCT_WHATSAPP_2FA_DEFAULT_CODE_LENGTH,
        "whatsapp_2fa_minutes" => $params["CodeValidMinutes"] ?? DCT_WHATSAPP_2FA_DEFAULT_VALID_MINUTES,
        "whatsapp_2fa_max_attempts" => $params["MaxAttempts"] ?? DCT_WHATSAPP_2FA_DEFAULT_MAX_ATTEMPTS,
        "whatsapp_2fa_max_resends" => $params["MaxResends"] ?? DCT_WHATSAPP_2FA_DEFAULT_MAX_RESENDS,
        "whatsapp_2fa_resend_cooldown" => $params["ResendCooldownSeconds"] ?? DCT_WHATSAPP_2FA_DEFAULT_RESEND_COOLDOWN,
    ];
}

function dct_whatsapp_2fa_context(?int $fallbackUserId = null): array
{
    if(!empty($_SESSION["adminid"])) {
        return ["type" => WhatsAppTwoFactorService::TYPE_ADMIN, "id" => (int) $_SESSION["adminid"]];
    }

    // FIX (2026-08-25): prefer the identity WHMCS's security-module
    // contract hands this module for THIS specific call
    // ($params['user_info']['id'], passed in here as $fallbackUserId)
    // over $_SESSION['uid'] — mirrors the identical, already-proven fix
    // in dct_email_2fa_context() (see that function's docblock for the
    // full explanation). Observed live on this install: for a
    // secondary/sub-account WHMCS User (e.g. "cirtsd@gmail.com" #666503,
    // a user granted access to the "Domain Manager" #666037 client
    // account), $_SESSION['uid'] did not reliably reflect which User
    // was actually authenticating — WhatsApp 2FA enrolled by #666503
    // was being recorded under #666037 instead, because this function
    // used to check $_SESSION['uid'] BEFORE ever considering the id
    // WHMCS actually passed in for the request. The per-call user_info
    // id is the more trustworthy signal precisely because WHMCS core
    // supplies it fresh for that specific request, rather than reading
    // session state that may reflect a different, shared, or stale
    // identity. Session remains the fallback for any call site that
    // genuinely has no id to pass (preserves prior behavior there).
    if($fallbackUserId !== null && $fallbackUserId > 0) {
        try {
            $isAdmin = \Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $fallbackUserId)->exists();
        } catch (\Throwable $e) {
            $isAdmin = false;
        }
        return ["type" => $isAdmin ? WhatsAppTwoFactorService::TYPE_ADMIN : WhatsAppTwoFactorService::TYPE_CLIENT, "id" => $fallbackUserId];
    }

    if(!empty($_SESSION["uid"])) {
        return ["type" => WhatsAppTwoFactorService::TYPE_CLIENT, "id" => (int) $_SESSION["uid"]];
    }

    return ["type" => WhatsAppTwoFactorService::TYPE_CLIENT, "id" => (int) ($fallbackUserId ?? 0)];
}

function dct_whatsapp_2fa_ip(array $settings = []): string
{
    if(function_exists("security_pack_detect_visitor_ip")) {
        $ip = security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto");
        if($ip !== "") {
            return $ip;
        }
    }
    return (string) ($_SERVER["REMOTE_ADDR"] ?? "");
}

function dct_whatsapp_2fa_e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}

function dct_whatsapp_2fa_config()
{
    return [
        "FriendlyName" => ["Type" => "System", "Value" => "DCTLAB WhatsApp"],
        "ShortDescription" => ["Type" => "System", "Value" => "Two-Factor Authentication via a one-time code sent over WhatsApp"],
        "Description" => ["Type" => "System", "Value" => "Sends a one-time verification code over WhatsApp to the phone number on your account every time you log in. Requires the \"dct_whatsapp_notifications\" addon module (github.com/dctlab/WHMCS-WhatsApp-Notifications) to be installed, with at least one of Botms.in, Baileys, or Meta WhatsApp Cloud API configured there — client-facing message wording is customizable at Notifications -> TwoFactorAuthentication in that addon's admin UI."],
        "CodeLength" => ["FriendlyName" => "Code Length", "Type" => "text", "Size" => "5", "Default" => (string) DCT_WHATSAPP_2FA_DEFAULT_CODE_LENGTH, "Description" => "Digits (6-8)"],
        "CodeValidMinutes" => ["FriendlyName" => "Code Valid", "Type" => "text", "Size" => "5", "Default" => (string) DCT_WHATSAPP_2FA_DEFAULT_VALID_MINUTES, "Description" => "Minutes (1-30)"],
        "MaxAttempts" => ["FriendlyName" => "Maximum Attempts", "Type" => "text", "Size" => "5", "Default" => (string) DCT_WHATSAPP_2FA_DEFAULT_MAX_ATTEMPTS, "Description" => "Per code (3-10)"],
        "MaxResends" => ["FriendlyName" => "Maximum Resends", "Type" => "text", "Size" => "5", "Default" => (string) DCT_WHATSAPP_2FA_DEFAULT_MAX_RESENDS, "Description" => "Per challenge (1-10)"],
        "ResendCooldownSeconds" => ["FriendlyName" => "Resend Cooldown", "Type" => "text", "Size" => "5", "Default" => (string) DCT_WHATSAPP_2FA_DEFAULT_RESEND_COOLDOWN, "Description" => "Seconds (30-600)"],
    ];
}

function dct_whatsapp_2fa_activate($params)
{
    dct_whatsapp_2fa_bootstrap();
    if(!class_exists(WhatsAppTwoFactorService::class)) {
        return "<div class=\"alert alert-danger\">WhatsApp 2FA is unavailable — the Security Pack addon module is not installed or active.</div>";
    }

    // FIX (2026-08-25): pass the per-request user_info id through, same
    // as dct_whatsapp_2fa_challenge()/dct_whatsapp_2fa_verify() already
    // do, and the same fix already proven for the identical bug in
    // dct_email_2fa_context()/dct_totp_2fa_context() — see
    // dct_email_2fa_context()'s docblock for the full explanation.
    // Observed live on this install: a sub-account/contact WHMCS User
    // (e.g. "cirtsd@gmail.com", #666503, a secondary user under the
    // "Domain Manager" #666037 client) enabling WhatsApp 2FA from their
    // own client-area Security Settings had the enrollment recorded
    // against #666037 instead of their own #666503, because this
    // function used to call dct_whatsapp_2fa_context() with no
    // argument at all — relying entirely on $_SESSION["uid"], which did
    // not reliably reflect which User was actually authenticating for
    // this specific sub-account request. $params["user_info"]["id"] is
    // the value WHMCS core itself supplies fresh for THIS activation
    // call, and is the more trustworthy signal.
    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_whatsapp_2fa_context($userId);
    if($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    $phone = WhatsAppTwoFactorService::resolveAccountPhone($context["id"], $context["type"]);
    if($phone === null || $phone === "") {
        return "<div class=\"alert alert-warning\">No phone number is on file for your account. Add one to your account profile, then click Enable again.</div>";
    }

    $settings = dct_whatsapp_2fa_settings_from_params($params);
    $ip = dct_whatsapp_2fa_ip($settings);
    $result = WhatsAppTwoFactorService::beginActivation($context["id"], $context["type"], $phone, $ip, $settings);
    $masked = dct_whatsapp_2fa_e(OtpEngine::maskPhone($phone));

    $status = (string) ($result["status"] ?? "error");
    if($status === "sent") {
        $notice = "<p>We've sent a verification code over WhatsApp to <strong>{$masked}</strong>. Enter it below to finish enabling WhatsApp Two-Factor Authentication.</p>";
    } elseif ($status === "send_failed") {
        $notice = "<p>We generated a verification code for <strong>{$masked}</strong>, but delivery over WhatsApp failed. Ask an administrator to check the \"dct_whatsapp_notifications\" addon's configuration before trying again.</p>";
    } elseif ($status === "rate_limited") {
        $notice = "<p>A verification code was already sent to <strong>{$masked}</strong> recently. Please wait a moment before requesting a new one.</p>";
    } else {
        $notice = "<p>We were unable to start WhatsApp Two-Factor Authentication activation right now. Please try again shortly.</p>";
    }

    // WHMCS core re-invokes _activate() after a failed _activateverify()
    // and passes the caught exception's message back in as
    // $params["verifyError"] — confirmed against native totp.php's own
    // totp_activate(). Previously never read here, so a wrong code
    // silently reset the form with no explanation.
    $verifyErrorHtml = "";
    $verifyError = (string) ($params["verifyError"] ?? "");
    if($verifyError !== "") {
        $verifyErrorHtml = '<div class="alert alert-danger">' . dct_whatsapp_2fa_e($verifyError) . '</div>';
    }

    return <<<HTML
        {$notice}
        {$verifyErrorHtml}
        <div class="form-group">
            <label for="dct_whatsapp_2fa_code">Verification Code</label>
            <input type="text" class="form-control" name="dct_whatsapp_2fa_code" id="dct_whatsapp_2fa_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" autofocus required>
        </div>
        <hr>
        <input type="submit" value="Enable WhatsApp Verification" class="btn btn-primary">
        HTML;
}

/**
 * CRITICAL CONTRACT FIX — see the matching, fully-explained docblock on
 * dct_totp_2fa_activateverify() in dct_totp_2fa.php. Same bug, same
 * fix: WHMCS core decides success/failure purely by whether an
 * exception was thrown, never by inspecting a returned "msg" string —
 * so every prior failure path here (which only returned a "msg" array)
 * was silently treated as a SUCCESSFUL activation at the WHMCS-core
 * level regardless of whether the submitted code was actually correct.
 */
function dct_whatsapp_2fa_activateverify($params)
{
    dct_whatsapp_2fa_bootstrap();
    if(!class_exists(WhatsAppTwoFactorService::class)) {
        throw new \WHMCS\Exception("WhatsApp 2FA is unavailable — the Security Pack addon module is not installed or active.");
    }

    // FIX (2026-08-25): same fix as dct_whatsapp_2fa_activate() above —
    // pass the per-request user_info id through instead of relying
    // solely on session state. See that function's docblock for the
    // full explanation.
    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_whatsapp_2fa_context($userId);
    if($context["id"] <= 0) {
        throw new \WHMCS\Exception("Could not identify your account.");
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_whatsapp_2fa_code"] ?? ""));
    if($submitted === "") {
        throw new \WHMCS\Exception("Please enter the verification code we sent you over WhatsApp.");
    }

    $settings = dct_whatsapp_2fa_settings_from_params($params);
    $ip = dct_whatsapp_2fa_ip($settings);
    $result = WhatsAppTwoFactorService::verify($context["id"], $context["type"], WhatsAppTwoFactorService::PURPOSE_ACTIVATION, $submitted, $ip, $settings);

    if($result["status"] !== "valid") {
        $messages = [
            "invalid" => "That code is incorrect.",
            "expired" => "That code has expired — click Enable again to get a new one.",
            "consumed" => "That code was already used — click Enable again to get a new one.",
            "locked" => "Too many incorrect attempts — click Enable again to get a new one.",
            "no_challenge" => "No pending verification found — click Enable again to get a new one.",
            "rate_limited" => "Too many attempts — please wait a moment and try again.",
        ];
        throw new \WHMCS\Exception($messages[$result["status"]] ?? "Verification failed.");
    }

    WhatsAppTwoFactorService::completeActivation($context["id"], $context["type"], "user");

    // Mutual exclusion: only one primary 2FA method may be active at a
    // time — activating WhatsApp here automatically deactivates Email/
    // TOTP if either was active (enrollment preserved, not deleted).
    // Server-side, not a UI label — see TwoFactorAuthenticationService.
    if(class_exists(TwoFactorAuthenticationService::class)) {
        TwoFactorAuthenticationService::activateExclusive("whatsapp", $context["id"], $context["type"], "user");
    }

    // "settings" (never "msg") is the confirmed native success contract
    // — deliberately empty, since this module manages its own
    // verification state entirely via WhatsAppTwoFactorService, never
    // via WHMCS's own user_settings storage.
    return ["settings" => []];
}

function dct_whatsapp_2fa_challenge($params)
{
    dct_whatsapp_2fa_bootstrap();
    if(!class_exists(WhatsAppTwoFactorService::class)) {
        return "<div class=\"alert alert-danger\">WhatsApp 2FA is unavailable — the Security Pack addon module is not installed or active.</div>";
    }

    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_whatsapp_2fa_context($userId);
    if($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    if(!WhatsAppTwoFactorService::isActive($context["id"], $context["type"])) {
        return "<div class=\"alert alert-warning\">WhatsApp Two-Factor Authentication is not currently active for this account. Please contact an administrator.</div>";
    }

    $settings = dct_whatsapp_2fa_settings_from_params($params);
    $ip = dct_whatsapp_2fa_ip($settings);

    // 2026-08-22 — Requirements doc Section 3: trusted-browser check
    // (own hidden field, own service, never merged with the bypass
    // OR-chain below — see dct_email_2fa.php's matching block / the
    // TrustedBrowserService class docblock for the full rationale).
    $trustedBrowserToken = TrustedBrowserService::readCookieToken();
    if($trustedBrowserToken !== "" && TrustedBrowserService::isValidForIdentity($trustedBrowserToken, $context["id"], $context["type"])) {
        return <<<HTML
            <p>Trusted browser recognized — continuing automatically.</p>
            <form id="dct_whatsapp_2fa_trusted_browser_form" method="post" action="dologin.php">
                <input type="hidden" name="dct_whatsapp_2fa_trusted_browser" value="1">
            </form>
            <script>document.getElementById('dct_whatsapp_2fa_trusted_browser_form').submit();</script>
            HTML;
    }

    if(dct_whatsapp_2fa_bypass_active($context["id"], $context["type"], $ip)) {
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.bypass.used", "2FA bypass or IP exemption used — no code required for this login.", ["user_id" => $context["id"], "user_type" => $context["type"], "method" => "whatsapp"]);
        }
        return <<<HTML
            <p>Trusted sign-in recognized for this device — continuing automatically.</p>
            <form id="dct_whatsapp_2fa_bypass_form" method="post" action="dologin.php">
                <input type="hidden" name="dct_whatsapp_2fa_bypass" value="1">
            </form>
            <script>document.getElementById('dct_whatsapp_2fa_bypass_form').submit();</script>
            HTML;
    }

    $config = WhatsAppTwoFactorService::getConfig($context["id"], $context["type"]);
    $phone = $config ? (string) $config->phone : WhatsAppTwoFactorService::resolveAccountPhone($context["id"], $context["type"]);
    if($phone === null || $phone === "") {
        return "<div class=\"alert alert-danger\">No phone number is on file for your account — contact an administrator.</div>";
    }

    $result = WhatsAppTwoFactorService::createChallenge($context["id"], $context["type"], WhatsAppTwoFactorService::PURPOSE_LOGIN, $phone, $ip, $settings);
    $codeLength = OtpEngine::clampOtpLength($settings["whatsapp_2fa_length"]);
    $masked = dct_whatsapp_2fa_e(OtpEngine::maskPhone($phone));
    // 2026-08-25: mirrors dct_email_2fa_challenge()'s existing $cooldown
    // computation — drives the Resend Code countdown below, purely
    // presentational (see that block's docblock for the full rationale).
    $cooldown = (int) ($result["retry_after"] ?? OtpEngine::clampResendCooldownSeconds($settings["whatsapp_2fa_resend_cooldown"]));
    $status = (string) ($result["status"] ?? "error");

    if($status === "sent") {
        $headline = "We sent a {$codeLength}-digit code over WhatsApp to <strong>{$masked}</strong>.";
        $notice = "";
    } elseif ($status === "rate_limited") {
        $headline = "A {$codeLength}-digit code was already sent to <strong>{$masked}</strong>.";
        $notice = "<p class=\"text-muted small\">Wait a moment before requesting a new one.</p>";
    } elseif ($status === "send_failed") {
        $headline = "A {$codeLength}-digit code was generated for <strong>{$masked}</strong>, but WhatsApp delivery failed.";
        $notice = "<p class=\"text-muted small\">If nothing arrives shortly, contact an administrator.</p>";
    } else {
        $headline = "We're preparing a verification code for <strong>{$masked}</strong>.";
        $notice = "<p class=\"text-muted small\">If nothing arrives shortly, contact an administrator.</p>";
    }

    return <<<HTML
        <form action="dologin.php" method="post">
            <div class="form-group text-center">
                <p>{$headline}</p>
                {$notice}
                <input
                    type="text"
                    name="dct_whatsapp_2fa_code"
                    class="form-control text-center"
                    style="font-size: 24px; letter-spacing: 4px;"
                    maxlength="{$codeLength}"
                    pattern="[0-9]{{$codeLength}}"
                    placeholder="000000"
                    inputmode="numeric"
                    autocomplete="one-time-code"
                    autofocus
                    required
                >
            </div>
            <div class="checkbox">
                <label>
                    <input type="checkbox" name="dct_whatsapp_2fa_remember_browser" value="1"> Remember this browser for 30 days
                </label>
            </div>
        </form>
        <p class="text-center small" style="margin-top: 10px;">
            Didn't get a code?
            <a href="javascript:void(0);" id="dct_whatsapp_2fa_resend_link" onclick="window.location.reload(); return false;">Resend Code</a>
            <span id="dct_whatsapp_2fa_resend_countdown"></span>
        </p>
        <script>
        (function() {
            // Presentation only — the actual enforcement is still
            // WhatsAppTwoFactorService::createChallenge()'s existing
            // server-side cooldown/rate-limit, completely unchanged.
            // This just reflects that same remaining time visually
            // instead of leaving the link clickable with no indication
            // it's not useful yet.
            var seconds = {$cooldown};
            var link = document.getElementById("dct_whatsapp_2fa_resend_link");
            var countdownEl = document.getElementById("dct_whatsapp_2fa_resend_countdown");
            if (!link || !countdownEl || seconds <= 0) { return; }
            link.style.pointerEvents = "none";
            link.style.opacity = "0.5";
            var timer = setInterval(function() {
                seconds--;
                if (seconds <= 0) {
                    clearInterval(timer);
                    link.style.pointerEvents = "";
                    link.style.opacity = "";
                    countdownEl.textContent = "";
                    return;
                }
                var m = Math.floor(seconds / 60);
                var s = seconds % 60;
                countdownEl.textContent = " (" + m + ":" + (s < 10 ? "0" : "") + s + ")";
            }, 1000);
        })();
        </script>
        HTML;
}

function dct_whatsapp_2fa_verify($params)
{
    dct_whatsapp_2fa_bootstrap();
    if(!class_exists(WhatsAppTwoFactorService::class)) {
        return false;
    }

    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_whatsapp_2fa_context($userId);
    if($context["id"] <= 0) {
        return false;
    }

    $settings = dct_whatsapp_2fa_settings_from_params($params);
    $ip = dct_whatsapp_2fa_ip($settings);

    if(!empty($params["post_vars"]["dct_whatsapp_2fa_trusted_browser"])) {
        $token = TrustedBrowserService::readCookieToken();
        return $token !== "" && TrustedBrowserService::consume($token, $context["id"], $context["type"]);
    }

    if(!empty($params["post_vars"]["dct_whatsapp_2fa_bypass"])) {
        return dct_whatsapp_2fa_bypass_active($context["id"], $context["type"], $ip);
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_whatsapp_2fa_code"] ?? ""));
    if($submitted === "") {
        return false;
    }

    $result = WhatsAppTwoFactorService::verify($context["id"], $context["type"], WhatsAppTwoFactorService::PURPOSE_LOGIN, $submitted, $ip, $settings);
    if($result["status"] !== "valid") {
        return false;
    }

    $days = \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine::clampBypassDays($settings["whatsapp_2fa_bypass_days"] ?? 7);
    \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorBypassService::grantSameIpBypass($context["id"], $context["type"], $ip, $days, "whatsapp", "2fa");

    try {
        \Illuminate\Database\Capsule\Manager::table("nnm_security_pack_whatsapp2fa")
            ->where("user_id", $context["id"])->where("user_type", $context["type"])
            ->update(["last_verified_at" => date("Y-m-d H:i:s")]);
    } catch (\Throwable $e) {
    }

    if(!empty($params["post_vars"]["dct_whatsapp_2fa_remember_browser"])) {
        $deviceLabel = mb_substr((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""), 0, 255);
        $raw = TrustedBrowserService::create($context["id"], $context["type"], $deviceLabel, $ip);
        if($raw !== null) {
            TrustedBrowserService::setCookie($raw);
        }
    }

    return true;
}

/**
 * Reuses the ONE shared bypass store (Section 21/22) — applies
 * regardless of which method the user has enrolled. 2026-08-22: also
 * checks the dedicated 2FA IP exemption (Requirements doc Section 1) as
 * a third, independent OR-condition — see dct_email_2fa.php's matching
 * function for the full rationale (identical pattern across all three
 * live methods). class_exists() guarded to fail closed on a partial
 * deploy.
 */
function dct_whatsapp_2fa_bypass_active(int $userId, string $userType, string $ip): bool
{
    $bypass = \WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorBypassService::findActive($userId, $userType, $ip);
    if($bypass !== null) {
        return true;
    }
    return $ip !== "" && class_exists(TwoFactorIpExemptionService::class) && TwoFactorIpExemptionService::isExempt($ip, $userId, $userType);
}
