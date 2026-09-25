<?php

/**
 * Security Pack — Email Two-Factor Authentication, as a native WHMCS
 * "Security Module" (Setup > Security > Two-Factor Authentication).
 *
 * ARCHITECTURE CORRECTION (2.6.1): the 2.6.0 release enforced Email 2FA
 * via a hybrid of the AuthAdmin hook (admin) and a UserLogin/
 * ClientAreaPage post-login session gate (client), because WHMCS's
 * documented Authentication Hooks expose no client-area pre-session
 * login hook. That remains true of the *Hooks* API. It does NOT mean no
 * pre-session integration point exists at all: WHMCS ships its own
 * built-in Two-Factor Authentication methods (Time-Based Tokens, Duo,
 * YubiKey) through a SEPARATE module type — "Security Modules", under
 * modules/security/ — which genuinely does intervene between password
 * validation and completed authentication, for BOTH admin and client
 * logins, before any session is considered fully authenticated. This
 * file implements Email 2FA as one of those modules instead, which is
 * the correct, native way to add a WHMCS 2FA method — see
 * SECURITY-AUDIT-PHASE-4.md's "Phase 7 / 2.6.1" section for the full
 * investigation and its residual uncertainty.
 *
 * IMPORTANT — same disclosure the reference implementation this was
 * built from carries: the modules/security/ interface is NOT published
 * in WHMCS's official developer documentation (developers.whmcs.com's
 * module documentation covers only Gateway, Merchant Gateway,
 * Provisioning, Registrar, and Addon modules — confirmed by direct
 * inspection during this phase). This file's function names, $params
 * usage, and control flow were reconstructed from (a) a working
 * reference Two-Factor Authentication security module already
 * installed and activated in this WHMCS instance
 * (modules/security/dct2fa/dct2fa.php, "WhatsApp Verification"), and
 * (b) publicly visible third-party WHMCS security modules following the
 * identical folder-name-prefixed-function pattern. No WHMCS core source
 * file was available to trace directly. TEST THOROUGHLY end-to-end
 * (activation AND login, for both an admin and a client account) in a
 * staging copy of this WHMCS install before enabling it for real users,
 * and before making it "Required" for anyone.
 *
 * Reuses, never duplicates, the existing Email 2FA engine: every OTP,
 * hashing, rate-limiting, bypass, and audit-logging behaviour is
 * unchanged from 2.6.0 and lives entirely in
 * modules/addons/security_pack/lib/Security/Email2faService.php (plus
 * RateLimiter/IpUtil). This file is integration/wiring only — see that
 * class for the actual security logic and its existing unit tests.
 */

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorIpExemptionService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;

const DCT_EMAIL_2FA_DEFAULT_CODE_LENGTH = 6;
const DCT_EMAIL_2FA_DEFAULT_VALID_MINUTES = 10;
const DCT_EMAIL_2FA_DEFAULT_MAX_ATTEMPTS = 5;
const DCT_EMAIL_2FA_DEFAULT_MAX_RESENDS = 3;
// FIX (2026-08-25): raised from 60 to 300 per explicit request. Only
// changes the DEFAULT used when Setup > Security > Two-Factor
// Authentication > Email Verification > Configure has never had its own
// "Resend Cooldown" value saved for this install — if that field was
// already explicitly configured (any value), this constant is never
// consulted; $params["ResendCooldownSeconds"] wins. To guarantee 300s
// on an install that already has an explicit value saved, set it there
// directly too. Still within clampResendCooldownSeconds()'s existing
// 30-600s bounds — unchanged.
const DCT_EMAIL_2FA_DEFAULT_RESEND_COOLDOWN = 300;
const DCT_EMAIL_2FA_DEFAULT_BYPASS_DAYS = 7;

/**
 * Loads the security_pack addon's Email 2FA engine and its direct
 * dependencies. This is a cross-module require of the SAME classes the
 * security_pack addon itself uses — deliberately not a second/copied
 * implementation (mirrors dct2fa_bootstrap()'s require of the WhatsApp
 * addon's own autoloader/helpers for the exact same reason).
 *
 * As of the mutual-exclusion fix, this ALSO requires the WhatsApp/TOTP
 * services + all three TwoFactorProviderInterface implementations +
 * TwoFactorAuthenticationService — dct_email_2fa_activateverify() calls
 * TwoFactorAuthenticationService::activateExclusive() on successful
 * activation, which needs to know how to check/disable the OTHER two
 * methods too (see that class's docblock). Same combined require list
 * as dct_whatsapp_2fa.php/dct_totp_2fa.php's own bootstrap() now use —
 * intentionally identical across all three so a security module never
 * activates a method without being able to enforce exclusivity against
 * the other two.
 */
function dct_email_2fa_bootstrap(): void
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

/**
 * ============================================================================
 * TEMPORARY DIAGNOSTIC — Phase 7A (Live Sub-Account/Contact Authentication
 * Discovery). NOT part of the Security Pack package proper — do not leave
 * this deployed long-term. See step7_diagnostic_snippet.php for the full
 * standalone version, apply notes, and removal instructions; this is the
 * same code, inlined directly into this live file per request.
 *
 * Disabled by default (see the kill-switch below). Logs only a redacted,
 * structural snapshot of $params to WHMCS's own Activity Log — never
 * passwords, OTPs, recovery codes, trusted-browser tokens, API keys,
 * cookies, or session secrets, and email addresses are always masked via
 * Email2faService::maskEmail(). Read-only: it never changes the challenge/
 * verify outcome.
 *
 * TO ARM: uncomment the define() line immediately below (or define it
 * earlier in this file / in a bootstrap step) before deploying.
 * TO CAPTURE: have a secondary contact/sub-account log in and reach the
 * 2FA challenge screen, then check Utilities > Logs > Activity Log for
 * lines beginning "STEP7_DIAG".
 * TO REMOVE: delete this whole block plus the one-line call inside
 * dct_email_2fa_challenge() below, once the diagnostic has been captured.
 * ============================================================================
 */
// define('STEP7_DIAG_ENABLED', true);

function dct_email_2fa_step7_diagnostic(array $params): void
{
    if (!defined('STEP7_DIAG_ENABLED')) {
        return; // kill-switch: define('STEP7_DIAG_ENABLED', true); above this block to arm it
    }
    try {
        $redactKeyPattern = '/pass|otp|code|token|secret|cookie|session|api|key|credential/i';

        $summarizeUserInfo = function ($userInfo) use ($redactKeyPattern) {
            if (!is_array($userInfo)) {
                return ['_type' => gettype($userInfo)];
            }
            $out = [];
            foreach ($userInfo as $k => $v) {
                if (preg_match($redactKeyPattern, (string) $k)) {
                    $out[$k] = '[REDACTED]';
                    continue;
                }
                if (is_string($v) && strpos($k, 'email') !== false && class_exists('WHMCS\\Module\\Addon\\Security_Pack\\Security\\Email2faService')) {
                    $out[$k] = \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::maskEmail($v);
                    continue;
                }
                if (is_scalar($v) || $v === null) {
                    $out[$k] = $v;
                } else {
                    $out[$k] = '[' . gettype($v) . ']';
                }
            }
            return $out;
        };

        $snapshot = [
            'top_level_keys' => array_keys($params),
            'user_info' => isset($params['user_info']) ? $summarizeUserInfo($params['user_info']) : null,
            'client_area_defined' => defined('CLIENTAREA'),
            'admin_area_defined' => defined('ADMINAREA'),
            'session_keys_present' => array_keys($_SESSION ?? []),
        ];

        // Read-only, best-effort look at WHMCS's own unified User model
        // (WHMCS\User\User, the "Users and Client Accounts" login
        // identity added in 8.0 — docs.whmcs.com/9-0/clients/
        // users-and-client-accounts/), IF it exists on this WHMCS
        // version and $params gave us an id. Never writes anything,
        // never throws past this block.
        if (!empty($params['user_info']['id']) && class_exists('\\WHMCS\\User\\User')) {
            try {
                $userId = (int) $params['user_info']['id'];
                $userObj = \WHMCS\User\User::find($userId);
                if ($userObj) {
                    $snapshot['whmcs_user_model'] = [
                        'found' => true,
                        'id' => $userObj->id ?? null,
                        'email_masked' => isset($userObj->email) && class_exists('WHMCS\\Module\\Addon\\Security_Pack\\Security\\Email2faService')
                            ? \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::maskEmail((string) $userObj->email)
                            : null,
                        'getClientIds_exists' => method_exists($userObj, 'getClientIds'),
                        'getClientIds_result' => method_exists($userObj, 'getClientIds') ? $userObj->getClientIds() : null,
                        'getContactId_exists' => method_exists($userObj, 'getContactId'),
                        'getContactId_result' => method_exists($userObj, 'getContactId') ? $userObj->getContactId() : null,
                        'class_methods_sample' => array_slice(get_class_methods($userObj), 0, 40),
                    ];
                } else {
                    $snapshot['whmcs_user_model'] = ['found' => false];
                }
            } catch (\Throwable $inner) {
                $snapshot['whmcs_user_model_error'] = $inner->getMessage();
            }
        }

        // Read-only, best-effort look at the OLDER, SEPARATE
        // WHMCS\User\Client\Contact model (tblcontacts) — WHMCS's own
        // generated class docs (classdocs.whmcs.com/7.10/WHMCS/User/
        // Client/Contact.html) show this is a DIFFERENT identity from
        // WHMCS\User\User above: it has its own $id, $clientId, $email,
        // $isSubAccount (bool — "Sub-accounts may log into the client
        // area"), $passwordHash, and $permissions. A WHMCS install may
        // represent a logged-in secondary contact through EITHER this
        // class OR the newer User class above (or, on some versions,
        // both may resolve to something) — that is exactly the
        // ambiguity this diagnostic exists to settle. $passwordHash is
        // deliberately never read/logged here.
        if (!empty($params['user_info']['id']) && class_exists('\\WHMCS\\User\\Client\\Contact')) {
            try {
                $contactObj = \WHMCS\User\Client\Contact::find((int) $params['user_info']['id']);
                if ($contactObj) {
                    $snapshot['whmcs_contact_model'] = [
                        'found' => true,
                        'id' => $contactObj->id ?? null,
                        'clientId' => $contactObj->clientId ?? ($contactObj->client_id ?? null),
                        'isSubAccount' => $contactObj->isSubAccount ?? ($contactObj->is_sub_account ?? null),
                        'email_masked' => isset($contactObj->email) && class_exists('WHMCS\\Module\\Addon\\Security_Pack\\Security\\Email2faService')
                            ? \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::maskEmail((string) $contactObj->email)
                            : null,
                        'permissions_count' => isset($contactObj->permissions) && is_array($contactObj->permissions) ? count($contactObj->permissions) : null,
                    ];
                } else {
                    $snapshot['whmcs_contact_model'] = ['found' => false];
                }
            } catch (\Throwable $inner) {
                $snapshot['whmcs_contact_model_error'] = $inner->getMessage();
            }
        }

        if (function_exists('logActivity')) {
            logActivity('STEP7_DIAG ' . json_encode($snapshot, JSON_UNESCAPED_SLASHES));
        }
    } catch (\Throwable $e) {
        if (function_exists('logActivity')) {
            logActivity('STEP7_DIAG_ERROR ' . $e->getMessage());
        }
    }
}
/**
 * ============================================================================
 * END TEMPORARY DIAGNOSTIC — Phase 7A
 * ============================================================================
 */

/**
 * Pure helper (unit tested — see tests/run.php in the security_pack
 * addon): builds the settings array Email2faService's methods expect
 * (email_2fa_length, email_2fa_minutes, ...) from WHMCS's own
 * module-config $params (the primary/native control surface — every
 * field declared in dct_email_2fa_config() below is rendered and
 * persisted by WHMCS itself on Setup > Security > Two-Factor
 * Authentication, so this module never reads/writes its own copy of
 * these values), falling back to security_pack's own settings table
 * only for the two options that have no equivalent native config field
 * (challenge/bypass retention days, used solely by the daily cleanup
 * cron — see core/email_2fa.php).
 */
function dct_email_2fa_settings_from_params(array $params, array $fallback = []): array
{
    return [
        "email_2fa_length" => $params["CodeLength"] ?? $fallback["email_2fa_length"] ?? DCT_EMAIL_2FA_DEFAULT_CODE_LENGTH,
        "email_2fa_minutes" => $params["CodeValidMinutes"] ?? $fallback["email_2fa_minutes"] ?? DCT_EMAIL_2FA_DEFAULT_VALID_MINUTES,
        "email_2fa_max_attempts" => $params["MaxAttempts"] ?? $fallback["email_2fa_max_attempts"] ?? DCT_EMAIL_2FA_DEFAULT_MAX_ATTEMPTS,
        "email_2fa_max_resends" => $params["MaxResends"] ?? $fallback["email_2fa_max_resends"] ?? DCT_EMAIL_2FA_DEFAULT_MAX_RESENDS,
        "email_2fa_resend_cooldown" => $params["ResendCooldownSeconds"] ?? $fallback["email_2fa_resend_cooldown"] ?? DCT_EMAIL_2FA_DEFAULT_RESEND_COOLDOWN,
        "email_2fa_bypass_same_ip" => $params["BypassSameIp"] ?? $fallback["email_2fa_bypass_same_ip"] ?? "1",
        "email_2fa_bypass_days" => $params["BypassDays"] ?? $fallback["email_2fa_bypass_days"] ?? DCT_EMAIL_2FA_DEFAULT_BYPASS_DAYS,
    ];
}

/**
 * Determines whether the current login is an admin or a client, and
 * their id. Mirrors dct2fa_context() in the reference module exactly —
 * WHMCS does not pass this explicitly to these module functions, so
 * this relies on the same session-variable signal WHMCS's own login
 * flow relies on internally, with the same documented fallback.
 *
 * @return array{type: string, id: int}
 */
function dct_email_2fa_context(?int $fallbackUserId = null): array
{
    if (!empty($_SESSION["adminid"])) {
        return ["type" => Email2faService::TYPE_ADMIN, "id" => (int) $_SESSION["adminid"]];
    }

    // FIX (2026-08-23): prefer the identity WHMCS's security-module contract
    // hands this module for THIS specific call ($params['user_info']['id'],
    // passed in here as $fallbackUserId) over $_SESSION['uid'].
    //
    // Observed live on this install: for a secondary/sub-account WHMCS User
    // (tblusers_clients — e.g. a "Cirtsd dev" user granted access to a
    // "Domain Manager" client account), $_SESSION['uid'] did NOT reliably
    // reflect which User was actually authenticating. dct_email_2fa_activate()
    // used to call dct_email_2fa_context() with no argument at all, so it
    // depended entirely on $_SESSION['uid'] — and the verification code was
    // sent to the primary/owner account's email instead of the secondary
    // user's own, because this function checked $_SESSION['uid'] BEFORE ever
    // considering the id WHMCS actually passed in for the request.
    //
    // The per-call user_info id is the more trustworthy signal precisely
    // because WHMCS core supplies it fresh for that specific authentication
    // event, rather than reading session state that may reflect a different,
    // shared, or stale identity. Session remains the fallback for any call
    // site that genuinely has no id to pass (preserves prior behavior there).
    if ($fallbackUserId !== null && $fallbackUserId > 0) {
        try {
            $isAdmin = \Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $fallbackUserId)->exists();
        } catch (\Throwable $e) {
            $isAdmin = false;
        }
        return ["type" => $isAdmin ? Email2faService::TYPE_ADMIN : Email2faService::TYPE_CLIENT, "id" => $fallbackUserId];
    }

    if (!empty($_SESSION["uid"])) {
        return ["type" => Email2faService::TYPE_CLIENT, "id" => (int) $_SESSION["uid"]];
    }

    return ["type" => Email2faService::TYPE_CLIENT, "id" => 0];
}

/** Shared visitor-IP resolution — see the 2.6.1 fix note: never a second/local IP parser. */
function dct_email_2fa_ip(array $settings = []): string
{
    if(function_exists("security_pack_detect_visitor_ip")) {
        $ip = security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto");
        if($ip !== "") {
            return $ip;
        }
    }
    return (string) ($_SERVER["REMOTE_ADDR"] ?? "");
}

function dct_email_2fa_e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}

/**
 * Every field here is rendered and persisted natively by WHMCS's own
 * Setup > Security > Two-Factor Authentication screen — this module
 * never maintains a second copy of these values. Bounds match
 * Email2faService's own clamp*() methods exactly (defense in depth:
 * even if an out-of-range value were saved here, every clamp*() call
 * downstream still enforces it server-side).
 */
function dct_email_2fa_config()
{
    return [
        "FriendlyName" => [
            "Type" => "System",
            "Value" => "Email Verification",
        ],
        "ShortDescription" => [
            "Type" => "System",
            "Value" => "Two-Factor Authentication via a one-time code sent to your email address",
        ],
        "Description" => [
            "Type" => "System",
            "Value" => "Sends a one-time verification code to your account email address every time you log in. "
                . "Uses Security Pack's existing Email 2FA engine (OTP generation, hashing, rate limiting, "
                . "same-IP/administrator bypass, and audit logging) — configure it here, then Activate below "
                . "to enable it on your own account.",
        ],
        "CodeLength" => [
            "FriendlyName" => "Code Length",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_CODE_LENGTH,
            "Description" => "Digits (6-8)",
        ],
        "CodeValidMinutes" => [
            "FriendlyName" => "Code Valid",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_VALID_MINUTES,
            "Description" => "Minutes (1-30)",
        ],
        "MaxAttempts" => [
            "FriendlyName" => "Maximum Attempts",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_MAX_ATTEMPTS,
            "Description" => "Per code (3-10)",
        ],
        "MaxResends" => [
            "FriendlyName" => "Maximum Resends",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_MAX_RESENDS,
            "Description" => "Per challenge (1-10)",
        ],
        "ResendCooldownSeconds" => [
            "FriendlyName" => "Resend Cooldown",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_RESEND_COOLDOWN,
            "Description" => "Seconds (30-600)",
        ],
        "BypassSameIp" => [
            "FriendlyName" => "Allow Same-IP Bypass",
            "Type" => "yesno",
            "Description" => "Skip the code on later logins from the same account + same IP",
        ],
        "BypassDays" => [
            "FriendlyName" => "Bypass Duration",
            "Type" => "text",
            "Size" => "5",
            "Default" => (string) DCT_EMAIL_2FA_DEFAULT_BYPASS_DAYS,
            "Description" => "Days (1-90)",
        ],
    ];
}

/**
 * Shown when a user clicks "Get Started" to enable this method on their
 * own account (Client Area > Security Settings, or Admin > My Account).
 *
 * The activation email address is always the account's OWN, already-
 * verified WHMCS email — this module never lets a user type an
 * arbitrary address here (unlike the WhatsApp reference module, which
 * necessarily collects a phone number since WHMCS has no native phone
 * field for admins). Activation immediately sends a real OTP to that
 * address (Email2faService::beginActivation) and requires it to be
 * entered correctly before the account is EVER marked active — Step 6:
 * enabling never implicitly trusts an address, even the account's own,
 * without a live round trip proving it can actually be received.
 */
function dct_email_2fa_activate($params)
{
    dct_email_2fa_bootstrap();
    if(!class_exists(Email2faService::class)) {
        return "<div class=\"alert alert-danger\">Email 2FA is unavailable — the Security Pack addon module is not installed or active.</div>";
    }

    // FIX (2026-08-23): pass the per-request user_info id through, same as
    // dct_email_2fa_challenge() already does — see dct_email_2fa_context()'s
    // docblock for why this must not be omitted for a secondary/sub-account
    // WHMCS User.
    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_email_2fa_context($userId);
    if($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    $email = dct_email_2fa_resolve_account_email($context);
    if($email === "") {
        return "<div class=\"alert alert-danger\">No email address is on file for your account — add one before enabling Email 2FA.</div>";
    }

    $settings = dct_email_2fa_settings_from_params($params);
    $ip = dct_email_2fa_ip($settings);
    $result = Email2faService::beginActivation($context["id"], $context["type"], $email, $ip, $settings);
    $masked = Email2faService::maskEmail($email);
    $safeMasked = dct_email_2fa_e($masked);

    // Step correction (2.6.3): this used to show "We've sent a
    // verification code..." unconditionally, regardless of whether the
    // underlying send actually succeeded — beginActivation()/
    // createChallenge()'s return status was silently discarded. A
    // challenge row is always created (so the form below is always safe
    // to show, since a code may still be re-sent), but the message text
    // must reflect what actually happened, otherwise a real delivery
    // failure (see Email2faService::sendOtpEmail()) looks identical to
    // success and the user has no signal that "no mail received" is
    // expected rather than a fluke.
    $status = (string) ($result["status"] ?? "error");
    if($status === "sent") {
        $notice = "<p>We've sent a verification code to <strong>{$safeMasked}</strong>. Enter it below to finish enabling Email Two-Factor Authentication.</p>";
    } elseif ($status === "send_failed") {
        $notice = "<p>We generated a verification code for <strong>{$safeMasked}</strong>, but the email could not be sent. Ask an administrator to check Setup &gt; Addon Modules &gt; Security Pack &gt; Diagnostics (Email 2FA delivery) before trying again.</p>";
    } elseif ($status === "rate_limited") {
        $notice = "<p>A verification code was already sent to <strong>{$safeMasked}</strong> recently. Please check your inbox (and spam folder), or wait a moment before requesting a new one.</p>";
    } else {
        $notice = "<p>We were unable to start Email Two-Factor Authentication activation right now. Please try again shortly.</p>";
    }

    // WHMCS core re-invokes _activate() after a failed _activateverify()
    // and passes the caught exception's message back in as
    // $params["verifyError"] — confirmed against native totp.php's own
    // totp_activate(). Previously never read here, so a wrong code
    // silently reset the form with no explanation.
    $verifyErrorHtml = "";
    $verifyError = (string) ($params["verifyError"] ?? "");
    if($verifyError !== "") {
        $verifyErrorHtml = '<div class="alert alert-danger">' . dct_email_2fa_e($verifyError) . '</div>';
    }

    return <<<HTML
        {$notice}
        {$verifyErrorHtml}
        <div class="form-group">
            <label for="dct_email_2fa_code">Verification Code</label>
            <input type="text" class="form-control" name="dct_email_2fa_code" id="dct_email_2fa_code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" autofocus required>
        </div>
        <hr>
        <input type="submit" value="Enable Email Verification" class="btn btn-primary">
        HTML;
}

/**
 * Handles the submission of the activation form above. Only marks the
 * account active on a genuine OTP match (Email2faService::verify +
 * completeActivation) — never on form submission alone.
 */
/**
 * CRITICAL CONTRACT FIX — see the matching, fully-explained docblock on
 * dct_totp_2fa_activateverify() in dct_totp_2fa.php. Same bug, same
 * fix: WHMCS core decides success/failure purely by whether an
 * exception was thrown, never by inspecting a returned "msg" string —
 * so every prior failure path here (which only returned a "msg" array)
 * was silently treated as a SUCCESSFUL activation at the WHMCS-core
 * level regardless of whether the submitted code was actually correct.
 */
function dct_email_2fa_activateverify($params)
{
    dct_email_2fa_bootstrap();
    if(!class_exists(Email2faService::class)) {
        throw new \WHMCS\Exception("Email 2FA is unavailable — the Security Pack addon module is not installed or active.");
    }

    // FIX (2026-08-23): same fix as dct_email_2fa_activate() above — pass
    // the per-request user_info id through instead of relying solely on
    // session state.
    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_email_2fa_context($userId);
    if($context["id"] <= 0) {
        throw new \WHMCS\Exception("Could not identify your account.");
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_email_2fa_code"] ?? ""));
    if($submitted === "") {
        throw new \WHMCS\Exception("Please enter the verification code we emailed you.");
    }

    $settings = dct_email_2fa_settings_from_params($params);
    $ip = dct_email_2fa_ip($settings);
    $result = Email2faService::verify($context["id"], $context["type"], Email2faService::PURPOSE_ACTIVATION, $submitted, $ip, $settings);

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

    Email2faService::completeActivation($context["id"], $context["type"], "user");

    // Mutual exclusion: only one primary 2FA method may be active at a
    // time — activating Email here automatically deactivates WhatsApp/
    // TOTP if either was active (enrollment preserved, not deleted).
    // Server-side, not a UI label — see TwoFactorAuthenticationService.
    if(class_exists(TwoFactorAuthenticationService::class)) {
        TwoFactorAuthenticationService::activateExclusive("email", $context["id"], $context["type"], "user");
    }

    // "settings" (never "msg") is the confirmed native success contract
    // — deliberately empty, since this module manages its own
    // verification state entirely via Email2faService, never via
    // WHMCS's own user_settings storage.
    return ["settings" => []];
}

/**
 * Shown after a correct username/password, before granting access — the
 * genuine pre-completion second-factor gate this module exists to
 * provide (see the 2.6.1 architecture correction note at the top of
 * this file). Sends (or re-sends, respecting the existing cooldown) the
 * code via the SAME Email2faService::createChallenge() the 2.6.0
 * client/admin flows already used, and renders the entry form.
 *
 * If a valid same-IP or administrator bypass already covers this exact
 * (user, ip) pair, the challenge is skipped entirely and an auto-
 * submitting form is rendered instead — dct_email_2fa_verify() re-checks
 * the SAME bypass before honoring this, so this is not a client-trusted
 * shortcut (Step 27: still scoped to user+IP, never IP alone).
 */
function dct_email_2fa_challenge($params)
{
    dct_email_2fa_step7_diagnostic($params);
    dct_email_2fa_bootstrap();
    if(!class_exists(Email2faService::class)) {
        return "<div class=\"alert alert-danger\">Email 2FA is unavailable — the Security Pack addon module is not installed or active.</div>";
    }

    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_email_2fa_context($userId);
    if($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    if(!Email2faService::isActive($context["id"], $context["type"])) {
        // Should not normally be reachable — WHMCS only invokes this
        // module's challenge() for an account that has actually selected
        // it as their 2FA method. Rather than guess at an unconfirmed
        // "skip this factor" return contract (challenge()'s documented
        // uses only ever return renderable HTML — see the reference
        // module), fail informatively: no OTP is sent, and the account
        // owner is told to contact an administrator rather than being
        // silently let through or silently stuck.
        return "<div class=\"alert alert-warning\">Email Two-Factor Authentication is not currently active for this account. Please contact an administrator.</div>";
    }

    $settings = dct_email_2fa_settings_from_params($params);
    $ip = dct_email_2fa_ip($settings);

    // 2026-08-22 — Requirements doc Section 3: trusted-browser check.
    // DELIBERATELY a separate check, own hidden-field name
    // (dct_email_2fa_trusted_browser, never dct_email_2fa_bypass), and
    // checked read-only here (no side effects) — verify() independently
    // re-checks AND consumes it via TrustedBrowserService::consume(),
    // same discipline as the existing bypass check below. This must
    // never be merged with dct_email_2fa_bypass_active()'s same-IP/
    // admin-bypass/IP-exemption OR-chain — see TrustedBrowserService's
    // class docblock for why these three stay independent.
    $trustedBrowserToken = TrustedBrowserService::readCookieToken();
    if($trustedBrowserToken !== "" && TrustedBrowserService::isValidForIdentity($trustedBrowserToken, $context["id"], $context["type"])) {
        return <<<HTML
            <p>Trusted browser recognized — continuing automatically.</p>
            <form id="dct_email_2fa_trusted_browser_form" method="post" action="dologin.php">
                <input type="hidden" name="dct_email_2fa_trusted_browser" value="1">
            </form>
            <script>document.getElementById('dct_email_2fa_trusted_browser_form').submit();</script>
            HTML;
    }

    if(dct_email_2fa_bypass_active($context["id"], $context["type"], $ip)) {
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.bypass.used", "Email 2FA bypass or IP exemption used — no OTP required for this login.", ["user_id" => $context["id"], "user_type" => $context["type"]]);
        }
        return <<<HTML
            <p>Trusted sign-in recognized for this device — continuing automatically.</p>
            <form id="dct_email_2fa_bypass_form" method="post" action="dologin.php">
                <input type="hidden" name="dct_email_2fa_bypass" value="1">
            </form>
            <script>document.getElementById('dct_email_2fa_bypass_form').submit();</script>
            HTML;
    }

    $config = Email2faService::getConfig($context["id"], $context["type"]);
    $email = $config ? (string) $config->email : dct_email_2fa_resolve_account_email($context);
    if($email === "") {
        return "<div class=\"alert alert-danger\">No email address is on file for your account — contact an administrator.</div>";
    }

    $result = Email2faService::createChallenge($context["id"], $context["type"], Email2faService::PURPOSE_LOGIN, $email, $ip, $settings);
    $codeLength = Email2faService::clampOtpLength($settings["email_2fa_length"]);
    $masked = dct_email_2fa_e(Email2faService::maskEmail($email));
    $cooldown = (int) ($result["retry_after"] ?? Email2faService::clampResendCooldownSeconds($settings["email_2fa_resend_cooldown"]));
    $status = (string) ($result["status"] ?? "error");

    // Step correction (2.6.3): distinguish "already have one, don't
    // panic" (rate_limited) from an actual delivery failure (send_failed)
    // — these previously shared one vague "already on its way" message,
    // which hid real outages from both the user and support staff.
    if($status === "sent") {
        $headline = "We sent a {$codeLength}-digit code to <strong>{$masked}</strong>.";
        $notice = "";
    } elseif ($status === "rate_limited") {
        $headline = "A {$codeLength}-digit code was already sent to <strong>{$masked}</strong>.";
        $notice = "<p class=\"text-muted small\">Check your inbox (and spam folder), or wait a moment before requesting a new one.</p>";
    } elseif ($status === "send_failed") {
        $headline = "A {$codeLength}-digit code was generated for <strong>{$masked}</strong>, but delivery failed.";
        $notice = "<p class=\"text-muted small\">If you don't receive it shortly, contact an administrator — mail delivery may need attention.</p>";
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
                    name="dct_email_2fa_code"
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
                    <input type="checkbox" name="dct_email_2fa_remember_browser" value="1"> Remember this browser for 30 days
                </label>
            </div>
        </form>
        <p class="text-center small" style="margin-top: 10px;">
            Didn't get a code?
            <a href="javascript:void(0);" id="dct_email_2fa_resend_link" onclick="window.location.reload(); return false;">Resend Code</a>
            <span id="dct_email_2fa_resend_countdown"></span>
        </p>
        <script>
        (function() {
            // Presentation only — the actual enforcement is still
            // Email2faService::createChallenge()'s existing server-side
            // cooldown/rate-limit, completely unchanged. This just
            // reflects that same remaining time visually instead of
            // leaving the link clickable with no indication it's not
            // useful yet.
            var seconds = {$cooldown};
            var link = document.getElementById("dct_email_2fa_resend_link");
            var countdownEl = document.getElementById("dct_email_2fa_resend_countdown");
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

/**
 * Verifies the code the user typed on the challenge screen above, OR
 * honors an active bypass carried through via the auto-submitting form
 * dct_email_2fa_challenge() rendered — re-checked here independently
 * (never trusted purely from the presence of the hidden field), so a
 * tampered/replayed POST of that field alone cannot grant access
 * without a genuinely active, correctly-scoped bypass.
 *
 * A successful OTP verification also grants/refreshes the same-IP
 * bypass immediately (Email2faService::grantSameIpBypass), matching the
 * documented "refresh, not silently extend" policy from 2.6.0.
 */
function dct_email_2fa_verify($params)
{
    dct_email_2fa_bootstrap();
    if(!class_exists(Email2faService::class)) {
        return false;
    }

    $userId = (int) ($params["user_info"]["id"] ?? 0);
    $context = dct_email_2fa_context($userId);
    if($context["id"] <= 0) {
        return false;
    }

    $settings = dct_email_2fa_settings_from_params($params);
    $ip = dct_email_2fa_ip($settings);

    if(!empty($params["post_vars"]["dct_email_2fa_trusted_browser"])) {
        // Independently re-checked AND consumed here — never trust the
        // hidden field's mere presence (same discipline as the bypass
        // branch below). This path is a shortcut through the challenge,
        // NOT a genuine verification — it must never itself be treated
        // as an opportunity to create a new trusted-browser token (see
        // TrustedBrowserService's docblock: only a REAL OTP/recovery
        // success may do that).
        $token = TrustedBrowserService::readCookieToken();
        return $token !== "" && TrustedBrowserService::consume($token, $context["id"], $context["type"]);
    }

    if(!empty($params["post_vars"]["dct_email_2fa_bypass"])) {
        return dct_email_2fa_bypass_active($context["id"], $context["type"], $ip);
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_email_2fa_code"] ?? ""));
    if($submitted === "") {
        return false;
    }

    $result = Email2faService::verify($context["id"], $context["type"], Email2faService::PURPOSE_LOGIN, $submitted, $ip, $settings);
    if($result["status"] !== "valid") {
        return false;
    }

    Email2faService::grantSameIpBypass($context["id"], $context["type"], $ip, $settings);
    try {
        \Illuminate\Database\Capsule\Manager::table("nnm_security_pack_email2fa")
            ->where("user_id", $context["id"])->where("user_type", $context["type"])
            ->update(["last_verified_at" => date("Y-m-d H:i:s")]);
    } catch (\Throwable $e) {
    }

    // 2026-08-22 — Requirements doc Section 3: only a REAL OTP-code
    // success (this exact branch — never the trusted-browser or
    // admin/IP-bypass shortcuts above, which both return earlier) may
    // create a new trusted-browser token, and only when the user
    // explicitly opted in.
    if(!empty($params["post_vars"]["dct_email_2fa_remember_browser"])) {
        $deviceLabel = mb_substr((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""), 0, 255);
        $raw = TrustedBrowserService::create($context["id"], $context["type"], $deviceLabel, $ip);
        if($raw !== null) {
            TrustedBrowserService::setCookie($raw);
        }
    }

    return true;
}

/**
 * Shared "no challenge needed" check (administrator-manual bypass, OR
 * same-IP bypass, OR a dedicated 2FA IP exemption), reused by both
 * dct_email_2fa_challenge() and dct_email_2fa_verify() so they can never
 * disagree about whether a challenge currently applies.
 *
 * 2026-08-22 — added the TwoFactorIpExemptionService check (Requirements
 * doc Section 1). Deliberately a THIRD, independent OR-condition here,
 * not folded into the bypass service itself — a 2FA IP exemption is a
 * fundamentally different grant (admin/company-configured, IP-only,
 * no expiry) from a same-IP/admin-manual bypass (identity+IP scoped,
 * time-limited) even though both currently answer the same yes/no
 * question at this call site. class_exists() guarded so a partial/
 * mid-upgrade install (addon updated, this module's own bundle not yet
 * redeployed) fails CLOSED — no exemption applied — rather than fatal.
 */
function dct_email_2fa_bypass_active(int $userId, string $userType, string $ip): bool
{
    if(Email2faService::findActiveAdminBypass($userId, $userType)) {
        return true;
    }
    if($ip !== "" && Email2faService::findActiveBypass($userId, $userType, $ip) !== null) {
        return true;
    }
    if($ip !== "" && class_exists(TwoFactorIpExemptionService::class) && TwoFactorIpExemptionService::isExempt($ip, $userId, $userType)) {
        return true;
    }
    return false;
}

/**
 * Resolves the account's own email address — client: WHMCS User email;
 * admin: the WHMCS admin's configured email. Never accepts a
 * client-supplied address (Step: identity/destination is never
 * request-controllable).
 */
function dct_email_2fa_resolve_account_email(array $context): string
{
    try {
        if($context["type"] === Email2faService::TYPE_ADMIN) {
            return (string) (\Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $context["id"])->value("email") ?? "");
        }
        $user = \Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $context["id"])->first();
        return $user ? (string) $user->email : "";
    } catch (\Throwable $e) {
        return "";
    }
}
