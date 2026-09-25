<?php

/**
 * dct_totp_native — a modern, secure, maintainable replacement for
 * WHMCS's native "Time Based Tokens" Security Module.
 *
 * WHY THIS EXISTS: WHMCS's own modules/security/totp/totp.php (ionCube-
 * encoded, decoded here only for reading its BEHAVIORAL CONTRACT — never
 * copied; see DIFFERENCES below) has no replay protection beyond a
 * 5-minute used-code list, no recovery codes, no rate limiting, no
 * trusted-device bypass, and its QR generation SILENTLY FALLS BACK to
 * sending the otpauth:// URI (including the secret) to a third-party API
 * (api.qrserver.com) if local dependencies aren't met. This module fixes
 * all of that while remaining a drop-in alternative an administrator can
 * enable instead — same enrollment flow, same authenticator-app
 * compatibility (RFC 6238), same "Setup > Security > Two-Factor
 * Authentication" location in the admin UI.
 *
 * INSTALLED AS A SEPARATE MODULE (dct_totp_native), NOT an overwrite of
 * modules/security/totp/ — a WHMCS core update ships and can silently
 * replace files under modules/security/totp/ at any time; this module's
 * own directory is never touched by a WHMCS core update. Existing users
 * already enrolled in native "Time Based Tokens" are entirely unaffected
 * and keep working exactly as before; this is an alternative an
 * administrator opts into per-account by having the user (re-)enroll
 * under "Time-Based Token (Enhanced)" instead.
 *
 * STANDALONE — no dependency on any addon module. Every table this
 * module needs (mod_dct_totp_native_*) is created lazily and idempotently
 * by lib/Schema.php the first time it's needed; there is no addon-style
 * `_activate()` install step for a Security Module to hook into.
 *
 * DIFFERENCES FROM NATIVE totp.php (all deliberate improvements):
 *  - Replay protection: a persisted last_used_step (RFC 4226 "moving
 *    factor") rejects any code at or below one already accepted, forever
 *    — not just within a rolling 5-minute window like native's used-code
 *    list.
 *  - QR generation is ALWAYS local/server-side (lib/QrGenerator.php, a
 *    from-scratch ISO/IEC 18004 encoder) — the secret NEVER leaves this
 *    server, unlike native's silent RemoteQrGenerator fallback.
 *  - Recovery codes: 10 single-use codes, so losing the device doesn't
 *    require an administrator to manually intervene.
 *  - Rate limiting on both enrollment verification and login attempts.
 *  - Optional trusted-device (same-account + same-IP) bypass — off by
 *    default, administrator-controlled duration.
 *  - Secret-at-rest encryption via libsodium (native totp.php stores the
 *    secret in `user_settings` via WHMCS core's own storage, whose
 *    at-rest protection this module does not control or depend on).
 *  - Identity for the pre-authentication challenge()/verify() calls is
 *    resolved exclusively from $params["user_info"]["id"] (the one value
 *    WHMCS supplies for THIS specific call) plus a DB-based admin/client
 *    type check — never from ambient PHP session state, which WHMCS
 *    shares between the admin area and client area on the same domain
 *    and can otherwise leak a stale, unrelated session's identity into a
 *    fresh login attempt.
 *
 * CONTRACT PRESERVED FROM NATIVE (confirmed via the real, decoded
 * totp.php — never guessed): `challenge()` returns ONLY bare form
 * controls, no `<form>` tag of its own, because WHMCS's own login page
 * already supplies the enclosing `<form action="dologin.php">` — nesting
 * a second form here would corrupt it.
 */

use WHMCS\Module\Security\DctTotpNative\Bypass;
use WHMCS\Module\Security\DctTotpNative\Enrollment;
use WHMCS\Module\Security\DctTotpNative\EventLog;
use WHMCS\Module\Security\DctTotpNative\QrGenerator;
use WHMCS\Module\Security\DctTotpNative\RateLimiter;
use WHMCS\Module\Security\DctTotpNative\RecoveryCodes;

const DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS = 7;
const DCT_TOTP_NATIVE_VERSION = "1.2.0";

function dct_totp_native_bootstrap(): void
{
    static $booted = false;
    if ($booted) {
        return;
    }
    $booted = true;

    if (!defined("WHMCS")) {
        define("WHMCS", true);
    }
    // robthree/twofactorauth (vendored below) requires PHP >=8.2 (its
    // own composer.json) — WHMCS 9.x's own minimum is already PHP 8.2,
    // so any WHMCS 9.x install satisfies this automatically. Guarded
    // explicitly anyway so an older PHP 8.1 host (still valid for
    // WHMCS 8.x) gets a clear, actionable message instead of a raw
    // "class not found"/parse fatal the first time this module runs.
    if (PHP_VERSION_ID < 80200) {
        throw new \RuntimeException("dct_totp_native requires PHP 8.2 or later (this server is running " . PHP_VERSION . "). This module's TOTP engine (robthree/twofactorauth) requires PHP 8.2+.");
    }
    // robthree/twofactorauth (MIT licensed), vendored verbatim under
    // lib/vendor/ — see Totp.php's docblock. Loaded FIRST since Totp.php
    // and NullQrCodeProvider.php both reference its classes.
    foreach ([
        "vendor/robthree/twofactorauth/TwoFactorAuthException.php",
        "vendor/robthree/twofactorauth/Algorithm.php",
        "vendor/robthree/twofactorauth/Providers/Qr/IQRCodeProvider.php",
        "vendor/robthree/twofactorauth/Providers/Rng/RNGException.php",
        "vendor/robthree/twofactorauth/Providers/Rng/IRNGProvider.php",
        "vendor/robthree/twofactorauth/Providers/Rng/CSRNGProvider.php",
        "vendor/robthree/twofactorauth/Providers/Time/TimeException.php",
        "vendor/robthree/twofactorauth/Providers/Time/ITimeProvider.php",
        "vendor/robthree/twofactorauth/Providers/Time/LocalMachineTimeProvider.php",
        "vendor/robthree/twofactorauth/TwoFactorAuth.php",
    ] as $file) {
        $path = __DIR__ . "/lib/" . $file;
        if (is_file($path)) {
            require_once $path;
        }
    }
    foreach ([
        "Schema.php",
        "EventLog.php",
        "RateLimiter.php",
        "NullQrCodeProvider.php",
        "Totp.php",
        "KeyStore.php",
        "QrGenerator.php",
        "RecoveryCodes.php",
        "Bypass.php",
        "Enrollment.php",
    ] as $file) {
        $path = __DIR__ . "/lib/" . $file;
        if (is_file($path)) {
            require_once $path;
        }
    }
}

/**
 * Resolves whether a given WHMCS ID belongs to an admin (tbladmins) or a
 * client (default assumption otherwise). DB-based, never session-based.
 */
function dct_totp_native_resolve_type_for_id(int $id): string
{
    try {
        $isAdmin = \Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $id)->exists();
    } catch (\Throwable $e) {
        $isAdmin = false;
    }
    return $isAdmin ? "admin" : "client";
}

/**
 * Session-based identity resolution — correct ONLY for post-
 * authentication flows (activate()/activateverify(), where the account
 * owner is already logged in and is enabling 2FA on their OWN account).
 */
function dct_totp_native_context(?int $fallbackUserId = null): array
{
    if (!empty($_SESSION["adminid"])) {
        return ["type" => "admin", "id" => (int) $_SESSION["adminid"]];
    }
    if (!empty($_SESSION["uid"])) {
        return ["type" => "client", "id" => (int) $_SESSION["uid"]];
    }
    if ($fallbackUserId !== null && $fallbackUserId > 0) {
        return ["type" => dct_totp_native_resolve_type_for_id($fallbackUserId), "id" => $fallbackUserId];
    }
    return ["type" => "client", "id" => (int) ($fallbackUserId ?? 0)];
}

/**
 * Identity resolution for the PRE-authentication login callbacks
 * (challenge()/verify()) ONLY — resolves exclusively from
 * $params["user_info"]["id"], never from ambient session state. See the
 * module docblock above for why.
 */
function dct_totp_native_login_identity(array $params): array
{
    $id = (int) ($params["user_info"]["id"] ?? 0);
    if ($id <= 0) {
        return ["type" => "client", "id" => 0];
    }
    return ["type" => dct_totp_native_resolve_type_for_id($id), "id" => $id];
}

/**
 * Identity resolution for the SELF-SERVICE enrollment callbacks
 * (activate()/activateverify()) ONLY. Prefers $params["user_info"]["id"]
 * (the value WHMCS itself supplies for this specific call); falls back
 * to the session-based dct_totp_native_context() only if WHMCS didn't
 * supply a usable id.
 */
function dct_totp_native_account_identity(array $params): array
{
    $id = (int) ($params["user_info"]["id"] ?? 0);
    if ($id > 0) {
        return ["type" => dct_totp_native_resolve_type_for_id($id), "id" => $id];
    }
    return dct_totp_native_context();
}

/**
 * $_SERVER["REMOTE_ADDR"] only — deliberately NOT trusting any
 * client-supplied header (X-Forwarded-For, CF-Connecting-IP, ...) by
 * default, since those are trivially spoofable unless the install's
 * actual reverse-proxy chain is known and verified. On an install
 * behind a reverse proxy/CDN, REMOTE_ADDR is the proxy's own IP for
 * every request — this only affects the accuracy of the same-IP bypass
 * feature (Bypass::isActive()/grant()), which is opt-in and off by
 * default; it never affects whether a TOTP/recovery code is accepted.
 */
function dct_totp_native_ip(): string
{
    return (string) ($_SERVER["REMOTE_ADDR"] ?? "");
}

function dct_totp_native_e($v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}

/**
 * 2026-08-27 — production bug fix (root cause of "Allow Same-IP Bypass
 * is on but the module still sees it as off"): the previous claim here —
 * that WHMCS passes this module's own config()-declared field values as
 * TOP-LEVEL keys directly on $params, "confirmed against the sibling
 * dct_totp_2fa module" — was WRONG. A live diagnostic dump of this
 * exact call's real $params keys came back as: whmcsVersion, settings,
 * user_info, user_settings, post_vars, twoFactorAuthentication — no
 * "BypassSameIp" key at top level at all. WHMCS nests this module's own
 * config field values under the "settings" key instead. Whatever earlier
 * "confirmation" led to the top-level assumption was never actually
 * verified against a live WHMCS install — this is.
 *
 * Reads from $params["settings"] first (the now-confirmed real location)
 * and falls back to the previously-assumed top-level keys only if
 * "settings" isn't present at all — harmless if this module is ever
 * called under a WHMCS version/context that genuinely does put them at
 * the top level, and avoids a second silent-failure mode if that ever
 * happens.
 */
function dct_totp_native_settings_from_params(array $params): array
{
    $settings = is_array($params["settings"] ?? null) ? $params["settings"] : [];
    return [
        "BypassSameIp" => $settings["BypassSameIp"] ?? $params["BypassSameIp"] ?? "",
        "BypassDays" => $settings["BypassDays"] ?? $params["BypassDays"] ?? DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS,
    ];
}

function dct_totp_native_config()
{
    return [
        "FriendlyName" => ["Type" => "System", "Value" => "Time-Based Token (Enhanced)"],
        "ShortDescription" => ["Type" => "System", "Value" => "Get codes from an authenticator app — with replay protection, recovery codes, and rate limiting native WHMCS TOTP doesn't have."],
        "Description" => ["Type" => "System", "Value" => "A modern, secure replacement for WHMCS's native Time Based Tokens module. Standard RFC 6238-compatible time-based one-time codes, works with the same authenticator apps (Google Authenticator, Microsoft Authenticator, Authy, ...). Adds: single-use recovery codes, persistent replay protection, per-account rate limiting, always-local QR generation (the secret never leaves this server), and an optional trusted-device bypass."],
        "BypassSameIp" => ["FriendlyName" => "Allow Same-IP Bypass", "Type" => "yesno", "Description" => "After a successful code entry, skip the challenge on later logins from the same account + same IP address."],
        "BypassDays" => ["FriendlyName" => "Bypass Duration", "Type" => "text", "Size" => "5", "Default" => (string) DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS, "Description" => "Days (1-90). Only used if Same-IP Bypass is enabled above."],
    ];
}

/**
 * Renders the enrollment step: generates a brand-new secret every time
 * this is opened (an abandoned enrollment is simply overwritten by the
 * next attempt, never silently activated). Shows the manual-entry
 * secret, the otpauth:// link, and an inline scannable QR image built
 * entirely server-side — no third-party QR API call, so the secret never
 * leaves this server. If the otpauth:// URI is too long for the
 * encoder's supported range, the QR image is silently omitted and manual
 * entry / the link remain the fallback (never a hard error).
 */
function dct_totp_native_activate($params)
{
    dct_totp_native_bootstrap();

    $context = dct_totp_native_account_identity($params);
    if ($context["id"] <= 0) {
        return "<div class=\"alert alert-danger\">Could not identify your account.</div>";
    }

    $label = $context["type"] . "#" . $context["id"];
    try {
        $email = $context["type"] === "admin"
            ? (string) (\Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $context["id"])->value("email") ?? "")
            : (string) (\Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $context["id"])->value("email") ?? "");
        if ($email !== "") {
            $label = $email;
        }
    } catch (\Throwable $e) {
    }

    $issuer = "WHMCS";
    try {
        $companyName = (string) \WHMCS\Config\Setting::getValue("CompanyName");
        if ($companyName !== "") {
            $issuer = $companyName;
        }
    } catch (\Throwable $e) {
    }

    $enrollment = Enrollment::beginEnrollment($context["id"], $context["type"], $label, $issuer);
    if (isset($enrollment["error"])) {
        return "<div class=\"alert alert-danger\">" . dct_totp_native_e($enrollment["error"]) . "</div>";
    }

    $secret = dct_totp_native_e($enrollment["formatted"]);
    $uri = dct_totp_native_e($enrollment["uri"]);

    $qrHtml = "";
    try {
        $svg = QrGenerator::generateSvg($enrollment["uri"], 5);
        $qrHtml = '<div style="display:inline-block;max-width:260px;">' . $svg . '</div><br>';
    } catch (\Throwable $e) {
        // Encoder couldn't fit this URI — manual entry / the link below still work.
    }

    // WHMCS core re-invokes _activate() after a failed _activateverify()
    // and passes the caught exception's message back in as
    // $params["verifyError"] — confirmed against native totp.php's own
    // totp_activate(), which reads exactly this key
    // ($params['verifyError'] ? '<div class="alert alert-danger">'...).
    // This module previously never read this key at all, so a wrong
    // code silently reset the form back to the QR screen with no
    // explanation — the form isn't broken, the error was just never
    // rendered. Escaped even though it currently only ever holds this
    // module's own fixed message strings, in case a future WHMCS
    // version routes a differently-sourced string through this key.
    $verifyErrorHtml = "";
    $verifyError = (string) ($params["verifyError"] ?? "");
    if ($verifyError !== "") {
        $verifyErrorHtml = '<div class="alert alert-danger">' . dct_totp_native_e($verifyError) . '</div>';
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
            <label for="dct_totp_native_code">6-digit code from your app</label>
            <input type="text" class="form-control" name="dct_totp_native_code" id="dct_totp_native_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" autofocus required>
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
 * An earlier version of this function returned `["msg" => "..."]` on
 * BOTH the success AND every failure path with no exception either way
 * — WHMCS core would therefore see "no exception" on every submission
 * regardless of whether the code was actually correct, and activate
 * 2FA at the WHMCS-core level even for a wrong/fake code, while this
 * module's own Enrollment table correctly stayed un-activated — a
 * broken split state where WHMCS believes 2FA is enabled but the
 * account is then locked out at the next real login. This was confirmed
 * live against the sibling dct_totp_2fa module (identical bug, same
 * fix) via a real enrollment attempt with an intentionally wrong code.
 *
 * UNVERIFIED (flagging honestly): whether WHMCS's core 2FA framework
 * also surfaces an ADDITIONAL "msg" key back to the user on a
 * successful activateverify() call — native's own totp.php never
 * returns one on success, so there is no confirmed reference for this.
 * Both "settings" (the confirmed-required key) and "msg" (best-effort,
 * in case WHMCS does display it) are returned below; the recovery codes
 * are the one thing that MUST reach the user somehow, so this needs a
 * real live test to confirm they actually appear on screen — if they
 * don't, the recovery codes will need a different delivery path (e.g.
 * a dedicated client-area page) rather than riding along in this
 * response.
 */
function dct_totp_native_activateverify($params)
{
    dct_totp_native_bootstrap();

    $context = dct_totp_native_account_identity($params);
    if ($context["id"] <= 0) {
        throw new \WHMCS\Exception("Could not identify your account.");
    }

    $submitted = preg_replace("/\D+/", "", (string) ($params["post_vars"]["dct_totp_native_code"] ?? ""));
    if ($submitted === "") {
        throw new \WHMCS\Exception("Please enter the 6-digit code from your authenticator app.");
    }

    $ip = dct_totp_native_ip();
    $result = Enrollment::verifyAndActivate($context["id"], $context["type"], $submitted, $ip);

    if ($result["status"] !== "valid") {
        $messages = [
            "invalid" => "That code is incorrect. Make sure your device's clock is accurate.",
            "no_pending_enrollment" => "No pending enrollment found — click Enable again to start over.",
            "rate_limited" => "Too many attempts — please wait a moment and try again.",
            "error" => "Time-Based Token could not be verified right now.",
        ];
        throw new \WHMCS\Exception($messages[$result["status"]] ?? "Verification failed.");
    }

    $recoveryNotice = "";
    if (!empty($result["recovery_codes"])) {
        $codes = implode(", ", array_map("dct_totp_native_e", $result["recovery_codes"]));
        $recoveryNotice = " Your one-time recovery codes (save these somewhere safe — shown only once): " . $codes;
    }

    // "settings" is the confirmed native success contract — deliberately
    // empty, since this module manages the encrypted secret entirely in
    // its own mod_dct_totp_native_secrets table, never via WHMCS's own
    // user_settings storage. "msg" is included as a best-effort delivery
    // path for the recovery codes — see the UNVERIFIED note above.
    return ["settings" => [], "msg" => "Time-Based Token Two-Factor Authentication enabled." . $recoveryNotice];
}

/**
 * No send step — the authenticator app already has a live code.
 *
 * CRITICAL (confirmed against the real native WHMCS
 * modules/security/totp/totp.php — its own totp_challenge() returns a
 * BARE `<div><input>...<input type="submit">...</div>` with NO `<form>`
 * tag): WHMCS's own login page already supplies the enclosing
 * `<form action="dologin.php">`, its CSRF token, and its submit
 * handling. A Security Module's challenge() must return ONLY bare form
 * controls — never its own nested `<form>`.
 */
/**
 * 2026-08-27 — production bug fix ("Administrator Manual Bypass also not
 * working"): this module's own Bypass class implements ONLY a same-
 * account+same-IP TRUSTED-DEVICE bypass (see that class's own docblock).
 * It has no concept of an administrator manually granting a temporary
 * bypass for a specific user — that feature ("Administrator Manual
 * Bypass") lives entirely in the separate DCTLAB Security Pack addon
 * (TwoFactorBypassService + its admin panel), and this module never
 * consulted it. Since dct_totp_native turned out to be the actual live
 * TOTP module on this install (see the 2026-08-27 secret-rotation
 * incident notes), an admin-created bypass had ZERO effect here — every
 * login still demanded a code regardless of the bypass an admin had just
 * granted.
 *
 * Fix: also check Security Pack's own bypass/IP-exemption store when the
 * addon is installed — resolved by string class name and guarded by
 * class_exists() throughout, so this module remains genuinely standalone
 * (per its own top-of-file docblock: "STANDALONE — no dependency on any
 * addon module") when Security Pack is absent; it simply never finds
 * those classes and this always returns false. Mirrors dct_totp_2fa's own
 * dct_totp_2fa_bypass_active() helper, so an administrator's bypass now
 * behaves identically regardless of which of the two TOTP modules a
 * given install actually uses. Fails CLOSED on any lookup error — never
 * grants a bypass it isn't sure of; the user just gets the normal code
 * challenge in that case.
 */
function dct_totp_native_addon_bypass_active(int $userId, string $userType, string $ip): bool
{
    $bypassClass = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TwoFactorBypassService";
    $exemptionClass = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TwoFactorIpExemptionService";
    try {
        if (!class_exists($bypassClass)) {
            // DIAGNOSTIC (2026-08-27, second pass — added after "still
            // not working" was reported once the first pass of this fix
            // was deployed). Rate-limited to once per hour (via this
            // module's own RateLimiter, keyed on a fixed string — never
            // per-user, so it can't be bypassed by testing with
            // different accounts) so a persistently-missing class can't
            // flood the WHMCS Activity Log. If this ever writes, it
            // means Security Pack's TwoFactorBypassService class is not
            // resolvable at all from THIS Security Module's execution
            // context — which tells us definitively whether the problem
            // is "the fix hasn't actually taken effect yet" (most
            // likely: PHP opcache serving a stale copy of this exact
            // file after the FTP upload — same symptom already seen once
            // in the TOTP secret-rotation incident) versus a genuine
            // class-resolution failure, instead of guessing a third
            // time. Check WHMCS Admin -> Utilities -> Logs -> Activity
            // Log for "[dct_totp_native] DIAGNOSTIC" after testing.
            if (RateLimiter::hit("addon_bypass_class_missing_diag", 1, 3600)) {
                EventLog::record(
                    "DIAGNOSTIC: Security Pack's TwoFactorBypassService class (WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TwoFactorBypassService) was not found during a login challenge — Administrator Manual Bypass cannot take effect until this resolves. Most likely cause: this updated dct_totp_native.php has not actually taken effect yet (stale PHP opcache after upload — ask your host to restart PHP-FPM/LSAPI or clear opcache). Less likely: the DCTLAB Security Pack addon is not active."
                );
            }
            return false;
        }
        $activeBypassRow = $bypassClass::findActive($userId, $userType, $ip);
        if ($activeBypassRow !== null) {
            return true;
        }
        $ipExempt = $ip !== "" && class_exists($exemptionClass) && $exemptionClass::isExempt($ip, $userId, $userType);
        if ($ipExempt) {
            return true;
        }
        // DIAGNOSTIC (2026-08-27, fourth pass): the class resolves fine
        // (we only reach here when it does) and findActive() ran without
        // throwing, but found nothing — logged every time (not rate-
        // limited, unlike the "class missing" diagnostic above) so the
        // NEXT test attempt gives a definitive answer instead of another
        // round of guessing: was findActive() even called with the
        // identity we expect, and did it genuinely find zero rows? Check
        // WHMCS Admin -> Utilities -> Logs -> Activity Log for
        // "[dct_totp_native] DIAGNOSTIC: no addon bypass found" right
        // after a login attempt.
        EventLog::record(
            "DIAGNOSTIC: no addon bypass found for user_id=" . $userId . " user_type=" . $userType . " ip=" . $ip . " — TwoFactorBypassService::findActive() returned null and no IP exemption matched. If an Administrator Manual Bypass was just created for this exact user_id+user_type, compare those values against what shows in the Security Pack admin panel's bypass table.",
            $userType === "client" ? $userId : 0
        );
    } catch (\Throwable $e) {
        try {
            EventLog::record("DIAGNOSTIC: Security Pack bypass lookup threw an exception: " . $e->getMessage());
        } catch (\Throwable $e2) {
        }
    }
    return false;
}

/**
 * 2026-08-27 — production fix ("Administrator Manual Bypass not added by
 * system" / "Remember this browser ... missing" report, client #666503):
 * dct_totp_native was missing TWO features its sibling live security
 * modules (dct_email_2fa, and the older dct_totp_2fa) already have —
 * this was reported as "the bypass isn't auto-created" and "the remember
 * browser checkbox is gone," but neither is actually a NEW auto-create
 * rule being invented; both already exist as an established pattern in
 * dct_email_2fa_verify()/dct_totp_2fa's own verify(), which is exactly
 * why a different account (client #666037, on Email Verification) DOES
 * show a same-IP row in the admin "Administrator Manual Bypass" table
 * (that table lists every scope, admin_manual AND same_ip together) —
 * dct_totp_native was simply the one live method never wired to either
 * feature:
 *
 *  1. "Remember this browser for 30 days" — TrustedBrowserService
 *     (Security Pack) already exists and is already used by
 *     dct_totp_2fa/dct_email_2fa/dct_whatsapp_2fa; this module's own
 *     challenge()/verify() never referenced it at all, so the checkbox
 *     never rendered and no cookie was ever set for a TOTP login.
 *  2. Security Pack's UNIFIED same-IP bypass
 *     (TwoFactorBypassService::grantSameIpBypass(), the one that
 *     populates the admin table shown above) was never called on a
 *     successful TOTP login — only this module's OWN separate,
 *     addon-independent `Bypass::grant()` was (a different table this
 *     module's own `BypassSameIp` setting has always controlled, kept
 *     exactly as-is below). Both are now granted together under the
 *     SAME existing `BypassSameIp` setting/condition, so nothing new is
 *     invented and the two never drift out of sync with each other —
 *     Security Pack integration remains fully optional (guarded by
 *     class_exists(), same pattern as the bypass-check integration
 *     already had), so this module still works standalone if the addon
 *     isn't installed.
 */
function dct_totp_native_trusted_browser_read_token(): string
{
    $class = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TrustedBrowserService";
    if (!class_exists($class)) {
        return "";
    }
    try {
        return (string) $class::readCookieToken();
    } catch (\Throwable $e) {
        return "";
    }
}

function dct_totp_native_trusted_browser_valid(string $token, int $userId, string $userType): bool
{
    if ($token === "") {
        return false;
    }
    $class = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TrustedBrowserService";
    if (!class_exists($class)) {
        return false;
    }
    try {
        return (bool) $class::isValidForIdentity($token, $userId, $userType);
    } catch (\Throwable $e) {
        return false;
    }
}

function dct_totp_native_challenge($params)
{
    dct_totp_native_bootstrap();

    $context = dct_totp_native_login_identity($params);
    if ($context["id"] <= 0) {
        return "<p class=\"text-danger\">Could not identify your account.</p>";
    }

    if (!Enrollment::isActive($context["id"], $context["type"])) {
        return "<p class=\"text-warning\">Time-Based Token Two-Factor Authentication is not currently active for this account. Please contact an administrator.</p>";
    }

    $ip = dct_totp_native_ip();
    $settings = dct_totp_native_settings_from_params($params);

    // "Remember this browser for 30 days" — checked BEFORE the same-IP
    // bypass, mirroring dct_totp_2fa_challenge()'s own ordering. Bare
    // hidden-input-on-the-enclosing-form pattern, its own field name —
    // never merged with the bypass/IP-exemption OR-chain below.
    $trustedBrowserToken = dct_totp_native_trusted_browser_read_token();
    if ($trustedBrowserToken !== "" && dct_totp_native_trusted_browser_valid($trustedBrowserToken, $context["id"], $context["type"])) {
        EventLog::record("TOTP trusted browser recognized for " . $context["type"] . " #" . $context["id"] . ".", $context["type"] === "client" ? $context["id"] : 0);
        return <<<HTML
            <p>Trusted browser recognized — continuing automatically.</p>
            <input type="hidden" name="dct_totp_native_trusted_browser" value="1">
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

    $addonBypassActive = dct_totp_native_addon_bypass_active($context["id"], $context["type"], $ip);
    if ($addonBypassActive || (!empty($settings["BypassSameIp"]) && Bypass::isActive($context["id"], $context["type"], $ip))) {
        EventLog::record("TOTP trusted-device bypass used for " . $context["type"] . " #" . $context["id"] . ".", $context["type"] === "client" ? $context["id"] : 0);
        // Bare hidden input on WHMCS's OWN outer form — no second
        // <form>. The script submits the ENCLOSING form
        // (document.currentScript.closest("form")), falling back to the
        // page's first <form> if the browser lacks Element.closest()
        // support, rather than creating and submitting a form of its own.
        return <<<HTML
            <p>Trusted sign-in recognized for this device — continuing automatically.</p>
            <input type="hidden" name="dct_totp_native_bypass" value="1">
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

    // Bare controls only (see docblock above). maxlength is 19 (not 6)
    // and there is no numeric-only pattern/inputmode because this single
    // field also accepts a recovery code (XXXX-XXXX-XXXX-XXXX) — see
    // dct_totp_native_verify() for how the two are distinguished.
    //
    // 2026-08-27 — removed this fragment's own "Verify" submit button, on
    // request: WHMCS's own outer login form (which encloses this bare
    // fragment — see the docblock on dct_totp_native_challenge() above)
    // already supplies its own "Login" submit button, so the two
    // buttons submitted the exact same form to the exact same place.
    // Matching the real native totp.php's own markup (which also ships
    // its own submit control) was the original reason this button
    // existed, but it read as a confusing duplicate in practice, so it's
    // gone — WHMCS's native "Login" button is the only submit control on
    // this screen now. No behavior changes: the field still submits via
    // the outer form's own button/Enter-key handling exactly as before.
    return <<<HTML
        <div class="form-group text-center">
            <p>Enter the 6-digit code from your authenticator app.</p>
            <input
                type="text"
                name="dct_totp_native_code"
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
                    <input type="checkbox" name="dct_totp_native_remember_browser" value="1"> Remember this browser for 30 days
                </label>
            </div>
            <p class="text-muted small" style="margin-top: 8px;">Lost your device? Enter one of your recovery codes instead of a 6-digit code.</p>
        </div>
        HTML;
}

function dct_totp_native_verify($params)
{
    dct_totp_native_bootstrap();

    $context = dct_totp_native_login_identity($params);
    if ($context["id"] <= 0) {
        return false;
    }

    $ip = dct_totp_native_ip();
    $settings = dct_totp_native_settings_from_params($params);

    if (!empty($params["post_vars"]["dct_totp_native_trusted_browser"])) {
        $token = dct_totp_native_trusted_browser_read_token();
        if ($token === "") {
            return false;
        }
        $class = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TrustedBrowserService";
        if (!class_exists($class)) {
            return false;
        }
        try {
            return (bool) $class::consume($token, $context["id"], $context["type"]);
        } catch (\Throwable $e) {
            return false;
        }
    }

    if (!empty($params["post_vars"]["dct_totp_native_bypass"])) {
        // 2026-08-27 fix (see dct_totp_native_addon_bypass_active()'s own
        // docblock): the hidden auto-submit field set by _challenge()
        // above can now be reached via EITHER Security Pack's own
        // Administrator Manual Bypass / IP exemption, or this module's
        // own same-IP trusted-device bypass — accept whichever one
        // _challenge() actually granted it for.
        return dct_totp_native_addon_bypass_active($context["id"], $context["type"], $ip)
            || (!empty($settings["BypassSameIp"]) && Bypass::isActive($context["id"], $context["type"], $ip));
    }

    $raw = trim((string) ($params["post_vars"]["dct_totp_native_code"] ?? ""));
    if ($raw === "") {
        return false;
    }
    $digitsOnly = preg_replace("/\s+/", "", $raw) ?? "";

    if (preg_match('/^\d{6}$/', $digitsOnly)) {
        $result = Enrollment::verifyLogin($context["id"], $context["type"], $digitsOnly, $ip);
        // "replayed"/"invalid"/"rate_limited"/"no_challenge"/"error" all
        // fail the same way here — verifyLogin() already recorded the
        // specific event for whichever case occurred.
        if ($result["status"] !== "valid") {
            return false;
        }
    } else {
        if (!RecoveryCodes::attemptConsume($context["id"], $context["type"], $raw, $ip)) {
            return false;
        }
    }

    // 2026-08-27 — unconditional diagnostic (this incident's next report,
    // "same-IP bypass still not feeding the shared table"): logs the RAW
    // setting value on every successful verification, regardless of
    // whether it's truthy, so the next report tells us definitively
    // whether "Allow Same-IP Bypass" is even enabled for this module —
    // that alone (not a code bug) would fully explain a bypass never
    // appearing, since BOTH this module's own local bypass AND the
    // unified Security Pack grant below share this one setting.
    if (function_exists("logActivity")) {
        try {
            logActivity("[dct_totp_native] DIAGNOSTIC v5: verify() success for " . $context["type"] . " #" . $context["id"] . " ip=" . $ip . " — settings[\"BypassSameIp\"]=" . var_export($settings["BypassSameIp"] ?? null, true) . " (a falsy value here means NEITHER this module's own bypass NOR Security Pack's unified same-IP bypass will be granted — check Setup > Security > Two-Factor Authentication > Time-Based Token (Enhanced) > \"Allow Same-IP Bypass\").", $context["type"] === "client" ? $context["id"] : 0);
        } catch (\Throwable $e) {
        }
        // 2026-08-27 (third pass) — the admin confirms "Allow Same-IP
        // Bypass" IS checked/saved, yet the line above still shows it
        // arriving empty. Rather than guess at WHY (a WHMCS-side config
        // cache, a field-name mismatch, a settings-scope issue), dump
        // every top-level $params KEY WHMCS actually handed this call
        // (names only — this deliberately never logs post_vars, which
        // could contain the submitted TOTP code) plus the raw value of
        // any key that merely CONTAINS "bypass" case-insensitively, so
        // the next report shows the real key WHMCS is using instead of
        // the one this module assumed.
        try {
            $keyNames = [];
            $bypassLikeKeys = [];
            foreach ($params as $k => $v) {
                if (!is_string($k)) {
                    continue;
                }
                $keyNames[] = $k;
                if (stripos($k, "bypass") !== false && is_scalar($v)) {
                    $bypassLikeKeys[] = $k . "=" . var_export($v, true);
                }
            }
            // 2026-08-27 — confirmed via this exact diagnostic that
            // WHMCS nests this module's config field values under a
            // "settings" key rather than the top level (see
            // dct_totp_native_settings_from_params()'s own docblock for
            // the fix this drove). Recurse one level into "settings"
            // (and "user_settings", just in case a future report shows
            // THAT'S actually the right one instead) so this diagnostic
            // now shows the real nested value directly, rather than
            // requiring another guess-and-redeploy round if the exact
            // key casing inside "settings" ever turns out different
            // from the top-level field name this module declares.
            foreach (["settings", "user_settings"] as $nestedKey) {
                $nested = is_array($params[$nestedKey] ?? null) ? $params[$nestedKey] : null;
                if ($nested === null) {
                    continue;
                }
                foreach ($nested as $nk => $nv) {
                    if (is_string($nk) && stripos($nk, "bypass") !== false && is_scalar($nv)) {
                        $bypassLikeKeys[] = $nestedKey . "." . $nk . "=" . var_export($nv, true);
                    }
                }
            }
            logActivity("[dct_totp_native] DIAGNOSTIC v5: verify() \$params top-level keys for this call: " . implode(", ", $keyNames) . " — keys containing \"bypass\" (any case, including one level into settings/user_settings) and their raw values: " . (count($bypassLikeKeys) ? implode(" | ", $bypassLikeKeys) : "NONE FOUND") . ".");
        } catch (\Throwable $e) {
        }
    }

    if (!empty($settings["BypassSameIp"])) {
        $days = (int) ($settings["BypassDays"] ?? DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS);
        $days = $days > 0 ? $days : DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS;
        Bypass::grant($context["id"], $context["type"], $ip, $days);
        // Also grant Security Pack's own UNIFIED same-IP bypass, under
        // this SAME setting/condition — see this function's own
        // docblock above (on dct_totp_native_challenge()) for why: this
        // is what makes the admin "Administrator Manual Bypass" table
        // show a row for a TOTP login, matching what Email/WhatsApp
        // logins already do. Fully optional — a standalone install with
        // no Security Pack addon just skips this, same as the bypass
        // CHECK earlier in this file already does.
        $bypassClass = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TwoFactorBypassService";
        $classExists = class_exists($bypassClass);
        if (function_exists("logActivity")) {
            try {
                logActivity("[dct_totp_native] DIAGNOSTIC v5: BypassSameIp is enabled — attempting unified grant for " . $context["type"] . " #" . $context["id"] . " ip=" . $ip . " days=" . $days . " — TwoFactorBypassService class_exists=" . ($classExists ? "true" : "false") . (!$classExists ? " (Security Pack addon not active/loaded — this is why nothing shows in its admin table; this module's OWN local bypass is still granted separately and is unaffected)" : ""), $context["type"] === "client" ? $context["id"] : 0);
            } catch (\Throwable $e) {
            }
        }
        if ($classExists) {
            try {
                $bypassClass::grantSameIpBypass($context["id"], $context["type"], $ip, $days, "totp", "2fa");
                if (function_exists("logActivity")) {
                    try {
                        logActivity("[dct_totp_native] DIAGNOSTIC v5: TwoFactorBypassService::grantSameIpBypass() returned without throwing for " . $context["type"] . " #" . $context["id"] . " — if the admin bypass table still doesn't show a row, compare user_id/user_type here against what that table displays.", $context["type"] === "client" ? $context["id"] : 0);
                    } catch (\Throwable $e) {
                    }
                }
            } catch (\Throwable $e) {
                try {
                    EventLog::record("DIAGNOSTIC: Security Pack's TwoFactorBypassService::grantSameIpBypass() threw for " . $context["type"] . " #" . $context["id"] . ": " . $e->getMessage());
                } catch (\Throwable $e2) {
                }
            }
        }
    }

    // "Remember this browser for 30 days" — only ever reachable from
    // THIS genuine code/recovery-code success branch, never from the
    // bypass/trusted-browser-itself auto-submit branches above (which
    // both return before this point) — matching TrustedBrowserService's
    // own documented design ("granted only when the user EXPLICITLY
    // opts in on a REAL successful verification").
    if (!empty($params["post_vars"]["dct_totp_native_remember_browser"])) {
        $class = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TrustedBrowserService";
        if (class_exists($class)) {
            try {
                $deviceLabel = mb_substr((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""), 0, 255);
                $rawToken = $class::create($context["id"], $context["type"], $deviceLabel, $ip);
                if ($rawToken !== null) {
                    $class::setCookie($rawToken);
                }
            } catch (\Throwable $e) {
                try {
                    EventLog::record("DIAGNOSTIC: Security Pack's TrustedBrowserService::create() threw for " . $context["type"] . " #" . $context["id"] . ": " . $e->getMessage());
                } catch (\Throwable $e2) {
                }
            }
        }
    }

    return true;
}
