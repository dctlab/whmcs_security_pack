<?php

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.6 — Email Two-Factor Authentication: account-lifecycle
 * hooks and admin visibility ONLY.
 *
 * ARCHITECTURE CORRECTION (2.6.1) — READ BEFORE EDITING THIS FILE:
 *
 * The 2.6.0 release enforced Email 2FA itself from THIS file, via a
 * hybrid of the AuthAdmin hook (a real pre-session gate, admin-only) and
 * a UserLogin + ClientAreaPage post-login SESSION gate for clients,
 * because WHMCS's documented Authentication Hooks
 * (ClientLoginShare/UserLogin/UserLogout/AuthAdmin) expose no
 * pre-session client-area login hook.
 *
 * That conclusion about the Hooks API was correct, but incomplete: WHMCS
 * separately ships a "Security Module" type (modules/security/, used by
 * WHMCS's own built-in Time-Based Tokens/Duo/YubiKey methods) that DOES
 * intervene between password validation and completed authentication,
 * for both admin and client logins, before either kind of session is
 * considered fully authenticated. That is the correct, native
 * integration point for a genuine second authentication factor, and
 * Email 2FA is now implemented there instead:
 *
 *     modules/security/dct_email_2fa/dct_email_2fa.php
 *
 * As a direct result, the enforcement logic that used to live in THIS
 * file — the UserLogin/ClientAreaPage session-gate hooks, the AuthAdmin
 * hard-gate hook, and the standalone email2fa-admin-verify.php page —
 * has been REMOVED here (2.6.1). Do not re-add authentication
 * enforcement to this file; it belongs in the security module above.
 * See SECURITY-AUDIT-PHASE-4.md's "Phase 7 / 2.6.1" section for the
 * full investigation, including the important caveat that the
 * modules/security/ interface is not published in WHMCS's official
 * developer documentation and was reconstructed from a working
 * reference implementation, not traced from WHMCS core source directly.
 *
 * What remains in THIS file is everything that is genuinely independent
 * of which enforcement mechanism is used: account-lifecycle bookkeeping
 * (email/password change handling), admin-facing visibility, and
 * scheduled cleanup — all of it operating on the SAME
 * Email2faService/tables the security module also uses.
 */

// ---------------------------------------------------------------------
// Account lifecycle — Step 47/49
// ---------------------------------------------------------------------

/**
 * Step 47: an email address change must not let an old verified address
 * remain implicitly trusted. Re-pends activation (requires
 * re-verification) and revokes trusted-IP bypasses for that user.
 */
add_hook("UserEdit", 1, function ($vars) {
    try {
        $userId = (int) ($vars["user_id"] ?? 0);
        $newEmail = (string) ($vars["email"] ?? "");
        $oldEmail = (string) ($vars["olddata"]["email"] ?? "");
        if($userId > 0 && $newEmail !== "" && $newEmail !== $oldEmail) {
            Email2faService::handleEmailChanged($userId, Email2faService::TYPE_CLIENT, $newEmail);
        }
    } catch (\Throwable $e) {
    }
});

/** Step 49: a password change invalidates any pending OTP challenge. */
add_hook("UserChangePassword", 1, function ($vars) {
    try {
        $userId = (int) ($vars["userid"] ?? 0);
        if($userId > 0) {
            Email2faService::handlePasswordChanged($userId, Email2faService::TYPE_CLIENT);
        }
    } catch (\Throwable $e) {
    }
});

// ---------------------------------------------------------------------
// Admin visibility — Step 8: client profile tab
// ---------------------------------------------------------------------

/**
 * Adds a read-only "Two-Factor Authentication" field group to the admin
 * client profile's user tab — via WHMCS's own documented
 * AdminClientProfileTabFields extension point, never by modifying core
 * templates. Never displays an OTP, hash, secret, or challenge token —
 * only status/configuration metadata (Step 8). Independent of which
 * enforcement mechanism is active — reads only Email2faService's own
 * tracking table, which the security module (dct_email_2fa) maintains
 * exactly as this file's account-lifecycle hooks above expect.
 *
 * 2026-08-27 — production bug fix ("Administrator Manual Bypass
 * auto-creation on login" investigation): `$vars["userid"]` on THIS
 * hook is WHMCS's own Client ID (`tblclients.id` — the Client Profile
 * page is one page per Client, and every other field this hook could
 * add, e.g. firstname/lastname/address, is a `tblclients` column, not
 * a `tblusers` one). Every 2FA enrollment, bypass, and login-time
 * challenge in this codebase, however, is keyed by the actual
 * authenticated WHMCS User (`tblusers.id` — resolved at login
 * exclusively from `$params["user_info"]["id"]`, per every Security
 * Module's own docblock in this project). A Client can have MULTIPLE
 * Users (an owner plus any number of sub-accounts, via the
 * `tblusers_clients` junction table) whose `tblusers.id` values are
 * never equal to the Client's own `tblclients.id` and never equal to
 * each other. This panel used to pass the raw Client ID straight into
 * `Email2faService::getConfig()`/`findActiveAdminBypass()` as if it
 * were a User ID — for any client with a sub-account (or simply
 * because `tblclients.id` and `tblusers.id` are different sequences),
 * that lookup was checking the WRONG identity entirely: it could show
 * "None" for a bypass that is genuinely active for the real logged-in
 * User, or (far less likely, but not impossible if the two sequences
 * happened to collide) show a bypass that has nothing to do with any
 * User under this client. Worse, an admin who trusts this panel's
 * numbers when manually filling in the "Administrator Manual Bypass"
 * form below could end up typing the Client ID into that WHMCS User ID
 * field — creating a bypass keyed to an identity nothing at login time
 * will ever match.
 *
 * FIX: resolve the client's REAL WHMCS User ID(s) first, via the same
 * `tblusers_clients` junction table already trusted elsewhere in this
 * codebase (`TwoFactorController::resolveUserIdsForClient()` — reused
 * here rather than duplicated), and report each real User's own status
 * and bypass — never the Client ID's. No database schema change: this
 * table/relationship already exists and is already used by the admin
 * Users-tab overlay for the identical purpose.
 */
add_hook("AdminClientProfileTabFields", 1, function ($vars) {
    try {
        $clientId = (int) ($vars["userid"] ?? $vars["user_id"] ?? 0);
        if($clientId <= 0) {
            return [];
        }
        $userIds = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\TwoFactorController")
            ? \WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController::resolveUserIdsForClient($clientId)
            : [];
        if(!$userIds) {
            // No real WHMCS User row is linked to this Client (e.g. an
            // older install without tblusers_clients populated yet, or
            // the junction table/columns genuinely don't exist here).
            // Deliberately does NOT fall back to treating $clientId as
            // a User ID — that fallback is exactly the bug being fixed.
            return [
                "Two-Factor Authentication (Method)" => "Email OTP",
                "Two-Factor Authentication (Status)" => "No linked WHMCS User account found for this client — nothing to report.",
            ];
        }
        $lines = [];
        foreach ($userIds as $realUserId) {
            $config = Email2faService::getConfig($realUserId, Email2faService::TYPE_CLIENT);
            $statusLabel = "Not enabled";
            if($config) {
                $statusLabel = $config->status === "active" ? "Enabled" : ($config->status === "pending" ? "Pending verification" : "Disabled");
            }
            $adminBypass = Email2faService::findActiveAdminBypass($realUserId, Email2faService::TYPE_CLIENT);
            $lines[] = "User #" . $realUserId . ": " . $statusLabel . " — Admin Bypass: " . ($adminBypass ? ("Active until " . $adminBypass->expires_at) : "None");
        }
        return [
            "Two-Factor Authentication (Method)" => "Email OTP",
            "Two-Factor Authentication (Status, by WHMCS User)" => implode("; ", $lines),
            "Two-Factor Authentication (Enforcement)" => "Native WHMCS Security Module (modules/security/dct_email_2fa) — see Setup > Security > Two-Factor Authentication.",
        ];
    } catch (\Throwable $e) {
        return [];
    }
});

// ---------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------

add_hook("DailyCronJob", 1, function ($vars) {
    try {
        $settings = security_pack_settings();
        Email2faService::purgeExpired(
            (int) ($settings["email_2fa_challenge_retention_days"] ?? 7),
            (int) ($settings["email_2fa_bypass_retention_days"] ?? 30)
        );
    } catch (\Throwable $e) {
    }
});
