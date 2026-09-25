<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Read-mostly bridge onto dct_totp_native's own secrets table
 * (modules/security/dct_totp_native/lib/Schema.php::SECRETS_TABLE ==
 * "mod_dct_totp_native_secrets").
 *
 * WHY THIS EXISTS (2026-08-27): this addon's own TOTP tracking
 * (TotpEnrollmentService, table dctlab_security_pack_totp2fa) was built
 * against modules/security/dct_totp_2fa. Investigating a live "the secret
 * changes on every wrong code" TOTP bug report revealed the site is
 * actually running a SEPARATE, standalone Security Module,
 * modules/security/dct_totp_native, with its own completely independent
 * table — confirmed live: dct_totp_2fa's own table has zero real
 * enrollments on this install (matching the "0 clients 0 administrators"
 * the admin Security Overview card was showing for "Time-Based Token"),
 * while the client actually attempting to enroll (the one from the
 * screenshots) has real, in-progress rows in dct_totp_native's table
 * instead — invisible to this addon's dashboard, reporting, mutual-
 * exclusion, and native-second-factor-sync logic until this fix.
 *
 * This class reads that table directly via Capsule (the exact same
 * technique this addon's own TotpEnrollmentService already uses for its
 * own table) — it does NOT modify any dct_totp_native file, and does NOT
 * duplicate its business logic: secret generation, TOTP verification, and
 * rate limiting all stay exclusively inside that module. The one write
 * path (disable()) mirrors — does not call, since a Security Module's
 * classes are not meant to be cross-included by an addon — exactly what
 * dct_totp_native\Enrollment::disable() itself does to this same table
 * (status => "disabled", enrollment/secret preserved), so that this
 * addon's own "disable 2FA for this user" admin action
 * (TwoFactorAuthenticationService::disableAllMethods()) can actually turn
 * off a native-tracked enrollment, not just a legacy dct_totp_2fa one.
 * This does not write dct_totp_native's own EventLog table — that
 * module's own event log and this addon's security_pack_record_event()
 * pipeline remain separate audit trails, exactly as they already are for
 * every other cross-module boundary in this codebase.
 *
 * Every method fails soft (false/null/no-op) if the table does not exist
 * yet — e.g. a fresh install that has never activated dct_totp_native —
 * so callers never need their own existence checks beyond tableExists().
 */
final class NativeTotpStatusBridge
{
    private const TABLE = "mod_dct_totp_native_secrets";

    public static function tableExists(): bool
    {
        try {
            return \Illuminate\Database\Capsule\Manager::schema()->hasTable(self::TABLE);
        } catch (\Throwable $e) {
            return false;
        }
    }

    public static function getConfig(int $userId, string $userType)
    {
        if(!self::tableExists()) {
            return null;
        }
        try {
            return \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->first();
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function isActive(int $userId, string $userType): bool
    {
        $row = self::getConfig($userId, $userType);
        return $row !== null && $row->status === "active";
    }

    public static function isPending(int $userId, string $userType): bool
    {
        $row = self::getConfig($userId, $userType);
        return $row !== null && $row->status === "pending";
    }

    /**
     * Mirrors dct_totp_native\Enrollment::disable() against the same
     * table: status flips to "disabled", the encrypted secret and every
     * other column is left untouched (re-enrollment starts clean via that
     * module's own beginEnrollment(), which already handles a prior
     * disabled row correctly). No-op (never throws) if there is no row or
     * the table does not exist.
     */
    public static function disable(int $userId, string $userType, string $actor = "user"): void
    {
        if(!self::tableExists()) {
            return;
        }
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
    }
}
