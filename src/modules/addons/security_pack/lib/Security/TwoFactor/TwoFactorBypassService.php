<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — the ONE authoritative 2FA bypass store.
 *
 * Per the unified 2FA architecture (Section 21/22/23): "Do not create
 * separate bypass systems for each method." This class does NOT create a
 * new table. It reuses the EXISTING `dctlab_security_pack_email2fa_bypasses`
 * table (already structurally method-agnostic: user_id/user_type/ip/
 * scope/expires_at/created_by/reason — no email-specific columns) — this
 * release only adds one additive, nullable `method` column so a bypass
 * row can record which method's verification produced it, purely for
 * display/audit. A bypass is NOT scoped by method: per Section 21/22, a
 * granted bypass applies "regardless of the configured method
 * (Email/WhatsApp/TOTP)" — a User+IP or admin-manual bypass silences the
 * 2FA challenge no matter which method they have enrolled.
 *
 * Email2faService's own bypass methods (findActiveBypass,
 * findActiveAdminBypass, grantSameIpBypass, createAdminBypass,
 * revokeBypass) are UNCHANGED — they keep operating directly against the
 * same table with their existing "email_2fa.bypass.*" event names, since
 * Security Pack's Analytics/Anomaly/Email2fa-overview screens already
 * key off those exact event type strings (do not rename them). This
 * class is for the NEW unified surfaces (WhatsApp, TOTP, and the unified
 * admin bypass screen) — same underlying storage, new
 * "2fa.bypass.*" event names per Section 24's event list, and an
 * optional $method tag for the audit trail.
 */
class TwoFactorBypassService
{
    private const TABLE = "dctlab_security_pack_email2fa_bypasses";

    /**
     * 2026-08-27 — third pass on the "Administrator Manual Bypass still
     * not working" incident: after the ensureMethodColumn() self-heal
     * (above) was deployed, the admin reported the EXACT SAME symptom
     * again — no row in the table, no error shown. Rather than guess a
     * fourth cause, createAdminBypass() now (a) records the real
     * exception message here so the admin UI can surface it instead of a
     * generic string, and (b) unconditionally writes to WHMCS's own
     * Activity Log — via the bare logActivity() call, not the
     * security_pack_record_event() pipeline (which itself depends on
     * this addon's own tables/settings being fully healthy, the exact
     * kind of assumption that has been wrong more than once already in
     * this incident) — on BOTH the attempt and its outcome, so there is
     * hard evidence in a place the admin can check even if the on-page
     * banner is missed or doesn't render for some other reason.
     */
    private static ?string $lastError = null;

    public static function getLastError(): ?string
    {
        return self::$lastError;
    }

    /**
     * 2026-08-27 — production bug fix ("Administrator Manual Bypass
     * still not working", second pass): the `method` column this class
     * writes to (createAdminBypass()/grantSameIpBypass()) is only ever
     * added by security_pack_ensure_tables(), which WHMCS only calls from
     * _activate() (fresh installs) or _upgrade() — and _upgrade() only
     * fires when WHMCS itself detects security_pack_config()'s "version"
     * has increased since the module's last recorded activation. This
     * project's whole delivery model is manual FTP upload of updated
     * files (confirmed throughout this incident's history) — a file
     * replacement alone does NOT trigger WHMCS's upgrade detection, so
     * any schema change bundled in a delivered fix could sit on disk,
     * fully coded, while the live database never actually gains the
     * column it needs. When that happens here, the INSERT below throws
     * an "Unknown column" error — silently caught by this method's own
     * try/catch — while the admin UI (TwoFactorController::bypass())
     * still showed "Bypass created." unconditionally, regardless of
     * whether anything was actually written. That combination (silent
     * DB failure + an unconditional success message) is exactly what
     * made this bug invisible until it was explicitly reported and
     * investigated.
     *
     * Fix, two parts:
     *  1. THIS method — self-heals the `method` column immediately
     *     before every write this class performs, via the identical
     *     hasColumn()-guarded migration security_pack_ensure_tables()
     *     already contains, so a write here can never fail merely
     *     because WHMCS's own upgrade hook hasn't fired yet. Idempotent
     *     and cheap (a single hasColumn() check) — safe to call before
     *     every write.
     *  2. createAdminBypass() below now returns bool (true only when the
     *     row actually persisted) instead of void, and
     *     TwoFactorController::bypass() now reports the REAL outcome
     *     instead of an unconditional "Bypass created." — see that
     *     method's own updated docblock.
     */
    private static function ensureMethodColumn(): void
    {
        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();
            if(!$schema->hasTable(self::TABLE)) {
                // Nothing to self-heal onto — the table itself is
                // missing (a much larger problem than one column, and
                // one security_pack_ensure_tables() must fix on its own
                // next real activation/upgrade). The insert below will
                // fail and be caught exactly as before; this is not this
                // method's job to fix.
                return;
            }
            if(!$schema->hasColumn(self::TABLE, "method")) {
                $schema->table(self::TABLE, function ($table) {
                    $table->string("method", 20)->nullable()->after("scope");
                });
            }
        } catch (\Throwable $e) {
            // Fail-soft: if this self-heal itself fails (e.g. a
            // permissions issue), the write below still runs and fails
            // with its own already-existing try/catch — no worse than
            // before this fix existed.
        }
    }

    /** Any active bypass (any method) for this exact user+ip pair, or the active admin-manual bypass for this user. */
    public static function findActive(int $userId, string $userType, string $ip)
    {
        $ipBypass = self::findActiveSameIp($userId, $userType, $ip);
        if($ipBypass) {
            return $ipBypass;
        }
        return self::findActiveAdminBypass($userId, $userType);
    }

    public static function findActiveSameIp(int $userId, string $userType, string $ip)
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("ip", $ip)
                ->whereNull("revoked_at")->orderBy("expires_at", "DESC")->get();
        } catch (\Throwable $e) {
            return null;
        }
        $now = time();
        foreach ($rows as $row) {
            if(OtpEngine::isBypassActive($row->revoked_at, strtotime((string) $row->expires_at) ?: 0, $now)) {
                return $row;
            }
        }
        return null;
    }

    public static function findActiveAdminBypass(int $userId, string $userType)
    {
        try {
            $row = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("scope", "admin_manual")
                ->whereNull("revoked_at")->orderBy("expires_at", "DESC")->first();
        } catch (\Throwable $e) {
            if(function_exists("security_pack_log_activity")) {
                security_pack_log_activity("[security_pack] DIAGNOSTIC: findActiveAdminBypass() query threw for user_id=" . $userId . " user_type=" . $userType . ": " . $e->getMessage());
            } elseif(function_exists("logActivity")) {
                try {
                    logActivity("[security_pack] DIAGNOSTIC: findActiveAdminBypass() query threw for user_id=" . $userId . " user_type=" . $userType . ": " . $e->getMessage());
                } catch (\Throwable $e2) {
                }
            }
            return null;
        }
        // DIAGNOSTIC (2026-08-27, fourth pass — "Administrator Manual
        // Bypass" incident): creation was confirmed working via the
        // Activity Log, but a subsequent lookup for the SAME user_id +
        // user_type found nothing, both from the admin panel's own
        // listing AND from a live login attempt's bypass check. Rather
        // than guess a fifth cause, this logs the RAW, unfiltered set of
        // every row in this table for this exact user_id + user_type
        // (any scope, any revoked/expired status) so the next lookup
        // tells us definitively whether: (a) no row exists at all for
        // this identity (the insert didn't actually persist, despite
        // logging "created" — e.g. a transaction that never committed),
        // (b) a row exists but with different scope/revoked_at/expires_at
        // values than expected (a WHERE-clause or isBypassActive() bug),
        // or (c) the row this method's own filtered query already found
        // is simply not being reached due to a logic error further down.
        // Kept intentionally verbose/diagnostic-only — safe to remove
        // once this incident is resolved.
        if(function_exists("logActivity")) {
            try {
                $allRowsForIdentity = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                    ->where("user_id", $userId)->where("user_type", $userType)->get();
                $dump = [];
                foreach ($allRowsForIdentity as $r) {
                    $dump[] = "id=" . $r->id . " scope=" . $r->scope . " revoked_at=" . ($r->revoked_at ?? "NULL") . " expires_at=" . $r->expires_at;
                }
                $diagMsg = "[security_pack] DIAGNOSTIC: findActiveAdminBypass(user_id=" . $userId . ", user_type=" . $userType . ") — filtered query found " . ($row ? "1 row (id=" . $row->id . ")" : "0 rows") . "; ALL rows for this identity in the bypass table (any scope/status): " . (count($dump) ? implode(" | ", $dump) : "NONE AT ALL");
                if(function_exists("security_pack_log_activity")) {
                    security_pack_log_activity($diagMsg);
                } else {
                    logActivity($diagMsg);
                }
            } catch (\Throwable $e) {
            }
        }
        if(!$row) {
            return null;
        }
        return OtpEngine::isBypassActive($row->revoked_at, strtotime((string) $row->expires_at) ?: 0, time()) ? $row : null;
    }

    /**
     * Create or refresh a same-IP bypass after a successful verification
     * (Section 22). $method is informational only ("email"|"whatsapp"|"totp"|"recovery_code").
     */
    public static function grantSameIpBypass(int $userId, string $userType, string $ip, int $days, string $method, string $eventPrefix = "2fa"): void
    {
        self::ensureMethodColumn();
        $days = OtpEngine::clampBypassDays($days);
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + ($days * 86400));
        try {
            $existing = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("ip", $ip)
                ->where("scope", "same_ip")->whereNull("revoked_at")->first();
            if($existing) {
                \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $existing->id)
                    ->update(["expires_at" => $expires, "updated_at" => $now, "method" => $method]);
                $eventType = $eventPrefix . ".bypass.refreshed";
            } else {
                \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert([
                    "user_id" => $userId, "user_type" => $userType, "ip" => $ip, "scope" => "same_ip",
                    "expires_at" => $expires, "created_by" => "system", "method" => $method,
                    "created_at" => $now, "updated_at" => $now,
                ]);
                $eventType = $eventPrefix . ".bypass.created";
            }
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event($eventType, "2FA same-IP bypass " . (str_ends_with($eventType, "refreshed") ? "refreshed" : "created") . " for " . $days . " day(s) (" . $method . ").", ["user_id" => $userId, "user_type" => $userType, "method" => $method]);
        }
    }

    /**
     * Explicit administrator-created manual bypass, applies regardless of
     * method (Section 21).
     *
     * 2026-08-27 — now returns bool (previously void): true only when the
     * row actually persisted, false on any DB error (self-healed via
     * ensureMethodColumn() first, so a missing `method` column — the
     * concrete failure mode confirmed in this incident — no longer
     * causes one). Callers (TwoFactorController::bypass()) must check
     * this before reporting success to the admin — see this class's own
     * docblock above for the full incident this fixes.
     */
    public static function createAdminBypass(int $userId, string $userType, int $days, string $actorLabel, string $reason = "", string $method = "manual", string $eventPrefix = "2fa"): bool
    {
        self::$lastError = null;
        if(function_exists("security_pack_log_activity")) {
            security_pack_log_activity("[security_pack] Administrator Manual Bypass attempted for " . $userType . " #" . $userId . " (" . $days . " day(s), by " . $actorLabel . ").", $userType === "client" ? $userId : 0);
        } elseif(function_exists("logActivity")) {
            try {
                logActivity("[security_pack] Administrator Manual Bypass attempted for " . $userType . " #" . $userId . " (" . $days . " day(s), by " . $actorLabel . ").", $userType === "client" ? $userId : 0);
            } catch (\Throwable $e) {
            }
        }
        self::ensureMethodColumn();
        $days = OtpEngine::clampBypassDays($days);
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + ($days * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert([
                "user_id" => $userId, "user_type" => $userType, "ip" => "", "scope" => "admin_manual",
                "expires_at" => $expires, "created_by" => $actorLabel, "reason" => mb_substr($reason, 0, 255),
                "method" => $method, "created_at" => $now, "updated_at" => $now,
            ]);
        } catch (\Throwable $e) {
            self::$lastError = $e->getMessage();
            if(function_exists("security_pack_log_activity")) {
                security_pack_log_activity("[security_pack] Administrator Manual Bypass creation FAILED for " . $userType . " #" . $userId . ": " . $e->getMessage(), $userType === "client" ? $userId : 0);
            } elseif(function_exists("logActivity")) {
                try {
                    logActivity("[security_pack] Administrator Manual Bypass creation FAILED for " . $userType . " #" . $userId . ": " . $e->getMessage(), $userType === "client" ? $userId : 0);
                } catch (\Throwable $e2) {
                }
            }
            return false;
        }
        if(function_exists("security_pack_log_activity")) {
            security_pack_log_activity("[security_pack] Administrator Manual Bypass created for " . $userType . " #" . $userId . " (" . $days . " day(s)).", $userType === "client" ? $userId : 0);
        } elseif(function_exists("logActivity")) {
            try {
                logActivity("[security_pack] Administrator Manual Bypass created for " . $userType . " #" . $userId . " (" . $days . " day(s)).", $userType === "client" ? $userId : 0);
            } catch (\Throwable $e) {
            }
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event($eventPrefix . ".bypass.created", "Administrator bypass created for " . $days . " day(s).", ["user_id" => $userId, "user_type" => $userType, "actor" => $actorLabel, "reason" => mb_substr($reason, 0, 255)]);
        }
        return true;
    }

    /**
     * 2026-08-25 — admin "Disable Two-Factor Authentication For This
     * User" must also revoke any active bypass (same-IP or
     * admin-manual, any scope) for that identity — otherwise a bypass
     * granted while 2FA was active keeps silently skipping the
     * challenge for whatever method the user re-enrolls in next,
     * exactly the same "protection removed" gap TrustedBrowserService::
     * revokeAll() was already added to close for trusted browsers at
     * the same call site (see TwoFactorAuthenticationService::
     * disableAllMethods()). Mirrors that method's shape: revokes every
     * currently-non-revoked row (regardless of scope or whether it has
     * already expired) and returns the count actually revoked, emitting
     * one summary event rather than one per row.
     */
    public static function revokeAllForUser(int $userId, string $userType, string $actorLabel, string $eventPrefix = "2fa"): int
    {
        $now = date("Y-m-d H:i:s");
        if(function_exists("logActivity")) {
            try {
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 6);
                $chain = [];
                foreach ($trace as $frame) {
                    $chain[] = (isset($frame["class"]) ? $frame["class"] . "::" : "") . ($frame["function"] ?? "?");
                }
                $diagMsg = "[security_pack] DIAGNOSTIC v5: revokeAllForUser(user_id=" . $userId . ", user_type=" . $userType . ", actor=\"" . $actorLabel . "\") called. Caller chain: " . implode(" <- ", $chain);
                if(function_exists("security_pack_log_activity")) {
                    security_pack_log_activity($diagMsg, $userType === "client" ? $userId : 0);
                } else {
                    logActivity($diagMsg, $userType === "client" ? $userId : 0);
                }
            } catch (\Throwable $e) {
            }
        }
        try {
            $ids = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("revoked_at")->pluck("id");
            if(!$ids || !count($ids)) {
                return 0;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("revoked_at")
                ->update(["revoked_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
            return 0;
        }
        $count = count($ids);
        if($count > 0 && function_exists("security_pack_record_event")) {
            security_pack_record_event($eventPrefix . ".bypass.revoked", "All (" . $count . ") 2FA bypass(es) revoked for " . $userType . " #" . $userId . ".", ["user_id" => $userId, "user_type" => $userType, "count" => $count, "actor" => $actorLabel]);
        }
        return $count;
    }

    public static function revokeBypass(int $bypassId, string $actorLabel, string $eventPrefix = "2fa"): void
    {
        $now = date("Y-m-d H:i:s");
        if(function_exists("logActivity")) {
            try {
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 6);
                $chain = [];
                foreach ($trace as $frame) {
                    $chain[] = (isset($frame["class"]) ? $frame["class"] . "::" : "") . ($frame["function"] ?? "?");
                }
                $diagMsg = "[security_pack] DIAGNOSTIC v5: revokeBypass(bypass_id=" . $bypassId . ", actor=\"" . $actorLabel . "\") called. Caller chain: " . implode(" <- ", $chain);
                if(function_exists("security_pack_log_activity")) {
                    security_pack_log_activity($diagMsg);
                } else {
                    logActivity($diagMsg);
                }
            } catch (\Throwable $e) {
            }
        }
        try {
            $row = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $bypassId)->first();
            if(!$row || $row->revoked_at) {
                return;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $bypassId)->update(["revoked_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event($eventPrefix . ".bypass.revoked", "2FA bypass revoked.", ["bypass_id" => $bypassId, "actor" => $actorLabel]);
        }
    }

    /** All currently-active bypasses (any method, any scope), for the unified admin bypass screen. */
    public static function listActive(int $limit = 100): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->whereNull("revoked_at")->where("expires_at", ">=", date("Y-m-d H:i:s"))
                ->orderBy("expires_at", "ASC")->limit($limit)->get();
            return $rows ? $rows->toArray() : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function purgeExpired(int $bypassRetentionDays = 30): void
    {
        $cutoff = date("Y-m-d H:i:s", time() - ($bypassRetentionDays * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("expires_at", "<", $cutoff)->delete();
        } catch (\Throwable $e) {
        }
    }
}
