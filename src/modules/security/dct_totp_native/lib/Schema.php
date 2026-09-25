<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — idempotent, lazy schema management.
 *
 * A WHMCS Security Module (modules/security/*) has no install-time
 * `_activate()` lifecycle hook the way an addon module does — the only
 * reliable moment to create this module's tables is "the first time any
 * of its code actually runs" (enrollment start, login challenge, etc.).
 * `ensure()` is therefore called at the top of every DB-touching method
 * in RateLimiter/RecoveryCodes/Enrollment; each call is a cheap
 * `hasTable()` check once the tables already exist, and the actual
 * `create()` calls are themselves guarded by `hasTable()` so this is
 * safe to call from concurrent requests and safe to call thousands of
 * times over the module's lifetime.
 *
 * Table names use the `mod_` prefix (this module's own tables only —
 * never a WHMCS core `tbl*` table).
 */
class Schema
{
    public const SECRETS_TABLE = "mod_dct_totp_native_secrets";
    public const RECOVERY_CODES_TABLE = "mod_dct_totp_native_recovery_codes";
    public const RATE_LIMITS_TABLE = "mod_dct_totp_native_rate_limits";

    private static bool $ensured = false;

    public static function ensure(): void
    {
        if (self::$ensured) {
            return;
        }
        self::$ensured = true;

        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();

            if (!$schema->hasTable(self::SECRETS_TABLE)) {
                $schema->create(self::SECRETS_TABLE, function ($table) {
                    /** @var \Illuminate\Database\Schema\Blueprint $table */
                    $table->increments("id");
                    $table->unsignedInteger("user_id");
                    $table->string("user_type", 20); // "admin" | "client"
                    $table->text("secret_encrypted");
                    $table->string("status", 20)->default("pending"); // pending | active | disabled
                    $table->unsignedBigInteger("last_used_step")->nullable();
                    $table->timestamp("activated_at")->nullable();
                    $table->timestamp("last_verified_at")->nullable();
                    $table->timestamp("deactivated_at")->nullable();
                    $table->timestamps();
                    $table->unique(["user_id", "user_type"]);
                });
            }

            if (!$schema->hasTable(self::RECOVERY_CODES_TABLE)) {
                $schema->create(self::RECOVERY_CODES_TABLE, function ($table) {
                    /** @var \Illuminate\Database\Schema\Blueprint $table */
                    $table->increments("id");
                    $table->unsignedInteger("user_id");
                    $table->string("user_type", 20);
                    $table->string("code_hash", 255);
                    $table->timestamp("used_at")->nullable();
                    $table->timestamp("created_at")->nullable();
                    $table->index(["user_id", "user_type"]);
                });
            }

            if (!$schema->hasTable(self::RATE_LIMITS_TABLE)) {
                $schema->create(self::RATE_LIMITS_TABLE, function ($table) {
                    /** @var \Illuminate\Database\Schema\Blueprint $table */
                    $table->increments("id");
                    $table->string("rate_key", 191)->unique();
                    $table->unsignedInteger("hits")->default(0);
                    $table->timestamp("window_started_at")->nullable();
                    $table->timestamp("updated_at")->nullable();
                });
            }
        } catch (\Throwable $e) {
            // If schema creation fails (e.g. a permissions issue), every
            // caller's own try/catch around its Capsule queries will
            // still fail closed (deny/inactive) rather than throw an
            // uncaught exception into WHMCS's login flow.
        }
    }
}
