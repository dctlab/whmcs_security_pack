<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — optional "trusted device" (same-account + same-IP)
 * bypass. Off by default (see dct_totp_native_config()'s BypassSameIp
 * field); native "Time Based Tokens" has no equivalent at all — this is
 * one of the concrete improvements this rebuild makes, purely opt-in so
 * an administrator who wants every single login challenged can leave it
 * off.
 *
 * Deliberately narrow: scoped to one exact IP string + one account, with
 * an administrator-configured expiry (1-90 days). This is NOT a
 * "remember this browser forever" cookie mechanism — no cookie is set at
 * all; the check is purely server-side against the IP WHMCS resolves for
 * the request.
 */
class Bypass
{
    private const TABLE = "mod_dct_totp_native_bypass";

    private static bool $ensured = false;

    private static function ensureTable(): void
    {
        if (self::$ensured) {
            return;
        }
        self::$ensured = true;
        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();
            if (!$schema->hasTable(self::TABLE)) {
                $schema->create(self::TABLE, function ($table) {
                    /** @var \Illuminate\Database\Schema\Blueprint $table */
                    $table->increments("id");
                    $table->unsignedInteger("user_id");
                    $table->string("user_type", 20);
                    $table->string("ip_address", 64);
                    $table->timestamp("expires_at");
                    $table->timestamps();
                    $table->index(["user_id", "user_type", "ip_address"]);
                });
            }
        } catch (\Throwable $e) {
        }
    }

    public static function isActive(int $userId, string $userType, string $ip): bool
    {
        if ($ip === "") {
            return false;
        }
        self::ensureTable();
        try {
            return \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("ip_address", $ip)
                ->where("expires_at", ">", date("Y-m-d H:i:s"))
                ->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    public static function grant(int $userId, string $userType, string $ip, int $days): void
    {
        if ($ip === "") {
            return;
        }
        self::ensureTable();
        $days = max(1, min(90, $days));
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + ($days * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->updateOrInsert(
                ["user_id" => $userId, "user_type" => $userType, "ip_address" => $ip],
                ["expires_at" => $expires, "updated_at" => $now, "created_at" => $now]
            );
        } catch (\Throwable $e) {
        }
    }

    /** Best-effort cleanup of expired grants — call periodically from a cron/scheduled task if desired. */
    public static function prune(): void
    {
        self::ensureTable();
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("expires_at", "<", date("Y-m-d H:i:s"))
                ->delete();
        } catch (\Throwable $e) {
        }
    }
}
