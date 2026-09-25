<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — single-use recovery codes.
 *
 * 10 codes, cryptographically random (random_int()), stored as a
 * secure hash (never plaintext, never logged). Uses password_hash()/
 * password_verify() (bcrypt) — the same primitive PHP itself
 * recommends for credential-shaped secrets — rather than a homegrown
 * hashing scheme.
 *
 * A native WHMCS TOTP login has no equivalent to this at all: lose your
 * device with native "Time Based Tokens" and an administrator must
 * manually disable 2FA for you. Recovery codes are one of the concrete
 * improvements this rebuild makes over the native module it replaces.
 */
class RecoveryCodes
{
    public const CODE_COUNT = 10;

    /** Generate a fresh set of plaintext codes (format: 4 blocks of 4 alphanumeric chars). Pure — no DB. */
    public static function generatePlaintextCodes(int $count = self::CODE_COUNT): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = self::generateOne();
        }
        return $codes;
    }

    private static function generateOne(): string
    {
        $alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I ambiguity
        $groups = [];
        for ($g = 0; $g < 4; $g++) {
            $chars = "";
            for ($c = 0; $c < 4; $c++) {
                $chars .= $alphabet[random_int(0, strlen($alphabet) - 1)];
            }
            $groups[] = $chars;
        }
        return implode("-", $groups);
    }

    public static function hashCode(string $code): string
    {
        return password_hash(self::normalize($code), PASSWORD_DEFAULT);
    }

    public static function verifyCode(string $candidate, string $hash): bool
    {
        if ($hash === "") {
            return false;
        }
        return password_verify(self::normalize($candidate), $hash);
    }

    private static function normalize(string $code): string
    {
        return strtoupper(trim($code));
    }

    // --- DB-backed orchestration ---------------------------------------

    /** Replace this user's recovery code set. Returns the new plaintext codes (display once, then discard). */
    public static function regenerate(int $userId, string $userType): array
    {
        Schema::ensure();
        $codes = self::generatePlaintextCodes();
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::RECOVERY_CODES_TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->delete();
            $rows = [];
            foreach ($codes as $code) {
                $rows[] = ["user_id" => $userId, "user_type" => $userType, "code_hash" => self::hashCode($code), "used_at" => null, "created_at" => $now];
            }
            \Illuminate\Database\Capsule\Manager::table(Schema::RECOVERY_CODES_TABLE)->insert($rows);
        } catch (\Throwable $e) {
            return [];
        }
        EventLog::record("Recovery codes (re)generated for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
        return $codes;
    }

    public static function remainingCount(int $userId, string $userType): int
    {
        Schema::ensure();
        try {
            return (int) \Illuminate\Database\Capsule\Manager::table(Schema::RECOVERY_CODES_TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("used_at")->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Attempt to consume a recovery code: authenticates only once,
     * consumed immediately on success, rate-limited. Never reveals which
     * remaining codes are valid — every non-match returns the same
     * generic false.
     */
    public static function attemptConsume(int $userId, string $userType, string $candidate, string $ip): bool
    {
        Schema::ensure();
        $rlKey = "recovery:" . $userType . ":" . $userId . ":" . $ip;
        if (!RateLimiter::hit($rlKey, 10, 300)) {
            return false;
        }
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(Schema::RECOVERY_CODES_TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("used_at")->get();
        } catch (\Throwable $e) {
            return false;
        }
        foreach ($rows as $row) {
            if (self::verifyCode($candidate, (string) $row->code_hash)) {
                try {
                    $updated = \Illuminate\Database\Capsule\Manager::table(Schema::RECOVERY_CODES_TABLE)
                        ->where("id", $row->id)->whereNull("used_at")
                        ->update(["used_at" => date("Y-m-d H:i:s")]);
                } catch (\Throwable $e) {
                    $updated = 0;
                }
                if ($updated) {
                    EventLog::record("A recovery code was used to sign in as " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
                    return true;
                }
            }
        }
        return false;
    }
}
