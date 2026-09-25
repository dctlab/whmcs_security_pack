<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — Recovery Codes (Section 16/17).
 *
 * 10 single-use codes, cryptographically random, stored as a secure hash
 * (never plaintext), never logged. Reuses the exact same hashing
 * primitive Email2faService/OtpEngine already use for OTPs
 * (password_hash()/password_verify(), bcrypt) rather than inventing a
 * second crypto approach.
 */
class RecoveryCodeService
{
    public const CODE_COUNT = 10;
    private const TABLE = "dctlab_security_pack_2fa_recovery_codes";

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
        if($hash === "") {
            return false;
        }
        return password_verify(self::normalize($candidate), $hash);
    }

    private static function normalize(string $code): string
    {
        return strtoupper(trim($code));
    }

    // --- DB-backed orchestration ---------------------------------------

    /** Replace this user's recovery code set. Returns the new plaintext codes (display once, per Section 16). */
    public static function regenerate(int $userId, string $userType): array
    {
        $codes = self::generatePlaintextCodes();
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->delete();
            $rows = [];
            foreach ($codes as $code) {
                $rows[] = ["user_id" => $userId, "user_type" => $userType, "code_hash" => self::hashCode($code), "used_at" => null, "created_at" => $now];
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert($rows);
        } catch (\Throwable $e) {
            return [];
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.recovery_code.generated", "2FA recovery codes (re)generated.", ["user_id" => $userId, "user_type" => $userType, "count" => count($codes)]);
        }
        return $codes;
    }

    public static function remainingCount(int $userId, string $userType): int
    {
        try {
            return (int) \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("used_at")->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Attempt to consume a recovery code (Section 17): authenticates
     * only once, consumed immediately, records `2fa.recovery_code.used`.
     * Never reveals which remaining codes are valid — every non-match
     * returns the same generic false.
     */
    public static function attemptConsume(int $userId, string $userType, string $candidate): bool
    {
        $rlKey = "2fa_recovery:" . $userType . ":" . $userId;
        if(!\WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::hit($rlKey, 10, 300)) {
            return false;
        }
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("used_at")->get();
        } catch (\Throwable $e) {
            return false;
        }
        foreach ($rows as $row) {
            if(self::verifyCode($candidate, (string) $row->code_hash)) {
                try {
                    $updated = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                        ->where("id", $row->id)->whereNull("used_at")
                        ->update(["used_at" => date("Y-m-d H:i:s")]);
                } catch (\Throwable $e) {
                    $updated = 0;
                }
                if($updated) {
                    if(function_exists("security_pack_record_event")) {
                        security_pack_record_event("2fa.recovery_code.used", "A 2FA recovery code was used to sign in.", ["user_id" => $userId, "user_type" => $userType], "warning");
                    }
                    return true;
                }
            }
        }
        return false;
    }
}
