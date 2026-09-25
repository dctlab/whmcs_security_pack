<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — shared, pure OTP engine.
 *
 * Extracted from Email2faService's pure helpers (Security Pack 2.6) so
 * that Email2faService and the new WhatsAppTwoFactorService use the
 * IDENTICAL clamp/generate/hash/verify/evaluate logic instead of two
 * copies of the same code — this is what the unified 2FA spec's
 * "these values should reuse the centralized 2FA configuration where
 * possible rather than being duplicated per provider" requirement means
 * in practice.
 *
 * Pure — no DB, no I/O, no WHMCS globals. Every method here is a plain
 * function of its arguments, unit-tested directly in tests/run.php.
 *
 * Email2faService's own same-named static methods now simply call
 * through to this class, so nothing calling Email2faService::clampOtpLength()
 * (or any other pure helper) needs to change.
 */
class OtpEngine
{
    public const MIN_OTP_LENGTH = 6;
    public const MAX_OTP_LENGTH = 8;
    public const MIN_VALIDITY_MINUTES = 1;
    public const MAX_VALIDITY_MINUTES = 30;
    public const MIN_BYPASS_DAYS = 1;
    public const MAX_BYPASS_DAYS = 90;

    public static function clampOtpLength($configured): int
    {
        $length = (int) $configured;
        if($length < self::MIN_OTP_LENGTH) {
            return self::MIN_OTP_LENGTH;
        }
        if($length > self::MAX_OTP_LENGTH) {
            return self::MAX_OTP_LENGTH;
        }
        return $length;
    }

    public static function clampValidityMinutes($configured): int
    {
        $minutes = (int) $configured;
        if($minutes < self::MIN_VALIDITY_MINUTES) {
            return self::MIN_VALIDITY_MINUTES;
        }
        if($minutes > self::MAX_VALIDITY_MINUTES) {
            return self::MAX_VALIDITY_MINUTES;
        }
        return $minutes;
    }

    public static function clampBypassDays($configured): int
    {
        $days = (int) $configured;
        if($days < self::MIN_BYPASS_DAYS) {
            return self::MIN_BYPASS_DAYS;
        }
        if($days > self::MAX_BYPASS_DAYS) {
            return self::MAX_BYPASS_DAYS;
        }
        return $days;
    }

    public static function clampMaxAttempts($configured): int
    {
        $attempts = (int) $configured;
        if($attempts < 3) {
            return 3;
        }
        if($attempts > 10) {
            return 10;
        }
        return $attempts;
    }

    public static function clampMaxResends($configured): int
    {
        $resends = (int) $configured;
        if($resends < 1) {
            return 1;
        }
        if($resends > 10) {
            return 10;
        }
        return $resends;
    }

    public static function clampResendCooldownSeconds($configured): int
    {
        $seconds = (int) $configured;
        if($seconds < 30) {
            return 30;
        }
        if($seconds > 600) {
            return 600;
        }
        return $seconds;
    }

    /**
     * Cryptographically secure numeric OTP of exactly $length digits.
     * Uses random_int() — never rand()/mt_rand()/time()/uniqid().
     */
    public static function generateOtp(int $length): string
    {
        $length = self::clampOtpLength($length);
        $max = (10 ** $length) - 1;
        $value = random_int(0, $max);
        return str_pad((string) $value, $length, "0", STR_PAD_LEFT);
    }

    /** Hash an OTP for storage — never store plaintext. Bcrypt via password_hash(). */
    public static function hashOtp(string $otp): string
    {
        return password_hash($otp, PASSWORD_DEFAULT);
    }

    public static function verifyOtpHash(string $otp, string $hash): bool
    {
        if($hash === "") {
            return false;
        }
        return password_verify($otp, $hash);
    }

    /**
     * Pure decision: given a challenge row's state (plain scalars) and
     * the candidate OTP, decide the verification outcome.
     *
     * @return string one of: "valid", "invalid", "expired", "consumed", "locked"
     */
    public static function evaluateOtpSubmission(
        string $candidateOtp,
        string $otpHash,
        string $status,
        int $expiresAtTs,
        int $attemptCount,
        int $maxAttempts,
        int $nowTs
    ): string {
        if($status === "consumed") {
            return "consumed";
        }
        if($status === "invalidated" || $attemptCount >= $maxAttempts) {
            return "locked";
        }
        if($nowTs >= $expiresAtTs) {
            return "expired";
        }
        if(self::verifyOtpHash($candidateOtp, $otpHash)) {
            return "valid";
        }
        return "invalid";
    }

    /** Pure decision: is a stored bypass still usable right now? */
    public static function isBypassActive(?string $revokedAt, int $expiresAtTs, int $nowTs): bool
    {
        if($revokedAt !== null && $revokedAt !== "") {
            return false;
        }
        return $nowTs < $expiresAtTs;
    }

    /** Mask an email address for display: "u***@example.com" style. */
    public static function maskEmail(string $email): string
    {
        if(!str_contains($email, "@")) {
            return "•••";
        }
        [$local, $domain] = explode("@", $email, 2);
        $localLen = function_exists("mb_strlen") ? mb_strlen($local) : strlen($local);
        $visible = $localLen > 1 ? mb_substr($local, 0, 1) : $local;
        return $visible . str_repeat("•", max(3, $localLen - 1)) . "@" . $domain;
    }

    /**
     * Mask a phone/WhatsApp number for display: keeps the last 3 digits
     * visible, masks everything else (Section 11 — never expose the full
     * destination unnecessarily beyond what the account owner already
     * knows).
     */
    public static function maskPhone(string $phone): string
    {
        $digits = preg_replace("/[^0-9+]/", "", $phone) ?? "";
        $len = strlen($digits);
        if($len <= 3) {
            return str_repeat("•", max(0, $len));
        }
        return str_repeat("•", $len - 3) . substr($digits, -3);
    }

    /**
     * PURE, DB-free (no database access — unit tested directly):
     * normalizes a phone number for EQUALITY COMPARISON only (never for
     * display or for dialing) — digits only, then the trailing 10 kept
     * so differing country-code/leading-zero formatting of the SAME real
     * number ("+919846560111", "09846560111", "9846560111") still
     * compares equal, while two genuinely different numbers essentially
     * never share the same last 10 digits.
     *
     * Added 2026-09-23 as part of the DctWhatsAppNotificationsBridge fix
     * (WhatsApp 2FA activation/send offered a code to a different
     * client's phone number — see WhatsAppTwoFactorService::
     * pickUnambiguousClientId()'s docblock for the full root cause) — a
     * defense-in-depth gate there compares a resolved client's stored
     * phone against the actual verified destination phone before
     * trusting that resolution for delivery, and needs a tolerant-but-
     * safe equality check to do it.
     */
    public static function normalizePhoneForComparison(?string $phone): string
    {
        $digits = preg_replace("/\D+/", "", (string) $phone) ?? "";
        return strlen($digits) > 10 ? substr($digits, -10) : $digits;
    }
}
