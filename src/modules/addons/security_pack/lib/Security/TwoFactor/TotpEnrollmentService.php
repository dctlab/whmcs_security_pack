<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

use WHMCS\Module\Addon\Security_Pack\Security\RateLimiter;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — DB-backed orchestration around the pure
 * TotpService (RFC 6238 math) and TotpKeyStore (secret-at-rest
 * encryption). Split follows the same pure-vs-orchestration pattern as
 * every other service in this module.
 *
 * Section 13: "Do NOT activate TOTP before successful verification" —
 * enrollment starts PENDING and only flips to active after the user
 * proves possession of the authenticator app by submitting a correct
 * current code.
 */
class TotpEnrollmentService
{
    private const TABLE = "dctlab_security_pack_totp2fa";

    /**
     * Version marker for the 2026-08-27 secret-stability fix
     * (beginEnrollment() no longer rotates the secret on a retry re-render
     * after a wrong code). Diagnostics checks for this constant's
     * existence via Reflection — which inspects whatever code is actually
     * LOADED (including a stale opcache-cached class definition), not
     * just what's on disk — to distinguish "the fix is deployed but not
     * yet working" from "the server is still executing the old,
     * pre-upload bytecode of this file." Purely diagnostic; nothing else
     * in this class reads or depends on it.
     */
    public const ENROLLMENT_FIX_MARKER = "totp-secret-stability-2026-08-27";

    public static function getConfig(int $userId, string $userType)
    {
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
        return $row && $row->status === "active";
    }

    /**
     * Begin enrollment: generate a new secret, encrypt it at rest, store
     * as PENDING. Returns the PLAINTEXT secret + otpauth:// URI for
     * THIS ONE response only (Section 14 — never expose it again after
     * this point; the caller must display it now or not at all).
     *
     * @return array{secret:string, formatted:string, uri:string}|array{error:string}
     */
    public static function beginEnrollment(int $userId, string $userType, string $accountLabel): array
    {
        $masterKey = TotpKeyStore::getKey();
        if($masterKey === null) {
            return ["error" => "TOTP secret-at-rest encryption is unavailable on this server (libsodium missing or the key file could not be created/read). Refusing to store an unencrypted secret — see TotpKeyStore's documentation."];
        }

        // INCIDENT FIX (2026-08-27): WHMCS core re-invokes the Security
        // Module's _activate() (which calls this method) after EVERY
        // failed _activateverify() submission, purely to re-render the
        // enrollment form with an error message — confirmed via
        // dct_totp_2fa_activate()'s own $params["verifyError"] handling.
        // This method previously generated + stored a BRAND-NEW secret on
        // every single call with no exception for that re-render case, so
        // entering one wrong code silently invalidated the QR/secret the
        // user had already scanned into their authenticator app — every
        // subsequent attempt was then guaranteed to fail too, since the
        // app still held the old (now-discarded) secret. Reported live:
        // the displayed "Manual entry secret" changed on every incorrect
        // code submission.
        //
        // Fix: if a PENDING enrollment already exists for this identity,
        // reuse its existing secret rather than rotating it — this does
        // NOT weaken "Section 13: do not activate before verification"
        // (the row's status stays "pending" either way; only which
        // secret backs that pending row changes). A genuinely NEW
        // enrollment (no pending row yet, or the prior row's secret
        // fails to decrypt — e.g. the encryption key was rotated since
        // it was written) still mints a fresh secret exactly as before.
        $existing = self::getConfig($userId, $userType);
        if($existing && $existing->status === "pending") {
            $reusedSecret = TotpService::decryptSecret((string) $existing->secret_encrypted, $masterKey);
            if($reusedSecret !== null) {
                return [
                    "secret" => $reusedSecret,
                    "formatted" => TotpService::formatSecretForDisplay($reusedSecret),
                    "uri" => TotpService::provisioningUri($reusedSecret, $accountLabel),
                ];
            }
            // Fall through to mint a fresh secret — the pending row's
            // secret can no longer be decrypted, so there is nothing
            // valid to reuse.
        }

        $secret = TotpService::generateSecret();
        $encrypted = TotpService::encryptSecret($secret, $masterKey);
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->updateOrInsert(
                ["user_id" => $userId, "user_type" => $userType],
                ["secret_encrypted" => $encrypted, "status" => "pending", "updated_at" => $now, "created_at" => $now]
            );
        } catch (\Throwable $e) {
            return ["error" => "could not store the pending TOTP enrollment"];
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.enrollment.started", "Time-Based Token enrollment started.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"]);
        }
        return [
            "secret" => $secret,
            "formatted" => TotpService::formatSecretForDisplay($secret),
            "uri" => TotpService::provisioningUri($secret, $accountLabel),
        ];
    }

    /**
     * Verify the code submitted during enrollment and, if correct,
     * activate. Rate-limited (Section 26) — never permanently locks the
     * account, just throttles.
     *
     * Replay protection (rebuild requirement #11): uses
     * TotpService::matchingStep() instead of verify() so the matched HOTP
     * counter is known, and persists it as last_used_step at the same
     * time the row flips to active — this guarantees the very first
     * accepted code at login (verifyLogin()) is compared against a real
     * baseline, not an unset column.
     */
    public static function verifyAndActivate(int $userId, string $userType, string $candidateCode, string $ip): array
    {
        $rlKey = "totp_enroll_verify:" . $userType . ":" . $userId;
        if(!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }
        $row = self::getConfig($userId, $userType);
        if(!$row || $row->status !== "pending") {
            return ["status" => "no_pending_enrollment"];
        }
        $masterKey = TotpKeyStore::getKey();
        $secret = $masterKey ? TotpService::decryptSecret((string) $row->secret_encrypted, $masterKey) : null;
        if($secret === null) {
            return ["status" => "error"];
        }
        $matchedStep = TotpService::matchingStep($secret, $candidateCode, time());
        if($matchedStep === null) {
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("2fa.verification.failed", "Time-Based Token enrollment verification failed.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"], "warning");
            }
            return ["status" => "invalid"];
        }
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "active", "activated_at" => $now, "last_verified_at" => $now, "last_used_step" => $matchedStep, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.totp.enrolled", "Time-Based Token enrollment completed.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"]);
            security_pack_record_event("2fa.enrollment.completed", "2FA enrollment completed (totp).", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"]);
            security_pack_record_event("2fa.enabled", "Time-Based Token Two-Factor Authentication enabled.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"]);
        }
        return ["status" => "valid"];
    }

    /**
     * Verify a code at sign-in time against an already-active enrollment.
     *
     * Replay protection (rebuild requirement #11): rejects a code whose
     * matched HOTP counter is <= the account's stored last_used_step —
     * this covers both "the exact same code submitted twice" (e.g. an
     * intercepted/replayed request) and "an older, previously-valid code
     * submitted after a newer one was already accepted", since TOTP
     * counters only move forward with time. On success, the new counter
     * is persisted so the very next login (even one that lands in the
     * same ±1-step tolerance window, e.g. two logins seconds apart) can't
     * reuse it. A single additive nullable column (last_used_step) on the
     * EXISTING dctlab_security_pack_totp2fa table — no new database table.
     */
    public static function verifyLogin(int $userId, string $userType, string $candidateCode, string $ip): array
    {
        $rlKey = "totp_verify:" . $userType . ":" . $userId . ":" . $ip;
        if(!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }
        $row = self::getConfig($userId, $userType);
        if(!$row || $row->status !== "active") {
            return ["status" => "no_challenge"];
        }
        $masterKey = TotpKeyStore::getKey();
        $secret = $masterKey ? TotpService::decryptSecret((string) $row->secret_encrypted, $masterKey) : null;
        if($secret === null) {
            return ["status" => "error"];
        }
        $matchedStep = TotpService::matchingStep($secret, $candidateCode, time());
        if($matchedStep === null) {
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("2fa.verification.failed", "Time-Based Token verification failed.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"], "warning");
            }
            return ["status" => "invalid"];
        }
        $lastUsedStep = isset($row->last_used_step) && $row->last_used_step !== null ? (int) $row->last_used_step : null;
        if($lastUsedStep !== null && $matchedStep <= $lastUsedStep) {
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("2fa.totp.replay_rejected", "A Time-Based Token code was rejected because it (or a newer one) was already used to sign in — possible replay attempt.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"], "warning");
            }
            return ["status" => "replayed"];
        }
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $row->id)
                ->update(["last_verified_at" => date("Y-m-d H:i:s"), "last_used_step" => $matchedStep]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.verification.success", "Time-Based Token verification succeeded.", ["user_id" => $userId, "user_type" => $userType, "method" => "totp"]);
        }
        return ["status" => "valid"];
    }

    /**
     * Section 15: reset invalidates the old secret entirely — the user
     * must re-enroll from scratch (scan a new QR / enter a new secret).
     * Never silently re-activates.
     */
    public static function reset(int $userId, string $userType, string $actor): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "secret_encrypted" => "", "deactivated_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.totp.reset", "Time-Based Token was reset — re-enrollment required.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor, "method" => "totp"], "warning");
        }
        // 2026-08-22 — Requirements doc Section 3: the secret itself is
        // being invalidated here, so any trusted browser tied to the
        // OLD enrollment must not keep bypassing 2FA once a NEW secret
        // is re-enrolled — the user never actually verified against the
        // new secret from that browser.
        if(class_exists(TrustedBrowserService::class)) {
            TrustedBrowserService::revokeAll($userId, $userType, $actor);
        }
    }

    public static function disable(int $userId, string $userType, string $actor = "user"): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.disabled", "Time-Based Token Two-Factor Authentication disabled.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor, "method" => "totp"]);
        }
    }
}
