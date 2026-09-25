<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — DB-backed orchestration around the pure Totp class
 * (RFC 6238 math) and KeyStore (secret-at-rest encryption).
 *
 * Enrollment starts PENDING and only flips to ACTIVE after the user
 * proves possession of the authenticator app by submitting a correct
 * current code — a secret is never trusted/activated on the strength of
 * having merely been generated and displayed.
 */
class Enrollment
{
    public static function getConfig(int $userId, string $userType)
    {
        Schema::ensure();
        try {
            return \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)
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
     * as PENDING (overwriting any prior pending/disabled row for this
     * account — an abandoned enrollment is simply replaced by the next
     * attempt, never silently activated).
     *
     * Returns the PLAINTEXT secret + otpauth:// URI for THIS ONE
     * response only — the plaintext secret is never persisted and never
     * re-derivable after this call returns.
     *
     * @return array{secret:string, formatted:string, uri:string}|array{error:string}
     */
    public static function beginEnrollment(int $userId, string $userType, string $accountLabel, string $issuer = "WHMCS"): array
    {
        Schema::ensure();
        $masterKey = KeyStore::getKey();
        if ($masterKey === null) {
            return ["error" => "TOTP secret-at-rest encryption is unavailable on this server (libsodium missing, or the key file could not be created/read). Refusing to store an unencrypted secret."];
        }

        // INCIDENT FIX (2026-08-27): WHMCS core re-invokes the Security
        // Module's _activate() (which calls this method, via
        // dct_totp_native_activate()) after EVERY failed
        // _activateverify() submission, purely to re-render the
        // enrollment form with an error message. This method previously
        // generated + stored a brand-new secret unconditionally on every
        // call, with no distinction between "starting a genuinely new
        // enrollment" and "WHMCS re-rendering the same still-pending
        // enrollment after a wrong code" — so entering one wrong code
        // silently invalidated the QR/secret the user had already
        // scanned into their authenticator app, guaranteeing every
        // subsequent attempt would also fail. Reported live: the
        // displayed "Manual entry secret" changed on every incorrect
        // code submission.
        //
        // Fix: reuse the existing secret for a still-PENDING enrollment
        // rather than rotating it. This does not weaken the "never
        // silently activate" guarantee described in this method's own
        // docblock above — the row's status stays "pending" either way;
        // only which secret backs that pending row changes. A genuinely
        // new enrollment (no pending row yet, or the prior row's secret
        // can no longer be decrypted — e.g. the encryption key was
        // rotated since it was written) still mints a fresh secret
        // exactly as before.
        $existing = self::getConfig($userId, $userType);
        if ($existing && $existing->status === "pending") {
            $reusedSecret = Totp::decryptSecret((string) $existing->secret_encrypted, $masterKey);
            if ($reusedSecret !== null) {
                return [
                    "secret" => $reusedSecret,
                    "formatted" => Totp::formatSecretForDisplay($reusedSecret),
                    "uri" => Totp::provisioningUri($reusedSecret, $accountLabel, $issuer),
                ];
            }
            // Fall through to mint a fresh secret — the pending row's
            // secret can no longer be decrypted, so there is nothing
            // valid to reuse.
        }

        $secret = Totp::generateSecret();
        $encrypted = Totp::encryptSecret($secret, $masterKey);
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)->updateOrInsert(
                ["user_id" => $userId, "user_type" => $userType],
                ["secret_encrypted" => $encrypted, "status" => "pending", "last_used_step" => null, "updated_at" => $now, "created_at" => $now]
            );
        } catch (\Throwable $e) {
            return ["error" => "Could not store the pending TOTP enrollment."];
        }
        EventLog::record("TOTP enrollment started for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
        return [
            "secret" => $secret,
            "formatted" => Totp::formatSecretForDisplay($secret),
            "uri" => Totp::provisioningUri($secret, $accountLabel, $issuer),
        ];
    }

    /**
     * Verify the code submitted during enrollment and, if correct,
     * activate. Rate-limited — never permanently locks the account, just
     * throttles retries.
     *
     * Uses Totp::matchingStep() (not verify()) so the matched HOTP
     * counter is known and can be persisted as last_used_step at the
     * same moment the row flips to active — this guarantees the very
     * first accepted code at a real login (verifyLogin()) is compared
     * against a real baseline, not an unset column.
     */
    public static function verifyAndActivate(int $userId, string $userType, string $candidateCode, string $ip): array
    {
        Schema::ensure();
        $rlKey = "enroll_verify:" . $userType . ":" . $userId;
        if (!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }
        $row = self::getConfig($userId, $userType);
        if (!$row || $row->status !== "pending") {
            return ["status" => "no_pending_enrollment"];
        }
        $masterKey = KeyStore::getKey();
        $secret = $masterKey ? Totp::decryptSecret((string) $row->secret_encrypted, $masterKey) : null;
        if ($secret === null) {
            return ["status" => "error"];
        }
        $matchedStep = Totp::matchingStep($secret, $candidateCode, time());
        if ($matchedStep === null) {
            EventLog::record("TOTP enrollment verification failed for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
            return ["status" => "invalid"];
        }
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "active", "activated_at" => $now, "last_verified_at" => $now, "last_used_step" => $matchedStep, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        EventLog::record("TOTP enrollment completed for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
        // First-time enrollment also (re)generates a fresh recovery-code
        // set, since a brand-new TOTP secret with no recovery codes yet
        // would leave the user with no fallback if they lose the device
        // before ever visiting a "generate recovery codes" screen.
        $recoveryCodes = [];
        if (RecoveryCodes::remainingCount($userId, $userType) === 0) {
            $recoveryCodes = RecoveryCodes::regenerate($userId, $userType);
        }
        return ["status" => "valid", "recovery_codes" => $recoveryCodes];
    }

    /**
     * Verify a code at sign-in time against an already-active
     * enrollment.
     *
     * Replay protection: rejects a code whose matched HOTP counter is
     * <= the account's stored last_used_step — this covers both "the
     * exact same code submitted twice" (e.g. an intercepted/replayed
     * request) and "an older, previously-valid code submitted after a
     * newer one was already accepted", since TOTP counters only move
     * forward with time. On success, the new counter is persisted so the
     * very next login (even one landing in the same +/-1-step tolerance
     * window) cannot reuse it.
     */
    public static function verifyLogin(int $userId, string $userType, string $candidateCode, string $ip): array
    {
        Schema::ensure();
        $rlKey = "verify:" . $userType . ":" . $userId . ":" . $ip;
        if (!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }
        $row = self::getConfig($userId, $userType);
        if (!$row || $row->status !== "active") {
            return ["status" => "no_challenge"];
        }
        $masterKey = KeyStore::getKey();
        $secret = $masterKey ? Totp::decryptSecret((string) $row->secret_encrypted, $masterKey) : null;
        if ($secret === null) {
            return ["status" => "error"];
        }
        $matchedStep = Totp::matchingStep($secret, $candidateCode, time());
        if ($matchedStep === null) {
            EventLog::record("TOTP verification failed for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
            return ["status" => "invalid"];
        }
        $lastUsedStep = isset($row->last_used_step) && $row->last_used_step !== null ? (int) $row->last_used_step : null;
        if ($lastUsedStep !== null && $matchedStep <= $lastUsedStep) {
            EventLog::record("A TOTP code was rejected as a possible replay for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
            return ["status" => "replayed"];
        }
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)->where("id", $row->id)
                ->update(["last_verified_at" => date("Y-m-d H:i:s"), "last_used_step" => $matchedStep]);
        } catch (\Throwable $e) {
        }
        EventLog::record("TOTP verification succeeded for " . $userType . " #" . $userId . ".", $userType === "client" ? $userId : 0);
        return ["status" => "valid"];
    }

    /**
     * Reset invalidates the old secret entirely — the user must
     * re-enroll from scratch (scan a new QR / enter a new secret).
     * Never silently re-activates.
     */
    public static function reset(int $userId, string $userType, string $actor): void
    {
        Schema::ensure();
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "secret_encrypted" => "", "deactivated_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        EventLog::record("TOTP was reset for " . $userType . " #" . $userId . " by " . $actor . " — re-enrollment required.", $userType === "client" ? $userId : 0);
    }

    public static function disable(int $userId, string $userType, string $actor = "user"): void
    {
        Schema::ensure();
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::SECRETS_TABLE)->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        EventLog::record("TOTP disabled for " . $userType . " #" . $userId . " by " . $actor . ".", $userType === "client" ? $userId : 0);
    }
}
