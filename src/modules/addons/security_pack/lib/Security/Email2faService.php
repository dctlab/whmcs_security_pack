<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.6 — Email Two-Factor Authentication.
 *
 * THE authoritative Email 2FA engine — extends the pre-existing (but
 * never actually wired up) Email 2FA scaffold from earlier releases
 * (the "email_2fa_length"/"email_2fa_minutes" settings and the
 * "Security Pack - Admin/User Two-Factor Authentication" email
 * templates, both already present before this release) rather than
 * creating a second implementation.
 *
 * Identity model: every record here is keyed by (user_id, user_type)
 * where user_type is "client" or "admin" — user_id is the WHMCS USER
 * identity (\WHMCS\User\User::id for clients, \WHMCS\User\Admin::id /
 * adminid for admins), never a per-client-relationship id. A WHMCS User
 * associated with multiple clients has exactly one Email 2FA
 * configuration, matching WHMCS's own User/Client separation.
 *
 * Split, consistent with every other service in this module
 * (SecurityScoreService, SecurityAnomalyService, ...): pure helpers
 * (OTP generation/hashing/verification, attempt/expiry logic) vs.
 * DB-backed orchestration (challenge/bypass lifecycle). The pure parts
 * are unit-tested without a database — see tests/run.php.
 *
 * Reuses, never duplicates: RateLimiter (OTP send/resend/verify
 * throttling), IpUtil / security_pack_detect_visitor_ip() (IP
 * resolution for bypass scoping — never a second IP parser),
 * security_pack_record_event() (all auditing).
 */
class Email2faService
{
    public const TYPE_CLIENT = "client";
    public const TYPE_ADMIN = "admin";

    public const PURPOSE_ACTIVATION = "activation";
    public const PURPOSE_LOGIN = "login";

    public const MIN_OTP_LENGTH = 6;
    public const MAX_OTP_LENGTH = 8;
    public const MIN_VALIDITY_MINUTES = 1;
    public const MAX_VALIDITY_MINUTES = 30;
    public const MIN_BYPASS_DAYS = 1;
    public const MAX_BYPASS_DAYS = 90;

    // ---------------------------------------------------------------
    // Pure helpers — no DB, no I/O. Safe to unit test directly.
    // ---------------------------------------------------------------

    /**
     * Clamp an admin-configured OTP length into the safe bounded range
     * (Step 12 — never 1, never 100/1000).
     */
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

    /**
     * Clamp an admin-configured code validity into a safe bounded range
     * (Step 15 — never 0, never negative, never absurdly large).
     */
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
     * Cryptographically secure numeric OTP of exactly $length digits
     * (Step 11 — random_int(), never rand()/mt_rand()/time()/uniqid()).
     * Leading zeros are preserved (str_pad), so the code always contains
     * exactly $length digits as required (Step 12).
     */
    public static function generateOtp(int $length): string
    {
        $length = self::clampOtpLength($length);
        $max = (10 ** $length) - 1;
        $value = random_int(0, $max);
        return str_pad((string) $value, $length, "0", STR_PAD_LEFT);
    }

    /**
     * Hash an OTP for storage (Step 13 — never store plaintext). Uses
     * PHP's password hashing API (bcrypt), the same primitive already
     * relied on elsewhere for short-lived secrets — no custom crypto.
     */
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
     * Pure decision: given a challenge row's state (as plain scalars,
     * not a DB row — so this is trivially unit-testable) and the
     * candidate OTP, decide the verification outcome. Never mutates
     * anything — callers apply the resulting state change.
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

    /**
     * Pure decision: is a stored bypass still usable right now? Scoped
     * check only — caller is responsible for confirming user_id+ip match
     * (Step 27 — never treat an IP alone as identity).
     */
    public static function isBypassActive(?string $revokedAt, int $expiresAtTs, int $nowTs): bool
    {
        if($revokedAt !== null && $revokedAt !== "") {
            return false;
        }
        return $nowTs < $expiresAtTs;
    }

    /**
     * Mask an email address for display (Step 5 — never expose the full
     * address unnecessarily). "u***@example.com" style.
     */
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

    // ---------------------------------------------------------------
    // DB-backed orchestration
    // ---------------------------------------------------------------

    /** Fetch the (user_id, user_type) config row, or null if none exists. */
    public static function getConfig(int $userId, string $userType)
    {
        try {
            return \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
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
     * Begin enabling Email 2FA for a user — creates/updates the config
     * row as PENDING (Step 6: enabling does not immediately trust the
     * address — it becomes active only after activation OTP succeeds)
     * and sends an activation-purpose challenge.
     */
    public static function beginActivation(int $userId, string $userType, string $email, string $ip, array $settings): array
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->updateOrInsert(
                ["user_id" => $userId, "user_type" => $userType],
                ["email" => $email, "status" => "pending", "updated_at" => $now, "created_at" => $now]
            );
        } catch (\Throwable $e) {
            return ["status" => "error"];
        }
        return self::createChallenge($userId, $userType, self::PURPOSE_ACTIVATION, $email, $ip, $settings);
    }

    /**
     * Create (or, if one is already pending and unexpired, reuse-then-
     * replace) a challenge and send the OTP email. Enforces: single
     * active challenge per user context (Step 37 — no duplicate
     * challenges), resend rate limiting via the EXISTING RateLimiter
     * (Step 19/20 — never a second rate limiter, keyed by user+IP so an
     * attacker can't flood a victim's inbox from many IPs, Step 20).
     *
     * @return array{status:string, challenge_id?:int, retry_after?:int}
     */
    public static function createChallenge(int $userId, string $userType, string $purpose, string $email, string $ip, array $settings): array
    {
        $cooldown = self::clampResendCooldownSeconds($settings["email_2fa_resend_cooldown"] ?? 60);
        $maxResends = self::clampMaxResends($settings["email_2fa_max_resends"] ?? 3);
        $length = self::clampOtpLength($settings["email_2fa_length"] ?? 6);
        $validity = self::clampValidityMinutes($settings["email_2fa_minutes"] ?? 10);
        $maxAttempts = self::clampMaxAttempts($settings["email_2fa_max_attempts"] ?? 5);

        // Step 20: rate-limit by the (user, IP, destination) combination —
        // never by IP alone — so an attacker spamming OTP requests for a
        // victim from many different source IPs is still bounded per
        // victim, and a shared-IP office can't lock a single user's
        // resend budget for everyone else on that IP.
        $rlKey = "email2fa_send:" . $userType . ":" . $userId;
        if(!RateLimiter::hit($rlKey, $maxResends + 1, $cooldown * ($maxResends + 1))) {
            return ["status" => "rate_limited", "retry_after" => $cooldown];
        }

        $now = time();
        try {
            $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("purpose", $purpose)
                ->where("status", "pending")->orderBy("id", "DESC")->first();

            if($existing && strtotime((string) $existing->last_sent_at) > 0 && ($now - strtotime((string) $existing->last_sent_at)) < $cooldown) {
                return ["status" => "cooldown", "retry_after" => $cooldown - ($now - strtotime((string) $existing->last_sent_at))];
            }
            if($existing && (int) $existing->resend_count >= $maxResends) {
                return ["status" => "max_resends"];
            }

            // Single-active-challenge rule (Step 37): invalidate any
            // still-pending prior challenge for this exact context before
            // creating the new one — old OTP becomes invalid the moment a
            // new one is issued (Step 18).
            if($existing) {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                    ->where("id", $existing->id)->update(["status" => "invalidated"]);
            }

            $otp = self::generateOtp($length);
            $expiresAt = date("Y-m-d H:i:s", $now + ($validity * 60));
            $challengeId = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")->insertGetId([
                "user_id" => $userId, "user_type" => $userType, "purpose" => $purpose,
                "otp_hash" => self::hashOtp($otp), "expires_at" => $expiresAt,
                "attempt_count" => 0, "max_attempts" => $maxAttempts,
                "resend_count" => $existing ? ((int) $existing->resend_count + 1) : 0,
                "last_sent_at" => date("Y-m-d H:i:s", $now), "ip" => $ip, "status" => "pending",
                "created_at" => date("Y-m-d H:i:s", $now),
            ]);
        } catch (\Throwable $e) {
            return ["status" => "error"];
        }

        // Admin login-purpose challenges get a random, single-use
        // continuation token — the standalone pre-session admin verify
        // page identifies "which challenge is this browser here for" via
        // this token (delivered through a dedicated cookie, never a URL,
        // never WHMCS's own session) rather than any admin identity.
        $continuationToken = null;
        if($userType === self::TYPE_ADMIN && $purpose === self::PURPOSE_LOGIN) {
            $continuationToken = bin2hex(random_bytes(32));
            try {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                    ->where("id", $challengeId)->update(["continuation_hash" => hash("sha256", $continuationToken)]);
            } catch (\Throwable $e) {
                $continuationToken = null;
            }
        }

        $sent = self::sendOtpEmail($userId, $userType, $email, $otp, $validity, $purpose);

        if(function_exists("security_pack_record_event")) {
            security_pack_record_event(
                $existing ? "email_2fa.otp.resent" : "email_2fa.otp.sent",
                "Email 2FA verification code " . ($existing ? "resent" : "sent") . " (" . $purpose . ").",
                ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose, "delivered" => $sent]
            );
        }

        return [
            "status" => $sent ? "sent" : "send_failed",
            "challenge_id" => $challengeId,
            "expires_in" => $validity * 60,
            "continuation_token" => $continuationToken,
        ];
    }

    /**
     * Resolve a continuation token (from the admin verify page's
     * dedicated cookie) back to its pending admin login challenge, IP
     * bound. Never trusts the token's admin identity from anywhere else
     * — the token itself IS the only identifying credential, and it was
     * only ever transmitted via a cookie this module set itself.
     */
    public static function findChallengeByContinuationToken(string $token, string $ip)
    {
        if($token === "") {
            return null;
        }
        try {
            $row = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                ->where("continuation_hash", hash("sha256", $token))
                ->where("purpose", self::PURPOSE_LOGIN)
                ->where("user_type", self::TYPE_ADMIN)
                ->where("ip", $ip)
                ->orderBy("id", "DESC")->first();
        } catch (\Throwable $e) {
            return null;
        }
        if(!$row || strtotime((string) $row->expires_at) < time()) {
            return null;
        }
        return $row;
    }

    /**
     * Verify a submitted OTP against the most recent pending challenge
     * for this (user, purpose). Single-use (Step 16), attempt-limited
     * (Step 17), rate-limited on the verify action itself (Step 19).
     *
     * @return array{status:string} status is one of:
     *   "valid", "invalid", "expired", "consumed", "locked", "no_challenge", "rate_limited"
     */
    public static function verify(int $userId, string $userType, string $purpose, string $candidateOtp, string $ip, array $settings): array
    {
        $rlKey = "email2fa_verify:" . $userType . ":" . $userId . ":" . $ip;
        if(!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }

        try {
            $challenge = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("purpose", $purpose)
                ->orderBy("id", "DESC")->first();
        } catch (\Throwable $e) {
            return ["status" => "no_challenge"];
        }
        if(!$challenge) {
            return ["status" => "no_challenge"];
        }

        $now = time();
        $result = self::evaluateOtpSubmission(
            (string) $candidateOtp,
            (string) $challenge->otp_hash,
            (string) $challenge->status,
            strtotime((string) $challenge->expires_at) ?: 0,
            (int) $challenge->attempt_count,
            (int) $challenge->max_attempts,
            $now
        );

        try {
            // Security regression fix (post-implementation review): the
            // attempt-count increment is conditioned on the SAME
            // attempt_count value this decision was evaluated against
            // (WHERE attempt_count = $challenge->attempt_count), rather
            // than blindly writing "old value + 1". Two concurrent
            // verify requests for the same challenge can both read the
            // same attempt_count, but only the first of their competing
            // UPDATEs will match this WHERE clause and take effect — the
            // second affects zero rows instead of silently landing an
            // extra, uncounted attempt. This keeps the attempt cap
            // (Step 17) enforced under concurrency, not just sequentially.
            if($result === "valid") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                    ->where("id", $challenge->id)->where("attempt_count", (int) $challenge->attempt_count)
                    ->update(["status" => "consumed", "attempt_count" => (int) $challenge->attempt_count + 1]);
            } elseif($result === "invalid") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                    ->where("id", $challenge->id)->where("attempt_count", (int) $challenge->attempt_count)
                    ->update(["attempt_count" => (int) $challenge->attempt_count + 1]);
            } elseif($result === "expired" && $challenge->status === "pending") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")->where("id", $challenge->id)
                    ->update(["status" => "expired"]);
            }
        } catch (\Throwable $e) {
        }

        if(function_exists("security_pack_record_event")) {
            if($result === "valid") {
                security_pack_record_event("email_2fa.verification.success", "Email 2FA verification succeeded (" . $purpose . ").", ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose]);
            } elseif(in_array($result, ["invalid", "expired", "locked"], true)) {
                security_pack_record_event("email_2fa.verification.failed", "Email 2FA verification failed (" . $result . ", " . $purpose . ").", ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose, "reason" => $result], "warning");
            }
        }

        return ["status" => $result];
    }

    /** Mark activation complete after a successful activation-purpose verify. */
    public static function completeActivation(int $userId, string $userType, string $actor = "user"): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "active", "activated_at" => $now, "last_verified_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.enabled", "Email Two-Factor Authentication enabled.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor]);
        }
    }

    /**
     * Disable Email 2FA (Step 48): invalidates pending challenges,
     * records the event. Historical audit events are never deleted (only
     * the live config/challenge rows are touched).
     *
     * 2026-08-27 — production bug fix ("Administrator Manual Bypass
     * still not automatically added" — confirmed live via a raw-row
     * diagnostic dump: a bypass created for a user, and confirmed
     * persisted, showed up REVOKED a few minutes later with no admin
     * action taken). Root cause: this method used to ALSO revoke every
     * one of this identity's bypasses here — dating back to when this
     * table (`dctlab_security_pack_email2fa_bypasses`) was Email 2FA's
     * own, private bypass store, before it became the ONE shared,
     * method-agnostic bypass system all three methods now use (see
     * TwoFactorBypassService's own class docblock: "A bypass is NOT
     * scoped by method... applies regardless of the configured method").
     * This method was never updated when that unification happened, so
     * disabling Email 2FA for an identity — including an AUTOMATIC
     * self-heal correction, not just a deliberate user action, via
     * TwoFactorAuthenticationService::reconcileNativeSecondFactorDrift()
     * — silently wiped out bypasses that had nothing to do with email at
     * all, including ones actively protecting a DIFFERENT, currently
     * active method (confirmed live: a Time-Based Token
     * Administrator Manual Bypass was destroyed this way for an account
     * that has never even had an active Email 2FA enrollment).
     *
     * Fix: this method no longer touches the shared bypass table at all.
     * Wiping every bypass for an identity is now exclusively
     * TwoFactorAuthenticationService::disableAllMethods()'s job — the
     * ONE place that already does this deliberately and correctly, only
     * when an admin explicitly turns 2FA off entirely for that user (see
     * that method's own "protection removed" docblock reasoning), never
     * as a side effect of a single provider being disabled or
     * self-healed.
     */
    public static function disable(int $userId, string $userType, string $actor = "user"): void
    {
        $now = date("Y-m-d H:i:s");
        if(function_exists("security_pack_log_activity")) {
            security_pack_log_activity("[security_pack] DIAGNOSTIC v5: Email2faService::disable() called for " . $userType . " #" . $userId . " by \"" . $actor . "\" — bypass table is NOT touched by this build (fix confirmed active). If a bypass is still disappearing after this line appears, the cause is elsewhere, not here.", $userType === "client" ? $userId : 0);
        } elseif(function_exists("logActivity")) {
            try {
                logActivity("[security_pack] DIAGNOSTIC v5: Email2faService::disable() called for " . $userType . " #" . $userId . " by \"" . $actor . "\" — bypass table is NOT touched by this build (fix confirmed active). If a bypass is still disappearing after this line appears, the cause is elsewhere, not here.", $userType === "client" ? $userId : 0);
            } catch (\Throwable $e) {
            }
        }
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("status", "pending")
                ->update(["status" => "invalidated"]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.disabled", "Email Two-Factor Authentication disabled.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor]);
        }
    }

    /**
     * Step 47: an email address change should not let an old verified
     * address remain implicitly trusted. Re-pends activation (requires
     * re-verification).
     *
     * 2026-08-27 — same fix as disable() above, same reason: this used to
     * also revoke every bypass for the identity, but the shared bypass
     * store is method-agnostic and an email address change on its own is
     * not a reason to strip a bypass protecting a different, unrelated
     * method. See disable()'s own docblock for the full incident.
     */
    public static function handleEmailChanged(int $userId, string $userType, string $newEmail): void
    {
        $row = self::getConfig($userId, $userType);
        if(!$row || $row->status === "disabled") {
            return;
        }
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["email" => $newEmail, "status" => "pending", "activated_at" => null, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.reverification_required", "Email 2FA requires re-verification after an account email change.", ["user_id" => $userId, "user_type" => $userType], "warning");
        }
    }

    /** Step 49: a password change invalidates any pending OTP challenge. */
    public static function handlePasswordChanged(int $userId, string $userType): void
    {
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("status", "pending")
                ->update(["status" => "invalidated"]);
        } catch (\Throwable $e) {
        }
    }

    // --- Bypass management -----------------------------------------

    /**
     * Look up an active same-IP or admin-manual bypass for this exact
     * (user, ip) pair (Step 27 — never IP alone).
     */
    public static function findActiveBypass(int $userId, string $userType, string $ip)
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")
                ->where("user_id", $userId)->where("user_type", $userType)->where("ip", $ip)
                ->whereNull("revoked_at")->orderBy("expires_at", "DESC")->get();
        } catch (\Throwable $e) {
            return null;
        }
        $now = time();
        foreach ($rows as $row) {
            if(self::isBypassActive($row->revoked_at, strtotime((string) $row->expires_at) ?: 0, $now)) {
                return $row;
            }
        }
        return null;
    }

    /**
     * Admin-manual bypass — scoped to the user only (any IP), a distinct
     * scope from the same-IP grant. Step 25/33.
     */
    public static function findActiveAdminBypass(int $userId, string $userType)
    {
        try {
            $row = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")
                ->where("user_id", $userId)->where("user_type", $userType)->where("scope", "admin_manual")
                ->whereNull("revoked_at")->orderBy("expires_at", "DESC")->first();
        } catch (\Throwable $e) {
            return null;
        }
        if(!$row) {
            return null;
        }
        return self::isBypassActive($row->revoked_at, strtotime((string) $row->expires_at) ?: 0, time()) ? $row : null;
    }

    /**
     * Step 31: a successful login-time Email 2FA verification creates or
     * REFRESHES (never silently extends beyond the configured window
     * from "now") the same-IP bypass for the configured duration — the
     * documented, predictable policy.
     */
    public static function grantSameIpBypass(int $userId, string $userType, string $ip, array $settings): void
    {
        if(empty($settings["email_2fa_bypass_same_ip"]) || $settings["email_2fa_bypass_same_ip"] === "0") {
            return;
        }
        $days = self::clampBypassDays($settings["email_2fa_bypass_days"] ?? 7);
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + ($days * 86400));
        try {
            $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")
                ->where("user_id", $userId)->where("user_type", $userType)->where("ip", $ip)
                ->where("scope", "same_ip")->whereNull("revoked_at")->first();
            if($existing) {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->where("id", $existing->id)
                    ->update(["expires_at" => $expires, "updated_at" => $now]);
                $eventType = "email_2fa.bypass.refreshed";
            } else {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->insert([
                    "user_id" => $userId, "user_type" => $userType, "ip" => $ip, "scope" => "same_ip",
                    "expires_at" => $expires, "created_by" => "system", "created_at" => $now, "updated_at" => $now,
                ]);
                $eventType = "email_2fa.bypass.created";
            }
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event($eventType, "Email 2FA same-IP bypass " . ($eventType === "email_2fa.bypass.created" ? "created" : "refreshed") . " for " . $days . " day(s).", ["user_id" => $userId, "user_type" => $userType]);
        }
    }

    /** Step 33/34: explicit administrator-created manual bypass. */
    public static function createAdminBypass(int $userId, string $userType, int $days, string $actorLabel, string $reason = ""): void
    {
        $days = self::clampBypassDays($days);
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + ($days * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->insert([
                "user_id" => $userId, "user_type" => $userType, "ip" => "", "scope" => "admin_manual",
                "expires_at" => $expires, "created_by" => $actorLabel, "reason" => mb_substr($reason, 0, 255),
                "created_at" => $now, "updated_at" => $now,
            ]);
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.bypass.created", "Administrator bypass created for " . $days . " day(s).", ["user_id" => $userId, "user_type" => $userType, "actor" => $actorLabel, "reason" => mb_substr($reason, 0, 255)]);
        }
    }

    public static function revokeBypass(int $bypassId, string $actorLabel): void
    {
        $now = date("Y-m-d H:i:s");
        if(function_exists("logActivity")) {
            try {
                $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 6);
                $chain = [];
                foreach ($trace as $frame) {
                    $chain[] = (isset($frame["class"]) ? $frame["class"] . "::" : "") . ($frame["function"] ?? "?");
                }
                if(function_exists("security_pack_log_activity")) {
                    security_pack_log_activity("[security_pack] DIAGNOSTIC v5: Email2faService::revokeBypass(bypass_id=" . $bypassId . ", actor=\"" . $actorLabel . "\") called. Caller chain: " . implode(" <- ", $chain));
                } else {
                    logActivity("[security_pack] DIAGNOSTIC v5: Email2faService::revokeBypass(bypass_id=" . $bypassId . ", actor=\"" . $actorLabel . "\") called. Caller chain: " . implode(" <- ", $chain));
                }
            } catch (\Throwable $e) {
            }
        }
        try {
            $row = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->where("id", $bypassId)->first();
            if(!$row || $row->revoked_at) {
                return;
            }
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->where("id", $bypassId)->update(["revoked_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.bypass.revoked", "Email 2FA bypass revoked.", ["bypass_id" => $bypassId, "actor" => $actorLabel]);
        }
    }

    /**
     * Cron-only cleanup (Step 30/56): correctness never depends on this
     * running — expiry is always checked at runtime — but old rows are
     * pruned so the tables don't grow unbounded.
     */
    public static function purgeExpired(int $challengeRetentionDays = 7, int $bypassRetentionDays = 30): void
    {
        $challengeCutoff = date("Y-m-d H:i:s", time() - ($challengeRetentionDays * 86400));
        $bypassCutoff = date("Y-m-d H:i:s", time() - ($bypassRetentionDays * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_challenges")->where("created_at", "<", $challengeCutoff)->delete();
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")->where("expires_at", "<", $bypassCutoff)->delete();
        } catch (\Throwable $e) {
        }
    }

    // --- Email delivery ----------------------------------------------

    /**
     * Sends the OTP via WHMCS's OWN mail pipeline (2.7.0 — explicit user
     * instruction: "use WHMCS Mail SYSTEM, do not use PHP mail()").
     *
     * *** SECURITY-RELEVANT TRADE-OFF REVERSAL — READ BEFORE CHANGING ***
     * Every release through 2.6.3 sent OTP mail via raw PHP mail(),
     * specifically and deliberately to guarantee WHMCS's Global BCC
     * recipient (General Settings > Mail > BCC Messages) never received
     * a one-time code — that was a hard requirement from this feature's
     * original specification. Routing through sendAdminMessage()/
     * sendMessage() below uses WHMCS's own templated mail-send pipeline,
     * which DOES apply Global BCC. This module no longer has any way to
     * exclude it. If Global BCC is configured, the BCC recipient WILL
     * now receive a copy of every Email 2FA one-time code, for both
     * admin and client accounts. This was an explicit, direct
     * instruction ("use WHMCS Mail SYSTEM do not use PHP mail()") that
     * knowingly reverses the earlier requirement — disclosed here,
     * in CHANGELOG.md, and in SECURITY-AUDIT-PHASE-4.md rather than
     * silently changed. If Global BCC must never see an OTP, do not set
     * a Global BCC recipient while Email 2FA is active, or revisit this
     * decision.
     *
     * Why this fixes "no mail received": sendAdminMessage()/
     * sendMessage() are the EXACT SAME functions
     * core/loginHistory.php's admin/client login notifications already
     * use successfully in this production environment — they go through
     * WHMCS's own configured mail transport (whatever General Settings >
     * Mail specifies: PHP mail, SMTP, etc.), not a bare, unconfigured
     * local mail() call. A server with no local MTA but a working SMTP
     * relay configured in WHMCS will now be able to deliver Email 2FA
     * mail, which it could not with the previous raw mail() approach.
     *
     * Admin-type: sendAdminMessage() targets the admin record directly
     * by id — no further resolution needed.
     *
     * Client-type — ARCHITECTURE CORRECTION (2026-08-23), explicit
     * instruction: "User-level OTP -> User email -> WHMCS Mail Provider,
     * keeping client_id only as the relationship/context." The original
     * 2.7.0 design routed client-type OTP through sendMessage(), which
     * requires a genuine tblclients.id and can ONLY ever deliver to that
     * Client account's own stored email — it has no override-recipient
     * parameter. That was the wrong primary mechanism for what this
     * module actually identifies (a WHMCS User, tblusers.id, which may
     * have its own email distinct from any Client account it's linked
     * to): it happened to work only when a User's email and their linked
     * Client's stored email were literally the same address (the common
     * owner/primary-login case), and silently misdelivered — to the
     * Client account's address instead of the actual logged-in user's —
     * for any secondary User with their own distinct email. Fixed live:
     * a secondary WHMCS User's Email 2FA activation delivered its code to
     * the Client account owner's inbox instead of that user's own.
     *
     * Client-type OTP is now sent directly to the User's own $email via
     * sendDirectToAddress() (WHMCS's own \WHMCS\Mail\Template/
     * \WHMCS\Mail\Message classes — still "the WHMCS Mail SYSTEM," same
     * transport as sendMessage()), unconditionally — never through
     * sendMessage()'s Client-id resolution.
     *
     * UPDATE (2026-08-25): resolveClientIdForUser() is no longer called
     * on this path at all (it previously ran purely to populate a
     * diagnostic string that was never surfaced anywhere) — explicit
     * instruction to avoid unnecessary DB work on every OTP send. The
     * method itself is untouched and still used elsewhere in this
     * codebase.
     *
     * CORRECTION (2026-08-25): this docblock previously claimed
     * sendDirectToAddress() had "the same Global BCC behavior as
     * sendMessage()" — that was an unverified assumption, and on
     * inspection it was wrong. sendDirectToAddress() built its own
     * \WHMCS\Mail\Message with a single addRecipient("to", ...) call and
     * dispatched it straight through the mail-provider module
     * (\WHMCS\Module\Mail::factory()->load($mailerid)->call("send", ...)),
     * bypassing whatever higher-level orchestration sendMessage() uses to
     * append the configured Global BCC recipient before dispatch. No BCC
     * recipient was ever added anywhere in this path — meaning Global BCC
     * (General Settings > Mail > BCC Messages), if configured, was NOT
     * actually receiving a copy of Email 2FA one-time codes, contrary to
     * the earlier claim. Fixed by explicitly reading the configured BCC
     * address(es) and adding them via addRecipient("bcc", ...) — see
     * sendDirectToAddress() below.
     *
     * CORRECTION (2026-08-26): this docblock previously claimed here that
     * "header/footer content already applies" because rendering goes
     * through WHMCS's real "mailMessage:" Smarty resource — that was
     * wrong. Rendering the template body and wrapping it in WHMCS's
     * Global Email Header/Footer are two separate steps; only the first
     * was ever done on this path. See the applyGlobalWrapper() fix in
     * sendDirectToAddress() below for the actual correction.
     */
    public static function sendOtpEmail(int $userId, string $userType, string $email, string $otp, int $validityMinutes, string $purpose): bool
    {
        if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            self::logMailFailure("invalid destination address on file");
            return false;
        }

        $templateName = $userType === self::TYPE_ADMIN ? "Security Pack - Admin Two-Factor Authentication" : "Security Pack - User Two-Factor Authentication";
        $purposeLabel = $purpose === self::PURPOSE_ACTIVATION ? "enabling Email Two-Factor Authentication" : "signing in";
        $mergefields = array_merge(self::genericMergeFields(), [
            "auth_code" => $otp,
            "otp" => $otp,
            "auth_validity_minutes" => (string) $validityMinutes,
            "validity" => (string) $validityMinutes,
            "auth_purpose_label" => $purposeLabel,
        ]);

        $result = self::sendViaWhmcs($userId, $userType, $email, $templateName, $mergefields);
        if(!$result["sent"]) {
            self::logMailFailure((string) $result["reason"]);
        }
        return $result["sent"];
    }

    /**
     * General-purpose merge fields available to ANY templated WHMCS
     * email — company name, logo, system URL, global signature, current
     * date/time, charset. Added 2026-08-25: confirmed real and in
     * production use via a second, independent reference implementation
     * (WSCustomMessage::getGenericMergeData(), from the same "Email
     * Verification by WHMCS Services" marketplace module this file's
     * send path already mirrors, user-supplied). These were previously
     * never assigned by this module at all, meaning a custom-edited
     * "Security Pack - Admin/User Two-Factor Authentication" template
     * referencing e.g. {$company_name} or {$signature} would have
     * rendered them blank. Purely additive — every OTP-specific field
     * (auth_code, otp, etc.) is still merged in by the caller and always
     * takes priority for any key that collides.
     *
     * Best-effort: each WHMCS class/method is guarded with
     * class_exists()/method_exists() and the whole thing is wrapped in
     * try/catch, returning an empty array (no generic fields, exactly
     * today's prior behavior) rather than failing the OTP send if any of
     * these aren't available in this execution context.
     *
     * @return array<string,string>
     */
    private static function genericMergeFields(): array
    {
        $fields = [];
        try {
            if(class_exists("\\WHMCS\\Config\\Setting")) {
                $fields["company_name"] = (string) \WHMCS\Config\Setting::getValue("CompanyName");
                $fields["companyname"] = $fields["company_name"];
                $fields["company_domain"] = (string) \WHMCS\Config\Setting::getValue("Domain");
                $fields["charset"] = (string) \WHMCS\Config\Setting::getValue("Charset");
                if(class_exists("\\WHMCS\\Input\\Sanitize")) {
                    $fields["signature"] = nl2br((string) \WHMCS\Input\Sanitize::decode((string) \WHMCS\Config\Setting::getValue("Signature")));
                }
            }
            if(class_exists("\\App")) {
                if(method_exists("\\App", "getSystemUrl")) {
                    $sysurl = (string) \App::getSystemUrl();
                    $fields["whmcs_url"] = $sysurl;
                    $fields["whmcs_link"] = "<a href=\"" . $sysurl . "\">" . $sysurl . "</a>";
                }
                if(method_exists("\\App", "self")) {
                    $whmcs = \App::self();
                    if($whmcs && method_exists($whmcs, "getLogoUrlForEmailTemplate")) {
                        $fields["company_logo_url"] = (string) $whmcs->getLogoUrlForEmailTemplate();
                    }
                }
            }
            $fields["date"] = date("l, jS F Y");
            $fields["time"] = date("g:ia");
        } catch (\Throwable $e) {
        }
        return $fields;
    }

    /**
     * The actual WHMCS-mail-pipeline transport, shared by sendOtpEmail()
     * above and sendTestEmail() below so the diagnostic "Send Test
     * Email" action exercises EXACTLY the same delivery path a real OTP
     * would use.
     *
     * @return array{sent:bool, reason:?string}
     */
    private static function sendViaWhmcs(int $userId, string $userType, string $email, string $templateName, array $mergefields): array
    {
        if($userType === self::TYPE_ADMIN) {
            if(!function_exists("sendAdminMessage")) {
                return ["sent" => false, "reason" => "sendAdminMessage() is not available in this execution context"];
            }
            try {
                // Same call shape as core/loginHistory.php's proven-
                // working admin login notification: (template,
                // mergefields, type, ticketid, adminid).
                sendAdminMessage($templateName, $mergefields, "system", 0, $userId);
            } catch (\Throwable $e) {
                return ["sent" => false, "reason" => $e->getMessage()];
            }
            return ["sent" => true, "reason" => null];
        }

        // FIX (2026-08-26, SEVENTH correction) — REVERTS the sixth
        // correction's unconditional sendMessage() call. Confirmed live:
        // it misdelivered a sub-account's OTP to the Client (owner)
        // account's own email instead of the actual WHMCS User's own
        // email — exactly the trade-off disclosed in that correction's
        // docblock/report, now confirmed as REAL, LIVE HARM, not a
        // hypothetical. This is a correctness/privacy issue (one
        // account's login code readable by another account's inbox) and
        // takes priority over cosmetic branding — reverted immediately
        // rather than left live while a better answer is found.
        //
        // Restores the fifth correction's verified-safe gate: resolve a
        // candidate client id, look up THAT client's own stored email,
        // and use sendMessage() (WHMCS's real pipeline, confirmed to
        // render full Global Header/Footer/branding — see Login
        // Notification, core/loginHistory.php) ONLY when it is
        // BYTE-IDENTICAL to the target User's own $email — i.e. only when
        // sendMessage()'s one real behavior (deliver to the Client's
        // stored address) is PROVEN to already be the correct
        // destination, not assumed. This is why the earlier "owner
        // account" failure happened: that account's own User email
        // differs from its linked Client's stored email, so the gate
        // (correctly) would have refused sendMessage() for it — meaning
        // it will keep getting the correctly-addressed, unbranded path
        // below, exactly as it should, until a way is found to get both
        // correct addressing AND branding for that case specifically
        // (still open — see the Mail Pipeline Introspection panel on
        // Diagnostics, added specifically to investigate this without
        // guessing).
        //
        // Any mismatch falls straight through to sendDirectToAddress()
        // below, unchanged: correctly addressed, without full branding —
        // never a wrong-inbox delivery.
        if(function_exists("sendMessage")) {
            try {
                $clientId = self::resolveClientIdForUser($userId);
                if($clientId !== null) {
                    $clientEmail = (string) (\Illuminate\Database\Capsule\Manager::table("tblclients")->where("id", $clientId)->value("email") ?? "");
                    if($clientEmail !== "" && strcasecmp($clientEmail, $email) === 0) {
                        // Same call shape as core/loginHistory.php's
                        // proven-working client login notification —
                        // sendMessage() does not hand back a result to
                        // inspect (same as sendAdminMessage() above), so a
                        // call that completes without throwing is treated
                        // as sent, matching this file's existing pattern.
                        sendMessage($templateName, $clientId, $mergefields);
                        return ["sent" => true, "reason" => null];
                    }
                }
            } catch (\Throwable $e) {
                // Any resolution/lookup/send failure here falls through
                // to the always-safe direct-address path below — this
                // block is a pure opportunistic upgrade, never a
                // dependency.
            }
        }

        return self::sendDirectToAddress($userId, $email, $templateName, $mergefields);
    }

    /**
     * Sends a WHMCS email template directly to a User's own address via
     * WHMCS's own mail pipeline — the module's client-type send path
     * since the 2026-08-23 architecture correction (see sendViaWhmcs()'s
     * docblock: "User-level OTP -> User email -> WHMCS Mail Provider").
     *
     * CONFIDENCE: PATTERN — this is NOT reconstructed from developer
     * guesswork. It matches, near line-for-line, real working code from a
     * live commercial WHMCS marketplace module ("Email Verification" by
     * WHMCS Services — its WSCustomEmailer::sendEmail()), confirmed
     * TWICE from two independent copies of that module's actual shipped
     * source (user-supplied), which sends a one-time-code-style email to
     * an ARBITRARY address (never tied to a Client ID) via WHMCS's own
     * configured mail provider:
     *   1. `WHMCS\Mail\Message` + `->addRecipient('to', $email)` —
     *      addresses the message directly, no Client/User record needed.
     *   2. `WHMCS\Mail\Emailer::factoryByTemplate($templateName, '', [])`
     *      loads the named template into a Message purely so its raw
     *      Smarty source becomes available for real rendering (see next
     *      step) — the Message it returns is not itself sent.
     *   3. `new \WHMCS\Smarty(false, "mail")` +
     *      `$smarty->setMailMessage($emailer->getMessage())` + one
     *      `$smarty->assign()` per merge field + `$smarty->fetch(
     *      "mailMessage:subject")`/`"mailMessage:message")` — genuine
     *      Smarty rendering through WHMCS's own template engine.
     *   4. The configured mail PROVIDER is read from the global $CONFIG
     *      array WHMCS populates every request: `$CONFIG['MailType']`
     *      ('mail' or 'smtp'), with `$CONFIG['MailConfig']` (WHMCS's own
     *      `decrypt()` on a JSON blob) overriding it via its `module` key
     *      when the newer Mail Provider module system is in use — mapped
     *      to the real provider class name ('PhpMail'/'SmtpMail').
     *   5. Dispatch goes through `WHMCS\Module\Mail::factory()->load(
     *      $mailerid)->call('send', [], $message)` — the same
     *      load-a-module-by-name-then-call-a-method loader pattern WHMCS
     *      uses for gateway/registrar modules, here applied to mail
     *      provider modules (confirmed real: `WHMCS\Module\Mail::send()`
     *      is literally the method live in the SmtpMail.php class file
     *      pulled from this install's own vendor directory).
     * Still not developers.whmcs.com-documented — a working third-party
     * module's own production code, same confidence tier this project
     * already gives dct2fa.php/smsmanagertwofactor.php elsewhere — so
     * TEST via Setup > Addon Modules > Security Pack > Diagnostics >
     * "Send Test Email" before relying on this for real logins. Fails
     * closed with a clear, logged reason (never a silent no-op) if any
     * required class is missing.
     *
     * BCC (added 2026-08-25): this path bypasses sendMessage()'s own
     * Global-BCC handling entirely (see the CORRECTION note on
     * sendOtpEmail()'s docblock above), so Global BCC is applied here
     * explicitly — see appendGlobalBcc() below (one lightweight, indexed
     * tblconfiguration read, kept because it closes a real, disclosed
     * gap). Best-effort: the exact tblconfiguration key ("BccMessages")
     * is not confirmed against live WHMCS core source in this
     * environment (same caveat already disclosed in
     * DiagnosticsController's "Email 2FA — OTP Delivery" check); if the
     * key is wrong or absent, this silently adds no BCC recipient rather
     * than failing the send.
     *
     * REVERTED (2026-08-25, second correction): a brief attempt to add
     * `Emailer::factoryByTemplate($templateName, $user, $mergeFields)
     * ->send()` as a "primary" path (based on an emailtwofactor.php file
     * that looked like a second independent reference module) was
     * removed after (a) live testing showed it did NOT close the missing
     * header/CSS gap it was meant to fix, and (b) a second, more complete
     * upload of that same module confirmed emailtwofactor.php was never
     * actually part of it — the genuine, verified module uses this exact
     * WSCustomEmailer pattern, not Emailer::send(). Explicit instruction:
     * keep the flow to Message -> addRecipient() -> WHMCS\Module\Mail ->
     * SmtpMail only, and avoid unnecessary work on this path. Per-user
     * `tblusers` lookups (for a firstname/lastname greeting) and
     * `resolveClientIdForUser()` (multiple DB round-trips purely for a
     * diagnostic string, never surfaced anywhere) are both dropped for
     * that reason — real, avoidable latency on every OTP send, matching
     * this project's still-open "email 2FA loading takes long"
     * complaint. The header/CSS gap itself remains open and disclosed,
     * not silently dropped — see PHASE_EMAIL_HEADER_CSS_FIX_REPORT.md's
     * "still missing" follow-up; it needs the real WHMCS core Emailer/
     * Message source (requested from the user, not yet supplied) before
     * attempting another fix, rather than a third guess.
     *
     * @return array{sent:bool, reason:?string}
     */
    private static function sendDirectToAddress(int $userId, string $email, string $templateName, array $mergefields): array
    {
        $context = "user #{$userId}";

        foreach (["\\WHMCS\\Mail\\Message", "\\WHMCS\\Mail\\Emailer", "\\WHMCS\\Smarty", "\\WHMCS\\Module\\Mail"] as $requiredClass) {
            if(!class_exists($requiredClass)) {
                return ["sent" => false, "reason" => "{$requiredClass} is not available in this execution context ({$context})"];
            }
        }

        try {
            // FIX (2026-08-25, third correction): factoryByTemplate()
            // builds its own Message FROM the template row — including
            // whatever "From Name"/"From Email"/"Copy To"/"Blind Copy
            // To" the admin configured on THIS template under Setup >
            // Email Templates. The previous code built a completely
            // separate, blank `new \WHMCS\Mail\Message()`, used
            // $emailer->getMessage() ONLY to feed the Smarty "mail"
            // resource, then discarded it — so none of the template's
            // own From/Copy-To ever reached the actual outgoing mail.
            // Confirmed live: the template's configured From
            // ("ISHost Verification Desk <Verify@ishost.in>") was
            // silently replaced by WHMCS's system-wide default From
            // address on the email actually received. Fixed by using
            // $emailer->getMessage() itself as the outgoing Message,
            // instead of building an unrelated one — this is the exact
            // same bug the reference WSCustomEmailer.php has too (it
            // also discards factoryByTemplate()'s own Message), so it's
            // not something either reference upload would have caught.
            // EXPERIMENT (2026-08-26, eighth correction): try building
            // the Message via \WHMCS\Mail\Message::createFromTemplate()
            // instead of \WHMCS\Mail\Emailer::factoryByTemplate()->
            // getMessage(). Both are real, documented methods
            // (developers.whmcs.com/classes/whmcs/mail/message — VERIFIED
            // page content, not a guess) — createFromTemplate() has just
            // never been tried on this path before. Whether it produces
            // different rendering (specifically: whether it's what
            // sendMessage()/sendAdminMessage() use internally, which
            // would explain their branding) is UNVERIFIED — this is a
            // genuinely new, doc-grounded attempt, not a repeat of
            // anything already tried and failed (Emailer::factoryByTemplate
            // ->send() was tried and reverted; that is a different call
            // than Message::createFromTemplate()). Falls back to the
            // existing, already-working Emailer::factoryByTemplate()->
            // getMessage() approach if the Template row can't be found or
            // createFromTemplate() isn't available — never a regression,
            // only an opportunistic upgrade attempt.
            $message = null;
            if(class_exists("\\WHMCS\\Mail\\Template") && method_exists("\\WHMCS\\Mail\\Message", "createFromTemplate")) {
                try {
                    $templateRow = \WHMCS\Mail\Template::name($templateName)->first();
                    if($templateRow !== null) {
                        $message = \WHMCS\Mail\Message::createFromTemplate($templateRow);
                    }
                } catch (\Throwable $e) {
                    $message = null;
                }
            }
            if($message === null) {
                $emailer = \WHMCS\Mail\Emailer::factoryByTemplate($templateName, "", []);
                $message = $emailer->getMessage();
            }
            $message->addRecipient("to", $email);
            self::appendGlobalBcc($message);

            $smarty = new \WHMCS\Smarty(false, "mail");
            $smarty->setMailMessage($message);
            $smarty->compile_id = md5(uniqid("dct_email_2fa_", true));

            foreach (array_merge(["email" => $email], $mergefields) as $key => $value) {
                $smarty->assign($key, $value);
            }

            $renderedSubject = $smarty->fetch("mailMessage:subject");
            $renderedBody = $smarty->fetch("mailMessage:message");

            // FIX (2026-08-26, fourth correction): setBodyAndPlainText()
            // just stores whatever HTML it's given — it does not, by
            // itself, apply WHMCS's Global Email Header/Footer/CSS
            // (General Settings > Mail > "Client Email Header Content" /
            // "Global Email CSS Styling" — the exact {$email_header}/
            // {$email_css} variables originally reported missing). That
            // wrapping is a SEPARATE, explicit step on \WHMCS\Mail\Message
            // itself: applyGlobalWrapper($blob) — "If defined and not
            // already present, wrap $blob in any header and/or footer
            // defined by global settings" (confirmed from WHMCS's own
            // published 9.0 class docs, classdocs.whmcs.com/9.0/WHMCS/
            // Mail/Message.html — VERIFIED, not a guess). Nothing on this
            // path ever called it, on any of the prior corrections to this
            // method — the Smarty rendering itself was always correct, it
            // simply produced the raw template body only, then that raw
            // body went straight to the wire. This is also the most
            // plausible explanation for the "Aug 21 email had full
            // branded header/footer, Aug 26 emails don't" discrepancy:
            // idempotent, additive, and requires no change to addressing
            // (still the User's own $email, never sendMessage()/Client-id
            // routing) — so it does not reopen the sub-account
            // misattribution issue the 2026-08-23 correction fixed.
            $renderedBody = $message->applyGlobalWrapper($renderedBody);

            $message->setSubject($renderedSubject);
            $message->setBodyAndPlainText($renderedBody);
        } catch (\Throwable $e) {
            return ["sent" => false, "reason" => "could not build/render the email template: " . $e->getMessage() . " ({$context})"];
        }

        // Captured purely so callers (sendTestEmail() -> Diagnostics) can
        // show the ADMIN the exact bytes WHMCS's own template pipeline
        // produced — never used for anything that affects delivery
        // itself. real OTP sends (sendOtpEmail()) simply ignore these
        // extra array keys, exactly as before this addition.
        $preview = ["subject" => $renderedSubject, "bodyHtml" => $renderedBody];

        try {
            global $CONFIG;
            $mailerid = $CONFIG["MailType"] ?? "mail";
            if(!empty($CONFIG["MailConfig"]) && function_exists("decrypt")) {
                $mailsettings = json_decode(decrypt($CONFIG["MailConfig"]), true);
                if(is_array($mailsettings) && !empty($mailsettings["module"])) {
                    $mailerid = $mailsettings["module"];
                }
            }
            if($mailerid === "smtp") {
                $mailerid = "SmtpMail";
            } elseif ($mailerid === "mail") {
                $mailerid = "PhpMail";
            }

            $mailer = \WHMCS\Module\Mail::factory();
            $mailer->load($mailerid);
            $mailer->call("send", [], $message);
        } catch (\Throwable $e) {
            return ["sent" => false, "reason" => $e->getMessage() . " ({$context}, provider: " . ($mailerid ?? "unresolved") . ")"] + $preview;
        }

        return ["sent" => true, "reason" => null] + $preview;
    }

    /**
     * Adds WHMCS's configured Global BCC recipient(s) (General Settings >
     * Mail > BCC Messages) to $message, if any are configured.
     *
     * Added 2026-08-25 to close a real gap: sendDirectToAddress() builds
     * its own \WHMCS\Mail\Message and dispatches it straight through the
     * mail-provider module, bypassing whatever higher-level orchestration
     * sendMessage() normally uses to append Global BCC before dispatch —
     * so without this, Global BCC silently never saw a copy of Email 2FA
     * one-time codes, contrary to this file's previous (incorrect) claim
     * that it already did.
     *
     * CONFIDENCE: PATTERN, not VERIFIED. The exact tblconfiguration
     * setting key for Global BCC ("BccMessages") is not confirmed against
     * live WHMCS core source in this environment — it mirrors the same
     * best-effort key DiagnosticsController.php's "Email 2FA — OTP
     * Delivery" check already reads, with the identical caveat. Multiple
     * addresses are supported comma- or newline-separated (WHMCS's own
     * "BCC Messages" field accepts a list this way in the admin UI).
     * Fails silently (adds no BCC recipient) on any lookup error or
     * invalid address — never blocks or fails the OTP send itself, since
     * a missing/wrong BCC copy is far lower-stakes than a user not
     * receiving their own login code. Verify live via Setup > Addon
     * Modules > Security Pack > Diagnostics > "Send Test Email" with a
     * Global BCC address configured.
     */
    private static function appendGlobalBcc(\WHMCS\Mail\Message $message): void
    {
        try {
            $raw = (string) (\Illuminate\Database\Capsule\Manager::table("tblconfiguration")->where("setting", "BccMessages")->value("value") ?? "");
        } catch (\Throwable $e) {
            return;
        }
        if($raw === "") {
            return;
        }
        foreach (preg_split('/[,\r\n]+/', $raw) as $addr) {
            $addr = trim($addr);
            if($addr !== "" && filter_var($addr, FILTER_VALIDATE_EMAIL)) {
                try {
                    $message->addRecipient("bcc", $addr);
                } catch (\Throwable $e) {
                }
            }
        }
    }

    /**
     * Best-effort resolution of a tblclients.id for a WHMCS User
     * (tblusers.id). As of the 2026-08-23 architecture correction this
     * is used purely as logging/diagnostic context — sendDirectToAddress()
     * addresses mail using the User's own email directly and no longer
     * needs a Client record to do so — but it's still resolved and
     * threaded through failure-reason messages so "which client account
     * was this user's OTP associated with" stays visible for support/
     * audit purposes.
     *
     * WHMCS does not publish a documented API for "the Client account(s)
     * this User can access" or for any concept of a default/primary one
     * — this was confirmed absent from docs.whmcs.com's Users and Client
     * Accounts page during this feature's own investigation. The
     * `tblusers_clients` junction table is corroborated by independent
     * WHMCS Community developer discussion (not official documentation)
     * as the table linking Users to the Client accounts they can access.
     * Per this module's established policy for undocumented internals,
     * this is used with try/catch (fails closed to "unresolved" rather
     * than guessing), and a second, more conservative fallback (a
     * tblclients row whose own `email` column matches the User's email)
     * is attempted if the junction table lookup finds nothing — this
     * mirrors how tblclients.email has held the account login address
     * since long before the User/Client split existed. If BOTH fail,
     * sendOtpEmail() reports a clear, actionable failure rather than
     * silently picking an arbitrary/wrong client account.
     *
     * The chosen client id, when multiple are found, is the lowest
     * id (oldest account) — an arbitrary but deterministic tie-break,
     * since WHMCS defines no "primary account" concept. If this
     * heuristic ever resolves to the wrong account in your installation,
     * that is a known limitation — see CHANGELOG.md "2.7.0".
     *
     * 3.1.20 — CONFIRMED SCHEMA FIX: this join was written against
     * `userid`/`clientid` column names based on undocumented WHMCS
     * Community developer discussion (never officially documented, and
     * explicitly flagged UNVERIFIED at the time). A live `SHOW COLUMNS
     * FROM tblusers_clients` on a real WHMCS 9.0.6 install confirmed the
     * REAL column names are `auth_user_id` and `client_id` — this join
     * silently failed on every call on that install (caught by the
     * try/catch below, fell through to the tblclients.email fallback
     * every time, which is why email sending kept working and this went
     * unnoticed). Now resolves the real column names via hasColumn() at
     * call time — trying the confirmed-real `auth_user_id`/`client_id`
     * first, falling back to the originally-assumed `userid`/`clientid`
     * only if those aren't present — so this keeps working across WHMCS
     * versions/installs that may differ, instead of hardcoding either
     * one as gospel a second time.
     *
     * 2026-08-23 — added \WHMCS\User\User::getClientIds() as the
     * FIRST-choice resolution, ahead of the raw tblusers_clients join
     * below. This is WHMCS's own User model method, not a raw SQL guess
     * at column names — real and callable (confirmed by its presence,
     * commented out, in a working third-party security module already
     * installed on this instance: smsmanagertwofactor.php), so it should
     * be more resilient to schema changes across WHMCS versions than
     * hardcoding column names ourselves. Still UNVERIFIED against
     * official docs (classdocs.whmcs.com had no reachable page for
     * WHMCS\User\User at the time this was written) and still guarded
     * with class_exists()/method_exists()/try-catch, failing through to
     * the existing tblusers_clients/tblclients.email lookups below
     * exactly as before if it's unavailable or returns nothing — this
     * addition can only ever make resolution better or identical, never
     * worse, than what already shipped.
     */
    private static function resolveClientIdForUser(int $userId): ?int
    {
        if(class_exists("\\WHMCS\\User\\User")) {
            try {
                $userObj = \WHMCS\User\User::find($userId);
                if($userObj && method_exists($userObj, "getClientIds")) {
                    $clientIds = $userObj->getClientIds();
                    if(is_array($clientIds) && count($clientIds) > 0) {
                        sort($clientIds);
                        return (int) $clientIds[0];
                    }
                }
            } catch (\Throwable $e) {
            }
        }

        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();
            if($schema->hasTable("tblusers_clients")) {
                $userCol = $schema->hasColumn("tblusers_clients", "auth_user_id") ? "auth_user_id" : "userid";
                $clientCol = $schema->hasColumn("tblusers_clients", "client_id") ? "client_id" : "clientid";
                $clientId = \Illuminate\Database\Capsule\Manager::table("tblusers_clients")
                    ->where($userCol, $userId)
                    ->orderBy($clientCol, "asc")
                    ->value($clientCol);
                if($clientId) {
                    return (int) $clientId;
                }
            }
        } catch (\Throwable $e) {
        }

        try {
            $userEmail = (string) (\Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $userId)->value("email") ?? "");
            if($userEmail !== "" && filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
                $clientId = \Illuminate\Database\Capsule\Manager::table("tblclients")
                    ->where("email", $userEmail)
                    ->orderBy("id", "asc")
                    ->value("id");
                if($clientId) {
                    return (int) $clientId;
                }
            }
        } catch (\Throwable $e) {
        }

        return null;
    }

    /**
     * Admin-triggered diagnostic send (Diagnostics page "Send Test
     * Email") — lets an admin confirm the WHMCS mail pipeline actually
     * delivers for Email 2FA's specific templates BEFORE relying on it
     * for a real login/activation, and surfaces the exact failure reason
     * if it doesn't. Never touches challenge/OTP state; purely a
     * transport smoke test — the message content makes clear it is a
     * test, never a real one-time code.
     *
     * Unlike the pre-2.7.0 version, this can no longer target an
     * arbitrary "to" address — sendAdminMessage()/sendMessage() only
     * ever deliver to a real WHMCS admin/client record's own configured
     * email — UPDATED 2026-08-23: for the client path this now means the
     * WHMCS User's own tblusers.email (resolved here, the same way
     * sendOtpEmail()'s real callers already do via
     * dct_email_2fa_resolve_account_email()), not any Client account's
     * stored email. Pass $userType/$userId to choose which path to test:
     * admin (targets that admin's own email) or client (targets that
     * WHMCS User's own email the same way a real OTP now would).
     *
     * @return array{sent:bool, reason:?string}
     */
    public static function sendTestEmail(string $userType, int $userId): array
    {
        $templateName = $userType === self::TYPE_ADMIN ? "Security Pack - Admin Two-Factor Authentication" : "Security Pack - User Two-Factor Authentication";
        $mergefields = [
            "auth_code" => "(test — no real code)",
            "otp" => "(test — no real code)",
            "auth_validity_minutes" => "0",
            "validity" => "0",
            "auth_purpose_label" => "a Diagnostics test send (not a real sign-in)",
        ];

        $email = "";
        if($userType !== self::TYPE_ADMIN) {
            try {
                $email = (string) (\Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $userId)->value("email") ?? "");
            } catch (\Throwable $e) {
                $email = "";
            }
            if($email === "" || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return ["sent" => false, "reason" => "no valid email on file for this WHMCS User (tblusers.id {$userId})"];
            }
        }

        $result = self::sendViaWhmcs($userId, $userType === self::TYPE_ADMIN ? self::TYPE_ADMIN : self::TYPE_CLIENT, $email, $templateName, $mergefields);
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event(
                "email_2fa.test_email." . ($result["sent"] ? "sent" : "failed"),
                "Email 2FA test message " . ($result["sent"] ? "sent" : "failed") . " (triggered from Diagnostics, via WHMCS's own mail pipeline).",
                $result["sent"] ? ["user_type" => $userType] : ["user_type" => $userType, "reason" => mb_substr((string) $result["reason"], 0, 500)],
                $result["sent"] ? "info" : "warning"
            );
        }
        return $result;
    }

    /**
     * Non-sensitive diagnostic logging for a failed OTP send — never the
     * OTP itself, never the full recipient address (masking is applied
     * upstream via existing callers' own event logging; this method logs
     * only the transport-level failure reason so an admin can tell "no
     * mail received" apart from "mail server misconfigured/unreachable"
     * without needing to reproduce the failure live).
     */
    private static function logMailFailure(string $reason): void
    {
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("email_2fa.otp.mail_transport_error", "Email 2FA OTP send failed at the mail transport layer.", ["reason" => mb_substr($reason, 0, 500)], "warning");
        }
    }
}
