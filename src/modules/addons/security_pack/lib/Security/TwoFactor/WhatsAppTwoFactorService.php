<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

use WHMCS\Module\Addon\Security_Pack\Security\RateLimiter;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\DctWhatsAppNotificationsBridge;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\DctWhatsAppTwoFactorLogBridge;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0/3.1 — DCTLAB WhatsApp Two-Factor Authentication
 * (Section 9/10/11).
 *
 * Structurally parallel to Email2faService (same challenge/attempt/
 * resend/rate-limit discipline) but for WhatsApp OTP delivery — reuses
 * OtpEngine for every clamp/generate/hash/verify decision (Section 10:
 * "these values should reuse the centralized 2FA configuration where
 * possible rather than being duplicated per provider") and the EXISTING
 * RateLimiter (never a second one). As of 3.1, all DCTLAB WhatsApp
 * sending is isolated in DctWhatsAppNotificationsBridge — a real
 * integration with the actual DCTLAB WhatsApp platform
 * (github.com/dctlab/WHMCS-WhatsApp-Notifications, the
 * "dct_whatsapp_notifications" addon) — this class never talks to that
 * addon directly.
 */
class WhatsAppTwoFactorService
{
    public const TYPE_CLIENT = "client";
    public const TYPE_ADMIN = "admin";
    public const PURPOSE_ACTIVATION = "activation";
    public const PURPOSE_LOGIN = "login";

    public static function getConfig(int $userId, string $userType)
    {
        try {
            return \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa")
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
     * Best-effort resolution of a candidate WhatsApp number from the
     * account's OWN records (Section 11 — never a client-supplied
     * $_POST['phone']/['mobile'] for the destination). Returns null if
     * none is on file; the caller must then collect+verify a new number
     * explicitly rather than silently switching the destination.
     */
    public static function resolveAccountPhone(int $userId, string $userType): ?string
    {
        try {
            if($userType === self::TYPE_ADMIN) {
                $phone = \Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $userId)->value("phonenumber");
                return $phone ? (string) $phone : null;
            }
            $clientId = self::resolveClientIdForUser($userId);
            if($clientId === null) {
                return null;
            }
            $phone = \Illuminate\Database\Capsule\Manager::table("tblclients")->where("id", $clientId)->value("phonenumber");
            return $phone ? (string) $phone : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): given
     * every distinct candidate `tblclients.id` a resolution step found
     * for a WHMCS User, decides whether it is safe to treat one of them
     * as THE client — only when there is EXACTLY one distinct candidate.
     *
     * BUG FIX (2026-09-23 — WhatsApp 2FA activation offered/sent a code
     * to a DIFFERENT client's phone number): reported case — WHMCS User
     * #666043 (an owner/authorized user under Client #666308, "Rajesh
     * jayadevan", own phone +91.9846560111) opened "Enable Two-Factor
     * Authentication" and the modal showed a code already sent to a
     * number ending "...994" — the stored phone number of an entirely
     * unrelated Client #666250 ("Shabeer Ahammed" / Orbiz Creativez Pvt
     * Ltd, +91.9020044994). Root cause: resolveClientIdForUser() used to
     * take the raw DB result of `->orderBy($clientCol, "asc")->value(...)`
     * — the numerically LOWEST matching client id — whenever the
     * `tblusers_clients` junction linked this User to MORE THAN ONE
     * Client account (a real, supported WHMCS scenario — e.g. a shared
     * developer/agency User account added as an authorized user on
     * several unrelated clients' profiles). #666250 < #666308, so the
     * unrelated, numerically-lower client silently won, even though
     * nothing about this specific 2FA request was actually for that
     * account. The same "lowest id silently wins" shortcut applied to
     * the email-match fallback too (two different `tblclients` rows can
     * share the same email address in WHMCS — account uniqueness is not
     * enforced on that column).
     *
     * This directly violates resolveAccountPhone()'s OWN documented
     * contract just above it in this file — "Returns null if none is on
     * file; the caller must then collect+verify a new number explicitly
     * rather than silently switching the destination" — the
     * implementation silently switched to an ambiguous, arbitrary match
     * instead of honoring that contract. Fixed by fetching every
     * DISTINCT candidate (not just the first, ordered one) and only ever
     * returning a client id when exactly one distinct candidate exists —
     * multiple real matches now fail soft (null), the same well-tested
     * behavior already in place for "no match at all", rather than
     * guessing. A User genuinely linked to more than one Client account
     * simply has no phone number resolved for WhatsApp 2FA purposes
     * (activation shows "No phone number is on file for your account")
     * until an administrator disambiguates — never a silent, wrong
     * delivery to an unrelated client's number.
     */
    public static function pickUnambiguousClientId(array $candidateIds): ?int
    {
        $distinct = array_values(array_unique(array_map("intval", array_filter($candidateIds, static function ($id) {
            return (int) $id > 0;
        }))));
        return count($distinct) === 1 ? $distinct[0] : null;
    }

    /**
     * Same resolution strategy as Email2faService::resolveClientIdForUser
     * — reused via the same corroborated evidence (tblusers_clients
     * junction, then a tblclients.email match), not re-derived
     * independently, so both providers agree on "which client account
     * does this WHMCS User map to".
     *
     * 3.1.20: same confirmed-real-schema fix as
     * Email2faService::resolveClientIdForUser() — a live `SHOW COLUMNS
     * FROM tblusers_clients` proved the real columns are
     * `auth_user_id`/`client_id`, not `userid`/`clientid`. Resolved via
     * hasColumn() at call time rather than hardcoded, same as there.
     *
     * 2026-09-23: now routes every candidate list through
     * pickUnambiguousClientId() above instead of taking the first,
     * lowest-id match — see that method's docblock for the bug this
     * fixes.
     */
    private static function resolveClientIdForUser(int $userId): ?int
    {
        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();
            if($schema->hasTable("tblusers_clients")) {
                $userCol = $schema->hasColumn("tblusers_clients", "auth_user_id") ? "auth_user_id" : "userid";
                $clientCol = $schema->hasColumn("tblusers_clients", "client_id") ? "client_id" : "clientid";
                $candidateIds = \Illuminate\Database\Capsule\Manager::table("tblusers_clients")
                    ->where($userCol, $userId)->pluck($clientCol)->all();
                $clientId = self::pickUnambiguousClientId($candidateIds);
                if($clientId !== null) {
                    return $clientId;
                }
            }
        } catch (\Throwable $e) {
        }
        try {
            $userEmail = (string) (\Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $userId)->value("email") ?? "");
            if($userEmail !== "" && filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
                $candidateIds = \Illuminate\Database\Capsule\Manager::table("tblclients")
                    ->where("email", $userEmail)->pluck("id")->all();
                $clientId = self::pickUnambiguousClientId($candidateIds);
                if($clientId !== null) {
                    return $clientId;
                }
            }
        } catch (\Throwable $e) {
        }
        return null;
    }

    /**
     * Begin enrollment/number-change: creates the config row as PENDING
     * and sends an activation OTP to the CANDIDATE number — the number
     * only becomes the account's trusted WhatsApp 2FA destination after
     * the OTP round-trip succeeds (Section 11: verify-then-activate,
     * never silently switch).
     */
    public static function beginActivation(int $userId, string $userType, string $phone, string $ip, array $settings): array
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa")->updateOrInsert(
                ["user_id" => $userId, "user_type" => $userType],
                ["phone" => $phone, "status" => "pending", "updated_at" => $now, "created_at" => $now]
            );
        } catch (\Throwable $e) {
            return ["status" => "error"];
        }
        return self::createChallenge($userId, $userType, self::PURPOSE_ACTIVATION, $phone, $ip, $settings);
    }

    public static function createChallenge(int $userId, string $userType, string $purpose, string $phone, string $ip, array $settings): array
    {
        $cooldown = OtpEngine::clampResendCooldownSeconds($settings["whatsapp_2fa_resend_cooldown"] ?? 60);
        $maxResends = OtpEngine::clampMaxResends($settings["whatsapp_2fa_max_resends"] ?? 3);
        $length = OtpEngine::clampOtpLength($settings["whatsapp_2fa_length"] ?? 6);
        $validity = OtpEngine::clampValidityMinutes($settings["whatsapp_2fa_minutes"] ?? 10);
        $maxAttempts = OtpEngine::clampMaxAttempts($settings["whatsapp_2fa_max_attempts"] ?? 5);

        $rlKey = "whatsapp2fa_send:" . $userType . ":" . $userId;
        if(!RateLimiter::hit($rlKey, $maxResends + 1, $cooldown * ($maxResends + 1))) {
            return ["status" => "rate_limited", "retry_after" => $cooldown];
        }

        $now = time();
        try {
            $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("purpose", $purpose)
                ->where("status", "pending")->orderBy("id", "DESC")->first();

            if($existing && strtotime((string) $existing->last_sent_at) > 0 && ($now - strtotime((string) $existing->last_sent_at)) < $cooldown) {
                return ["status" => "cooldown", "retry_after" => $cooldown - ($now - strtotime((string) $existing->last_sent_at))];
            }
            if($existing && (int) $existing->resend_count >= $maxResends) {
                return ["status" => "max_resends"];
            }
            if($existing) {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                    ->where("id", $existing->id)->update(["status" => "invalidated"]);
            }

            $otp = OtpEngine::generateOtp($length);
            $expiresAt = date("Y-m-d H:i:s", $now + ($validity * 60));
            $newChallengeId = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")->insertGetId([
                "user_id" => $userId, "user_type" => $userType, "purpose" => $purpose,
                "otp_hash" => OtpEngine::hashOtp($otp), "expires_at" => $expiresAt,
                "attempt_count" => 0, "max_attempts" => $maxAttempts,
                "resend_count" => $existing ? ((int) $existing->resend_count + 1) : 0,
                "last_sent_at" => date("Y-m-d H:i:s", $now), "ip" => $ip, "status" => "pending",
                "created_at" => date("Y-m-d H:i:s", $now),
            ]);
        } catch (\Throwable $e) {
            return ["status" => "error"];
        }

        $sent = self::sendOtpWhatsApp($userId, $userType, $phone, $otp, $validity);

        // 3.1.28 — WhatsApp resend defect fix: a failed delivery must not
        // destroy a still-valid, previously-sent code nor consume a
        // resend-budget slot for a code the user never received (WhatsApp
        // delivery is a real, documented third-party failure mode — see
        // DctWhatsAppNotificationsBridge's own docblock). This is a
        // best-effort, fail-soft compensating rollback ONLY — it never
        // throws past this point, never touches the outer RateLimiter gate
        // above (abuse protection is unchanged), and never re-attempts
        // delivery itself. It restores exactly the pre-attempt state: the
        // newly-inserted row is invalidated, and if a prior challenge
        // existed it is restored to "pending" with its original
        // resend_count/last_sent_at untouched, so it remains usable.
        if(!$sent) {
            try {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                    ->where("id", $newChallengeId)->update(["status" => "invalidated"]);
                if($existing) {
                    \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                        ->where("id", $existing->id)->update(["status" => "pending"]);
                }
            } catch (\Throwable $e) {
            }
        }

        if(function_exists("security_pack_record_event")) {
            security_pack_record_event(
                $existing ? "2fa.otp.resent" : "2fa.whatsapp.sent",
                "WhatsApp 2FA verification code " . ($existing ? "resent" : "sent") . " (" . $purpose . ").",
                ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose, "delivered" => $sent]
            );
        }

        // DCTLAB WhatsApp Notifications addon's own "Client Logs Review" —
        // producer-only, fail-soft, existing table/event vocabulary only.
        // See DctWhatsAppTwoFactorLogBridge's class docblock.
        DctWhatsAppTwoFactorLogBridge::logCodeSent($userType, $userId, $sent, $purpose, $existing !== null, $ip);

        return ["status" => $sent ? "sent" : "send_failed", "expires_in" => $validity * 60];
    }

    public static function verify(int $userId, string $userType, string $purpose, string $candidateOtp, string $ip, array $settings): array
    {
        $rlKey = "whatsapp2fa_verify:" . $userType . ":" . $userId . ":" . $ip;
        if(!RateLimiter::hit($rlKey, 10, 300)) {
            return ["status" => "rate_limited"];
        }

        try {
            $challenge = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("purpose", $purpose)
                ->orderBy("id", "DESC")->first();
        } catch (\Throwable $e) {
            DctWhatsAppTwoFactorLogBridge::logVerifyFailed($userType, $userId, "no pending code", $purpose, $ip);
            return ["status" => "no_challenge"];
        }
        if(!$challenge) {
            DctWhatsAppTwoFactorLogBridge::logVerifyFailed($userType, $userId, "no pending code", $purpose, $ip);
            return ["status" => "no_challenge"];
        }

        $now = time();
        $result = OtpEngine::evaluateOtpSubmission(
            (string) $candidateOtp,
            (string) $challenge->otp_hash,
            (string) $challenge->status,
            strtotime((string) $challenge->expires_at) ?: 0,
            (int) $challenge->attempt_count,
            (int) $challenge->max_attempts,
            $now
        );

        try {
            if($result === "valid") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                    ->where("id", $challenge->id)->where("attempt_count", (int) $challenge->attempt_count)
                    ->update(["status" => "consumed", "attempt_count" => (int) $challenge->attempt_count + 1]);
            } elseif($result === "invalid") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                    ->where("id", $challenge->id)->where("attempt_count", (int) $challenge->attempt_count)
                    ->update(["attempt_count" => (int) $challenge->attempt_count + 1]);
            } elseif($result === "expired" && $challenge->status === "pending") {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")->where("id", $challenge->id)
                    ->update(["status" => "expired"]);
            }
        } catch (\Throwable $e) {
        }

        if(function_exists("security_pack_record_event")) {
            if($result === "valid") {
                security_pack_record_event("2fa.verification.success", "WhatsApp 2FA verification succeeded (" . $purpose . ").", ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose, "method" => "whatsapp"]);
            } elseif(in_array($result, ["invalid", "expired", "locked"], true)) {
                security_pack_record_event("2fa.verification.failed", "WhatsApp 2FA verification failed (" . $result . ", " . $purpose . ").", ["user_id" => $userId, "user_type" => $userType, "purpose" => $purpose, "reason" => $result, "method" => "whatsapp"], "warning");
            }
        }

        // DCTLAB WhatsApp Notifications addon's own "Client Logs Review" —
        // producer-only, fail-soft, existing table/event vocabulary only.
        // Reason wording deliberately mirrors dct2fa_log_event()'s own
        // verify_failed call sites exactly ("code expired" / "too many
        // attempts" / "incorrect code").
        if($result === "valid") {
            DctWhatsAppTwoFactorLogBridge::logVerifySuccess($userType, $userId, $purpose, $ip);
        } elseif($result === "expired") {
            DctWhatsAppTwoFactorLogBridge::logVerifyFailed($userType, $userId, "code expired", $purpose, $ip);
        } elseif($result === "locked") {
            DctWhatsAppTwoFactorLogBridge::logVerifyFailed($userType, $userId, "too many attempts", $purpose, $ip);
        } elseif($result === "invalid") {
            DctWhatsAppTwoFactorLogBridge::logVerifyFailed($userType, $userId, "incorrect code", $purpose, $ip);
        }

        return ["status" => $result];
    }

    public static function completeActivation(int $userId, string $userType, string $actor = "user"): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa")
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "active", "activated_at" => $now, "last_verified_at" => $now, "updated_at" => $now]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.enabled", "WhatsApp Two-Factor Authentication enabled.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor, "method" => "whatsapp"]);
        }
    }

    public static function disable(int $userId, string $userType, string $actor = "user"): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa")
                ->where("user_id", $userId)->where("user_type", $userType)
                ->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")
                ->where("user_id", $userId)->where("user_type", $userType)->where("status", "pending")
                ->update(["status" => "invalidated"]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.disabled", "WhatsApp Two-Factor Authentication disabled.", ["user_id" => $userId, "user_type" => $userType, "actor" => $actor, "method" => "whatsapp"]);
        }
    }

    public static function purgeExpired(int $challengeRetentionDays = 7): void
    {
        $cutoff = date("Y-m-d H:i:s", time() - ($challengeRetentionDays * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa_challenges")->where("created_at", "<", $cutoff)->delete();
        } catch (\Throwable $e) {
        }
    }

    /**
     * As of 3.1, delegates to DctWhatsAppNotificationsBridge — the real
     * DCTLAB WhatsApp integration. For a client login, resolves the real
     * tblclients.id via the existing resolveClientIdForUser() heuristic
     * (never trusts $userId as-is — see that method's doc comment) so the
     * bridge can use the addon's customizable, client-aware notification
     * template; admins always use the bridge's plain-message path.
     */
    private static function sendOtpWhatsApp(int $userId, string $userType, string $phone, string $otp, int $validityMinutes): bool
    {
        $clientId = ($userType === self::TYPE_CLIENT) ? self::resolveClientIdForUser($userId) : null;
        $sent = DctWhatsAppNotificationsBridge::sendCode($userType, $clientId, $phone, $otp, $validityMinutes);
        if(!$sent && function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.otp.mail_transport_error", "WhatsApp 2FA OTP send failed — DCTLAB WhatsApp delivery did not succeed (see the dct_whatsapp_notifications addon's own module log for details).", ["method" => "whatsapp"], "warning");
        }
        return $sent;
    }
}
