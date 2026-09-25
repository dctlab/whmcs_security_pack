<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * DctWhatsAppTwoFactorLogBridge
 *
 * Security Pack 3.1.4 — PRODUCER-ONLY integration with the DCTLAB WhatsApp
 * Notifications addon's own "2FA Logs" / "Client Logs Review" screen
 * (Notification Report -> 2FA Logs, `TwoFactorAuthLogsController` +
 * `pages/2fa_logs.tpl` in `modules/addons/dct_whatsapp_notifications`).
 *
 * TABLE OWNERSHIP (non-negotiable, per explicit instruction): the table
 * this class writes to, `mod_lkn_wa2fa_logs`, is OWNED by the reference
 * `modules/security/dct2fa` module (confirmed by reading its real source:
 * `dct2fa_bootstrap()` creates it, `dct2fa_log_event()` writes to it) and
 * READ by `dct_whatsapp_notifications`' own `TwoFactorAuthLogsController`
 * (confirmed by reading the addon's real, cloned source — see the 3.1.0
 * section of project memory for how that source was obtained). Security
 * Pack is a PRODUCER of rows in this table, never its owner:
 *   - This class NEVER calls `Capsule::schema()->create("mod_lkn_wa2fa_logs", ...)`
 *     or any other schema-mutating call against it — no create, no
 *     migrate, no rename, no truncate, no column change.
 *   - If the table does not exist (dct2fa was never installed/activated
 *     on this WHMCS), every write here is a silent, fail-soft no-op — see
 *     write() below. Security Pack's own 2FA state/enforcement is
 *     completely unaffected either way; this class is reporting-only.
 *   - The table's schema/columns/indexes are exactly as dct2fa itself
 *     defines them (`user_type` varchar(10), `user_id` unsigned int,
 *     `event` varchar(30), `ip_address` varchar(64) nullable, `details`
 *     varchar(255) nullable, `created_at` datetime) — never redefined or
 *     duplicated here.
 *
 * EVENT VOCABULARY (non-negotiable): `dct_whatsapp_notifications`'
 * `2fa_logs.tpl` only renders three `event` values with a distinct status
 * badge — `code_sent` / `verify_success` / `verify_failed` (anything else
 * falls through to a generic neutral badge, which is safe but not
 * distinct) — and its own filter dropdown only offers those three. This
 * class therefore NEVER writes any other `event` string; every more
 * specific outcome (code delivery failure, expired code, too many
 * attempts, no pending code, which purpose — activation vs login) is
 * encoded in the free-text `details` column instead, mirroring EXACTLY
 * how dct2fa's own `dct2fa_log_event()` calls already do this (e.g.
 * `dct2fa_log_event($type, $id, 'code_sent', $sent ? 'delivered' :
 * 'delivery failed - check module log')` and `dct2fa_log_event($type,
 * $id, 'verify_failed', 'code expired')`) — this class's `details`
 * strings are deliberately worded the same way for a consistent Client
 * Logs Review reading experience across both the old dct2fa flow (if
 * ever re-enabled) and Security Pack's own dct_whatsapp_2fa flow.
 *
 * WhatsApp "2FA enabled"/"2FA disabled"/administrator manual bypass are
 * DELIBERATELY NOT written here — dct2fa's own real implementation never
 * emits an event for those either (only code_sent/verify_success/
 * verify_failed exist in its vocabulary), and inventing a 4th/5th event
 * string this page's UI does not render distinctly would violate the "do
 * not silently create event names the existing UI cannot display" rule.
 * Those state changes remain fully covered by Security Pack's own
 * `security_pack_record_event()` (`2fa.enabled`/`2fa.disabled`/bypass
 * events), unaffected by any of this.
 *
 * SECURITY: never receives or writes an OTP, an OTP hash, a TOTP secret,
 * a recovery code, or any WhatsApp/Meta/Botms/Baileys credential — the
 * only data passed in is user_type/user_id/a boolean or short reason
 * string/purpose/ip, all already-non-sensitive by the time they reach
 * this class (see WhatsAppTwoFactorService's call sites).
 *
 * FAILURE BEHAVIOR: every public method here is wrapped in try/catch and
 * NEVER throws — a reporting-table write failure (missing table,
 * transient DB error, anything) must never block OTP verification, never
 * cause a login failure, and never surface an exception to the user. A
 * failed write is disclosed via the EXISTING `security_pack_record_event()`
 * Security Events pipeline (a diagnostic-severity entry), not a new
 * reporting/error subsystem.
 */
final class DctWhatsAppTwoFactorLogBridge
{
    private const TABLE = "mod_lkn_wa2fa_logs";

    /**
     * OTP generated and a send was attempted — logs exactly once per
     * actual send attempt (never once per rate-limited/cooldown-blocked
     * call, since those never reach this point in
     * WhatsAppTwoFactorService::createChallenge() — no code was actually
     * generated or sent for those, so nothing to report here, matching
     * "do not fabricate events"). $delivered is the REAL boolean result
     * DctWhatsAppNotificationsBridge/sendOtpWhatsApp() returned — never
     * assumed true merely because a send was attempted.
     */
    public static function logCodeSent(string $userType, int $userId, bool $delivered, string $purpose, bool $isResend, string $ip): void
    {
        $details = ($delivered ? "delivered" : "delivery failed - check module log") . " (" . $purpose . ($isResend ? ", resend" : "") . ")";
        self::write($userType, $userId, "code_sent", $details, $ip);
    }

    public static function logVerifySuccess(string $userType, int $userId, string $purpose, string $ip): void
    {
        self::write($userType, $userId, "verify_success", $purpose !== "" ? "(" . $purpose . ")" : null, $ip);
    }

    /**
     * $reason should be one of the same short, non-sensitive strings
     * dct2fa's own verify_failed calls already use — "no pending code",
     * "code expired", "too many attempts", "incorrect code" — so the
     * Client Logs Review reads identically regardless of which module
     * produced the row. Never the actual submitted/expected OTP value.
     */
    public static function logVerifyFailed(string $userType, int $userId, string $reason, string $purpose, string $ip): void
    {
        $details = $reason . ($purpose !== "" ? " (" . $purpose . ")" : "");
        self::write($userType, $userId, "verify_failed", $details, $ip);
    }

    private static function write(string $userType, int $userId, string $event, ?string $details, string $ip): void
    {
        try {
            if (!\Illuminate\Database\Capsule\Manager::schema()->hasTable(self::TABLE)) {
                // Fail-soft, no-op: dct2fa was never installed/activated
                // on this WHMCS, so its table doesn't exist. Never
                // created/migrated here — see class docblock.
                return;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert([
                "user_type" => $userType,
                "user_id" => $userId,
                "event" => $event,
                "ip_address" => $ip !== "" ? $ip : null,
                "details" => $details,
                "created_at" => date("Y-m-d H:i:s"),
            ]);
        } catch (\Throwable $e) {
            // Never break authentication over a reporting-log write
            // failure — disclose via the EXISTING Security Events
            // pipeline instead of a new error-reporting mechanism.
            if (function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.whatsapp.dctlab_log_write_failed",
                    "Could not write a WhatsApp 2FA activity record to the DCTLAB WhatsApp Notifications addon's own 2FA log (Client Logs Review will be missing this entry) — DCTLAB Security Pack's own 2FA state and Security Events are unaffected.",
                    ["user_id" => $userId, "user_type" => $userType, "event" => $event],
                    "warning"
                );
            }
        }
    }
}
