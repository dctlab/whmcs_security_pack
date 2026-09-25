<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — thin wrapper around WHMCS's own `logActivity()`.
 *
 * This module is deliberately standalone (see the module's README —
 * "no dependency on any addon module"), so it does not assume any
 * third-party event/audit table exists. `logActivity()` is a native
 * WHMCS core function, always available, and writes into WHMCS's own
 * System Activity Log (Utilities > Logs > Activity Log) — the correct,
 * already-existing place for this on an install with no Security Pack
 * (or similar) addon present.
 *
 * NEVER pass a TOTP secret, recovery code, or submitted OTP into this —
 * every call site in this module passes only non-sensitive identifiers
 * (user id/type, event name, generic descriptions).
 */
class EventLog
{
    public static function record(string $description, int $userId = 0): void
    {
        try {
            if (function_exists("logActivity")) {
                logActivity("[dct_totp_native] " . $description, $userId);
            }
        } catch (\Throwable $e) {
            // Logging must never break the auth flow it is describing.
        }
    }
}
