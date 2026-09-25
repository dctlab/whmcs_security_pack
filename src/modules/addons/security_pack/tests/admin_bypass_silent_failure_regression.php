<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 "Administrator
 * Manual Bypass still not working" incident (second pass, after the
 * dct_totp_native login-side integration fix landed and the problem
 * persisted).
 *
 * CONFIRMED LIVE: an admin filled in the "Administrator Manual Bypass"
 * form (WHMCS User ID, Duration, Reason) and clicked "Confirm Bypass" —
 * no error was shown, but no row ever appeared in the table below.
 *
 * ROOT CAUSE: TwoFactorBypassService::createAdminBypass()'s INSERT
 * writes a `method` column that is only ever added to the live database
 * by security_pack_ensure_tables() — which WHMCS only calls from
 * _activate() (fresh installs) or _upgrade() (only fires when WHMCS
 * itself detects the module's config() version number has increased
 * since its last recorded activation). This project's entire delivery
 * model is manual FTP upload of updated files — replacing files alone
 * does NOT trigger WHMCS's upgrade detection, so a schema change bundled
 * in a delivered fix can sit fully coded on disk while the live database
 * never actually gains the column it needs. When that happens, the
 * INSERT throws an "Unknown column" error that was silently swallowed by
 * createAdminBypass()'s own try/catch — while
 * TwoFactorController::bypass() (the form handler) set
 * "Bypass created." UNCONDITIONALLY regardless of whether anything
 * actually persisted. Silent DB failure + an unconditional success
 * message is exactly what made this invisible until directly
 * investigated.
 *
 * FIX (two parts, both asserted below):
 *  1. TwoFactorBypassService::ensureMethodColumn() self-heals the
 *     `method` column immediately before every write this class
 *     performs (createAdminBypass() AND grantSameIpBypass()) — the exact
 *     same hasColumn()-guarded migration security_pack_ensure_tables()
 *     already contains, just also runnable lazily so it no longer
 *     depends on WHMCS's upgrade hook ever firing.
 *  2. createAdminBypass() (both the TwoFactorBypassService one and the
 *     TwoFactorAuthenticationService pass-through) now returns bool
 *     (true only on a real persisted row) instead of void, and
 *     TwoFactorController::bypass() now reports the REAL outcome to the
 *     admin instead of an unconditional "Bypass created."
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging a new regression test into tests/run.php
 * mid-incident (tests/run.php's own baseline was updated separately for
 * the one pre-existing assertion this signature change touched — see
 * that file's own diff). Run on its own:
 *
 *   php tests/admin_bypass_silent_failure_regression.php
 *
 * No live database is available in this CLI runner, so these are
 * source-level checks, same technique as this project's other
 * standalone regression files.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function absf_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function absf_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

// --- TwoFactorBypassService: self-healing schema ----------------------

$bypassServiceSource = absf_src("lib/Security/TwoFactor/TwoFactorBypassService.php");

absf_assert(
    "TwoFactorBypassService::ensureMethodColumn() exists and checks hasTable() before hasColumn() (never assumes the table itself exists)",
    (bool) preg_match('/private static function ensureMethodColumn\(\): void\s*\{[\s\S]*?hasTable\(self::TABLE\)[\s\S]*?hasColumn\(self::TABLE, "method"\)/', $bypassServiceSource),
    $failures,
    $passed
);
absf_assert(
    "ensureMethodColumn() adds the EXACT same column definition security_pack_ensure_tables() already contains (string(20) nullable, positioned after \"scope\") — no schema drift between the two migration paths",
    strpos($bypassServiceSource, '$table->string("method", 20)->nullable()->after("scope");') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() calls self::ensureMethodColumn() before attempting its INSERT (after clearing \$lastError and logging the attempt — see the third-pass diagnostic assertions below)",
    (bool) preg_match('/public static function createAdminBypass\([^)]*\): bool\s*\{\s*self::\$lastError = null;[\s\S]{0,1200}self::ensureMethodColumn\(\);/', $bypassServiceSource),
    $failures,
    $passed
);
absf_assert(
    "grantSameIpBypass() also calls self::ensureMethodColumn() first — the same fix applies to the OTHER write path in this class, not just the admin-manual one",
    (bool) preg_match('/public static function grantSameIpBypass\([^)]*\): void\s*\{\s*self::ensureMethodColumn\(\);/', $bypassServiceSource),
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass()'s signature was widened from void to bool",
    strpos($bypassServiceSource, 'public static function createAdminBypass(int $userId, string $userType, int $days, string $actorLabel, string $reason = "", string $method = "manual", string $eventPrefix = "2fa"): bool') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() captures the real exception message into \$lastError and still returns false on a caught DB error (was: silent void return, indistinguishable from success)",
    strpos($bypassServiceSource, 'self::$lastError = $e->getMessage();') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() returns true only after the security_pack_record_event() call on the success path — i.e. only when the INSERT above it did not throw",
    (bool) preg_match('/security_pack_record_event\(\$eventPrefix \. "\.bypass\.created", "Administrator bypass created[\s\S]{0,400}\n\s*\}\s*return true;/', $bypassServiceSource),
    $failures,
    $passed
);

// --- Third pass (2026-08-27): getLastError() + unconditional Activity
// Log entries, so the NEXT report (if any) comes with hard server-side
// evidence instead of another round of guessing --------------------

absf_assert(
    "TwoFactorBypassService exposes getLastError() so callers can surface the real captured exception message, not a generic string",
    strpos($bypassServiceSource, 'public static function getLastError(): ?string') !== false
        && strpos($bypassServiceSource, 'return self::$lastError;') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() unconditionally logs the ATTEMPT to WHMCS's Activity Log via bare logActivity() (not gated behind security_pack_record_event(), which itself depends on addon health) — evidence exists even if the on-page banner is missed",
    strpos($bypassServiceSource, 'logActivity("[security_pack] Administrator Manual Bypass attempted for') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() logs the FAILURE outcome (including the real exception message) to the Activity Log when the insert throws",
    strpos($bypassServiceSource, 'logActivity("[security_pack] Administrator Manual Bypass creation FAILED for') !== false,
    $failures,
    $passed
);
absf_assert(
    "createAdminBypass() logs the SUCCESS outcome to the Activity Log too, so a successful attempt is just as findable as a failed one",
    strpos($bypassServiceSource, 'logActivity("[security_pack] Administrator Manual Bypass created for') !== false,
    $failures,
    $passed
);

// --- TwoFactorAuthenticationService: propagates the real result -------

$tfaServiceSource = absf_src("lib/Security/TwoFactor/TwoFactorAuthenticationService.php");
absf_assert(
    "TwoFactorAuthenticationService::createAdminBypass() now returns bool and actually returns (propagates) TwoFactorBypassService's real result, rather than a fire-and-forget void call",
    (bool) preg_match('/public static function createAdminBypass\([^)]*\): bool\s*\{\s*return TwoFactorBypassService::createAdminBypass\(/', $tfaServiceSource),
    $failures,
    $passed
);

// --- TwoFactorController::bypass(): reports the REAL outcome ----------

$controllerSource = absf_src("lib/Admin/TwoFactorController.php");
absf_assert(
    "TwoFactorController::bypass() captures createAdminBypass()'s return value instead of discarding it",
    strpos($controllerSource, '$created = TwoFactorAuthenticationService::createAdminBypass($userId, $userType, $days, "admin#" . $adminId, $reason);') !== false,
    $failures,
    $passed
);
absf_assert(
    "TwoFactorController::bypass() only sets the \"Bypass created.\" success message when \$created is actually true — the previous unconditional success message (root cause of this bug going unnoticed) is gone",
    strpos($controllerSource, "if(\$created) {\n                \$_SESSION[\"nnm_2fa_success\"] = \"Bypass created.\";\n            } else {") !== false,
    $failures,
    $passed
);
absf_assert(
    "the \"could not create\" error path surfaces TwoFactorBypassService::getLastError()'s REAL captured message rather than a generic string, and still points the admin at the Activity Log",
    strpos($controllerSource, "\$lastError = TwoFactorBypassService::getLastError();") !== false
        && strpos($controllerSource, "Could not create the bypass") !== false
        && strpos($controllerSource, "This attempt was also logged to Admin -> Utilities -> Logs -> Activity Log.") !== false,
    $failures,
    $passed
);
absf_assert(
    "index()'s CSRF/POST guard also logs to the Activity Log when it blocks a state-changing action (e.g. an expired bypass form token) — so a report of \"no error, nothing happened\" can be distinguished from bypass() itself silently failing",
    strpos($controllerSource, "logActivity(\"[security_pack] Two-Factor Authentication admin action \\\"\" . \$action . \"\\\" was blocked: CSRF token missing or invalid.\");") !== false,
    $failures,
    $passed
);

// --- Fourth pass (2026-08-27): findActiveAdminBypass() raw-row dump ---
// Creation was confirmed working via the Activity Log, but a subsequent
// lookup for the SAME user_id+user_type found nothing at login time AND
// in the admin panel's own listing. This diagnostic logs the raw,
// unfiltered set of every row for that identity so the next report tells
// us whether the row exists at all, or exists with unexpected values.

absf_assert(
    "findActiveAdminBypass() logs the RAW unfiltered row set for the exact (user_id, user_type) being looked up — not just the filtered admin_manual/unrevoked result — so a report of \"nothing found\" can distinguish \"no row exists at all\" from \"a row exists but doesn't match the filter\"",
    strpos($bypassServiceSource, 'DIAGNOSTIC: findActiveAdminBypass(user_id=" . $userId . ", user_type=" . $userType . ") — filtered query found') !== false
        && strpos($bypassServiceSource, '->where("user_id", $userId)->where("user_type", $userType)->get();') !== false,
    $failures,
    $passed
);
absf_assert(
    "findActiveAdminBypass()'s diagnostic reports \"NONE AT ALL\" when zero rows exist for the identity, distinct from reporting rows that exist but don't match — so the log line itself is unambiguous about which case occurred",
    strpos($bypassServiceSource, '(count($dump) ? implode(" | ", $dump) : "NONE AT ALL")') !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Admin-bypass silent-failure regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
