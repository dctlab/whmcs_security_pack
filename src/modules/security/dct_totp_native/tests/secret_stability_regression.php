<?php

/**
 * dct_totp_native — regression test for the 2026-08-27 incident:
 * entering an incorrect code during "Enable Two-Factor Authentication"
 * changed the displayed "Manual entry secret" / QR code entirely,
 * invalidating whatever the user had already scanned into their
 * authenticator app and guaranteeing every subsequent attempt would also
 * fail.
 *
 * ROOT CAUSE: WHMCS core re-invokes the Security Module's _activate()
 * (dct_totp_native_activate()) after every failed _activateverify()
 * submission, purely to re-render the form with an error message.
 * That function calls Enrollment::beginEnrollment(), which previously
 * generated + stored a brand-new secret unconditionally on every call,
 * with no distinction between "starting a genuinely new enrollment" and
 * "WHMCS re-rendering the same still-pending enrollment after a wrong
 * code."
 *
 * FIX: beginEnrollment() now reuses the existing secret for a still-
 * pending enrollment rather than rotating it. This does not weaken the
 * "never silently activate before verification" guarantee — the row's
 * status stays "pending" either way.
 *
 * Delivered as its own standalone file (this project's convention
 * elsewhere is to never fold a new regression test into an existing
 * suite — applied here too, since this module's own tests/run.php was
 * not part of what was available to inspect when this fix was made; run
 * this alongside it, not merged into it):
 *
 *   php tests/secret_stability_regression.php
 *
 * No live database is available in this CLI runner, so these are
 * source-level checks (regex/substring against the actual shipped file
 * contents) — the same technique this module's own tests/run.php uses
 * throughout for its module-contract checks (per its README).
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function stab_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function stab_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$enrollmentSource = stab_src("lib/Enrollment.php");
$fnStart = strpos($enrollmentSource, "public static function beginEnrollment(");
stab_assert("Enrollment::beginEnrollment() is present", $fnStart !== false, $failures, $passed);
$nextFn = $fnStart !== false ? strpos($enrollmentSource, "public static function", $fnStart + 10) : false;
$fnBody = $fnStart !== false ? substr($enrollmentSource, $fnStart, $nextFn !== false ? $nextFn - $fnStart : null) : "";

stab_assert(
    "beginEnrollment() checks for an existing enrollment via self::getConfig() before deciding whether to mint a new secret",
    strpos($fnBody, "self::getConfig(\$userId, \$userType)") !== false,
    $failures,
    $passed
);
stab_assert(
    "beginEnrollment() only reuses a secret when the existing row's status is \"pending\" (never reuses an already-active or disabled row's secret)",
    (bool) preg_match('/\$existing\s*&&\s*\$existing->status === "pending"/', $fnBody),
    $failures,
    $passed
);
stab_assert(
    "beginEnrollment() decrypts and returns the EXISTING row's secret_encrypted (reuse path) via Totp::decryptSecret()",
    (bool) preg_match('/Totp::decryptSecret\(\(string\) \$existing->secret_encrypted, \$masterKey\)/', $fnBody),
    $failures,
    $passed
);
stab_assert(
    "beginEnrollment()'s reuse-path return happens BEFORE generateSecret()/updateOrInsert() in source order — a reused secret does not also trigger a fresh secret generation or a duplicate \"enrollment started\" event",
    strpos($fnBody, "if (\$reusedSecret !== null) {") !== false
        && strpos($fnBody, "if (\$reusedSecret !== null) {") < strpos($fnBody, "\$secret = Totp::generateSecret();"),
    $failures,
    $passed
);
stab_assert(
    "beginEnrollment() still falls back to generating a fresh secret when there is no pending row, or the existing one fails to decrypt",
    strpos($fnBody, "\$secret = Totp::generateSecret();") !== false,
    $failures,
    $passed
);
stab_assert(
    "beginEnrollment() still stores the (possibly freshly generated) secret as \"pending\" — never silently activates, matching this class's own docblock guarantee",
    strpos($fnBody, '"status" => "pending"') !== false,
    $failures,
    $passed
);

// verifyAndActivate()/verifyLogin() — untouched by this fix — must still
// require status === "pending" / "active" respectively before accepting
// anything, and must never mutate a row on a failed code (a wrong code
// must be a pure read + rejection, so the pending row this fix now
// relies on being stable is genuinely never altered by a failed
// attempt).
stab_assert(
    "verifyAndActivate() still requires status === \"pending\" before accepting a code (unchanged by this fix)",
    strpos($enrollmentSource, 'if (!$row || $row->status !== "pending") {') !== false,
    $failures,
    $passed
);
$verifyAndActivateStart = strpos($enrollmentSource, "public static function verifyAndActivate(");
$verifyAndActivateEnd = strpos($enrollmentSource, "public static function verifyLogin(");
$verifyAndActivateBody = ($verifyAndActivateStart !== false && $verifyAndActivateEnd !== false)
    ? substr($enrollmentSource, $verifyAndActivateStart, $verifyAndActivateEnd - $verifyAndActivateStart)
    : "";
stab_assert(
    "verifyAndActivate()'s \"invalid\" (wrong code) branch only records an event and returns — it never writes to the secrets table, so a wrong code cannot itself disturb the pending row this fix relies on",
    (bool) preg_match('/\$matchedStep === null\) \{\s*EventLog::record\([^;]*;\s*return \["status" => "invalid"\];\s*\}/', $verifyAndActivateBody),
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "dct_totp_native secret-stability regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
