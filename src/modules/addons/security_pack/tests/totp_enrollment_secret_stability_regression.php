<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 TOTP
 * enrollment incident: entering an incorrect code during "Enable
 * Two-Factor Authentication" changed the displayed "Manual entry secret"
 * / QR code entirely, invalidating whatever the user had already scanned
 * into their authenticator app and guaranteeing every subsequent attempt
 * would also fail.
 *
 * ROOT CAUSE: WHMCS core re-invokes the Security Module's _activate()
 * (modules/security/dct_totp_2fa/dct_totp_2fa.php:dct_totp_2fa_activate())
 * after every failed _activateverify() submission, purely to re-render
 * the form with an error message. That function calls
 * TotpEnrollmentService::beginEnrollment(), which previously generated +
 * stored a brand-new secret unconditionally on every call, with no
 * distinction between "starting a genuinely new enrollment" and "WHMCS
 * re-rendering the same still-pending enrollment after a wrong code."
 *
 * FIX: beginEnrollment() now reuses the existing secret for a still-
 * pending enrollment rather than rotating it. This does not touch
 * "Section 13: do not activate before verification" — the row's status
 * stays "pending" either way.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging new regression tests into tests/run.php.
 * Run on its own:
 *
 *   php tests/totp_enrollment_secret_stability_regression.php
 *
 * No live database is available in this CLI runner (same constraint as
 * tests/run.php's own docblock), so these are source-level checks —
 * same technique used throughout this project's other standalone
 * regression files.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function sp6_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function sp6_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$enrollmentSource = sp6_src("lib/Security/TwoFactor/TotpEnrollmentService.php");
$fnStart = strpos($enrollmentSource, "public static function beginEnrollment(");
sp6_assert("TotpEnrollmentService::beginEnrollment() is present", $fnStart !== false, $failures, $passed);
// Isolate just this method's body (up to the next "public static function")
// so checks can't accidentally match unrelated code elsewhere in the file.
$fnBody = "";
if ($fnStart !== false) {
    $nextFn = strpos($enrollmentSource, "public static function", $fnStart + 10);
    $fnBody = $nextFn !== false ? substr($enrollmentSource, $fnStart, $nextFn - $fnStart) : substr($enrollmentSource, $fnStart);
}

sp6_assert(
    "beginEnrollment() checks for an existing enrollment via self::getConfig() before deciding whether to mint a new secret",
    strpos($fnBody, "self::getConfig(\$userId, \$userType)") !== false,
    $failures,
    $passed
);
sp6_assert(
    "beginEnrollment() only reuses a secret when the existing row's status is \"pending\" (never reuses an already-active row's secret)",
    (bool) preg_match('/\$existing\s*&&\s*\$existing->status === "pending"/', $fnBody),
    $failures,
    $passed
);
sp6_assert(
    "beginEnrollment() decrypts and returns the EXISTING row's secret_encrypted (reuse path) via TotpService::decryptSecret()",
    (bool) preg_match('/TotpService::decryptSecret\(\(string\) \$existing->secret_encrypted, \$masterKey\)/', $fnBody),
    $failures,
    $passed
);
sp6_assert(
    "beginEnrollment()'s reuse path returns before reaching generateSecret()/updateOrInsert() — i.e. a reused secret does NOT also trigger a fresh secret generation or a second enrollment-started event",
    (bool) preg_match('/if\(\$reusedSecret !== null\) \{\s*return \[/', $fnBody)
        && strpos($fnBody, "if(\$reusedSecret !== null) {") < strpos($fnBody, "\$secret = TotpService::generateSecret();"),
    $failures,
    $passed
);
sp6_assert(
    "beginEnrollment() still falls back to generating a fresh secret when there is no pending row, or the existing one fails to decrypt",
    strpos($fnBody, "\$secret = TotpService::generateSecret();") !== false,
    $failures,
    $passed
);
sp6_assert(
    "beginEnrollment() still stores the (possibly freshly generated) secret as \"pending\" — Section 13 (never silently activate) is unaffected by this fix",
    strpos($fnBody, '"status" => "pending"') !== false,
    $failures,
    $passed
);

// The Security Module's own docblock must no longer claim the old,
// now-incorrect behavior ("generates a brand-new secret every time this
// is opened").
$totpModuleSource = sp6_src("../../security/dct_totp_2fa/dct_totp_2fa.php");
sp6_assert(
    "dct_totp_2fa.php no longer claims a brand-new secret is generated every time the enrollment step is opened",
    strpos($totpModuleSource, "generates a brand-new secret every time this\n * is opened") === false,
    $failures,
    $passed
);
sp6_assert(
    "dct_totp_2fa.php's dct_totp_2fa_activate() docblock now documents the secret-stability fix",
    strpos($totpModuleSource, "SECRET STABILITY (incident fix, 2026-08-27)") !== false,
    $failures,
    $passed
);

// The activate/activateverify wiring itself (which supplied the crucial
// clue that WHMCS re-invokes _activate() on a failed verify, and which
// this fix relies on continuing to behave that way) must remain
// unmodified — this incident's fix touched TotpEnrollmentService only.
sp6_assert(
    "dct_totp_2fa_activate() still reads \$params[\"verifyError\"] to show the prior failure's message (unchanged by this fix)",
    strpos($totpModuleSource, '$params["verifyError"]') !== false,
    $failures,
    $passed
);
sp6_assert(
    "dct_totp_2fa_activateverify() still throws (never returns an array with a \"msg\" key) on an incorrect code — the WHMCS-core success/failure contract this whole flow depends on is untouched",
    (bool) preg_match('/throw new \\\\WHMCS\\\\Exception\(\$messages\[\$result\["status"\]\] \?\? "Verification failed\."\);/', $totpModuleSource),
    $failures,
    $passed
);

// =============================================================================
// Deployment-freshness diagnostic (2026-08-27, added after a report that
// the fix above was uploaded but the bug was still observed live — code
// review confirmed the fix itself has no bug, so this exists to let a
// reload of the admin Diagnostics page distinguish "not deployed/not yet
// active" (most likely: stale PHP opcache) from a genuine regression.
// =============================================================================

sp6_assert(
    "TotpEnrollmentService defines the ENROLLMENT_FIX_MARKER version-marker constant used by the Diagnostics freshness check",
    strpos($enrollmentSource, 'public const ENROLLMENT_FIX_MARKER = "totp-secret-stability-2026-08-27";') !== false,
    $failures,
    $passed
);
$diagnosticsSource = sp6_src("lib/Admin/DiagnosticsController.php");
sp6_assert(
    "DiagnosticsController checks ENROLLMENT_FIX_MARKER via class_exists()+defined() — reflecting whatever code PHP actually has LOADED (a stale opcache entry included), not just what's on disk",
    strpos($diagnosticsSource, 'class_exists($totpEnrollmentClass) && defined($totpEnrollmentClass . "::ENROLLMENT_FIX_MARKER")') !== false,
    $failures,
    $passed
);
sp6_assert(
    "DiagnosticsController's freshness check reports \"fail\" with opcache-restart guidance when the marker is absent, and \"pass\" with the marker value when present",
    strpos($diagnosticsSource, '"name" => "TOTP Enrollment — Secret Stability Fix"') !== false
        && strpos($diagnosticsSource, "Clear/reset your host's PHP opcache") !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "TOTP enrollment secret-stability regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
