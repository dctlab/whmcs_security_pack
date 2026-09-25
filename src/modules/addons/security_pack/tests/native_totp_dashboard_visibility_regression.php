<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 "Time-Based
 * Token is Active but not in Two-Factor Authentication admin" incident.
 *
 * ROOT CAUSE: this addon's own admin 2FA screens (Security Overview
 * cards, the admin reporting table, "Manage a User's Two-Factor
 * Authentication") were built entirely against
 * modules/security/dct_totp_2fa's own table
 * (dctlab_security_pack_totp2fa) — but this install actually runs a
 * SEPARATE, standalone Security Module, modules/security/dct_totp_native,
 * with its own independent table (mod_dct_totp_native_secrets, confirmed
 * via that module's own lib/Schema.php). dct_totp_2fa has zero real
 * enrollments here, so every one of these screens showed "0 clients 0
 * administrators" / "NOT ACTIVE" / "Not enrolled" for Time-Based Token,
 * even while a real client (the one from the TOTP secret-rotation
 * screenshots, User #666503) was actively enrolled/enrolling through
 * dct_totp_native the entire time.
 *
 * FIX: a new NativeTotpStatusBridge class reads dct_totp_native's own
 * table directly (read-mostly; disable() mirrors that module's own
 * Enrollment::disable()). Every place this addon reads TOTP status now
 * checks that bridge first — falling back to the legacy dct_totp_2fa
 * table only when no native row exists, so nothing that already worked
 * for a genuine dct_totp_2fa install regresses.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging a new regression test into tests/run.php.
 * Run on its own:
 *
 *   php tests/native_totp_dashboard_visibility_regression.php
 *
 * No live database is available in this CLI runner, so these are
 * source-level checks (regex/substring against the actual shipped file
 * contents) — the same technique used throughout this project's other
 * standalone regression files.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function ntv_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function ntv_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

// --- NativeTotpStatusBridge itself -----------------------------------

$bridgeSource = ntv_src("lib/Security/TwoFactor/NativeTotpStatusBridge.php");
ntv_assert(
    "NativeTotpStatusBridge reads dct_totp_native's own table (mod_dct_totp_native_secrets), not a new/duplicate table",
    strpos($bridgeSource, 'private const TABLE = "mod_dct_totp_native_secrets";') !== false,
    $failures,
    $passed
);
ntv_assert(
    "NativeTotpStatusBridge::tableExists() exists and is fail-soft (wrapped in try/catch)",
    (bool) preg_match('/function tableExists\(\): bool\s*\{\s*try\s*\{/', $bridgeSource),
    $failures,
    $passed
);
ntv_assert(
    "NativeTotpStatusBridge::getConfig() checks tableExists() first and is fail-soft on any DB error",
    strpos($bridgeSource, "if(!self::tableExists()) {") !== false && strpos($bridgeSource, "catch (\\Throwable \$e) {\n            return null;") !== false,
    $failures,
    $passed
);
ntv_assert(
    "NativeTotpStatusBridge::disable() flips status to \"disabled\" without touching secret_encrypted — mirrors dct_totp_native's own Enrollment::disable(), enrollment preserved not deleted",
    (bool) preg_match('/update\(\["status" => "disabled", "deactivated_at" => \$now, "updated_at" => \$now\]\)/', $bridgeSource),
    $failures,
    $passed
);

// --- TotpTwoFactorProvider prefers the native row ---------------------

$providerSource = ntv_src("lib/Security/TwoFactor/Providers/TotpTwoFactorProvider.php");
ntv_assert(
    "TotpTwoFactorProvider::isActive() checks NativeTotpStatusBridge::getConfig() FIRST and returns based on that row when one exists",
    (bool) preg_match('/public function isActive\(int \$userId, string \$userType\): bool\s*\{\s*\$nativeRow = NativeTotpStatusBridge::getConfig\(\$userId, \$userType\);\s*if\(\$nativeRow !== null\) \{\s*return \$nativeRow->status === "active";/', $providerSource),
    $failures,
    $passed
);
ntv_assert(
    "TotpTwoFactorProvider::isActive() still falls back to the legacy TotpEnrollmentService when no native row exists — a genuine dct_totp_2fa install does not regress",
    strpos($providerSource, "return TotpEnrollmentService::isActive(\$userId, \$userType);") !== false,
    $failures,
    $passed
);
ntv_assert(
    "TotpTwoFactorProvider::isPending() also checks the native row first",
    (bool) preg_match('/public function isPending\(int \$userId, string \$userType\): bool\s*\{\s*\$nativeRow = NativeTotpStatusBridge::getConfig\(\$userId, \$userType\);/', $providerSource),
    $failures,
    $passed
);
ntv_assert(
    "TotpTwoFactorProvider::disable() disables whichever table(s) actually have a row for this identity, never assuming only one",
    strpos($providerSource, "NativeTotpStatusBridge::disable(\$userId, \$userType, \$actor);") !== false
        && strpos($providerSource, "TotpEnrollmentService::disable(\$userId, \$userType, \$actor);") !== false,
    $failures,
    $passed
);

// --- SECOND_FACTOR_MODULE_FOLDERS recognizes dct_totp_native ----------

$tfaServiceSource = ntv_src("lib/Security/TwoFactor/TwoFactorAuthenticationService.php");
ntv_assert(
    "TwoFactorAuthenticationService::SECOND_FACTOR_MODULE_FOLDERS lists BOTH dct_totp_2fa and dct_totp_native under \"totp\" (native's login gate is now recognized as \"ours\", not silently self-healed away)",
    (bool) preg_match('/"totp" => \["dct_totp_2fa", "dct_totp_native"\]/', $tfaServiceSource),
    $failures,
    $passed
);
ntv_assert(
    "clearNativeSecondFactorIfOurs() checks membership across ALL folders (array_merge of every key's array), not a flat single-value list",
    strpos($tfaServiceSource, "array_merge(...array_values(self::SECOND_FACTOR_MODULE_FOLDERS))") !== false,
    $failures,
    $passed
);
ntv_assert(
    "reconcileNativeSecondFactorDrift() checks in_array() membership against a method's folder LIST, not a single === comparison — required now that \"totp\" maps to two folders",
    strpos($tfaServiceSource, "in_array(\$native, \$expectedFolders, true)") !== false,
    $failures,
    $passed
);
ntv_assert(
    "TwoFactorAuthenticationService::configRow() prefers a NativeTotpStatusBridge row for \"totp\" before falling back to TotpEnrollmentService — so activated_at/last_verified_at reporting dates are correct for a native-tracked identity too",
    (bool) preg_match('/case "totp":\s*\$nativeRow = NativeTotpStatusBridge::getConfig\(\$userId, \$userType\);\s*return \$nativeRow !== null \? \$nativeRow : TotpEnrollmentService::getConfig\(\$userId, \$userType\);/', $tfaServiceSource),
    $failures,
    $passed
);

// --- Admin dashboard: Security Overview counts + reporting table ------

$controllerSource = ntv_src("lib/Admin/TwoFactorController.php");
ntv_assert(
    "TwoFactorController imports NativeTotpStatusBridge",
    strpos($controllerSource, "use WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\NativeTotpStatusBridge;") !== false,
    $failures,
    $passed
);
ntv_assert(
    "buildOverviewViewModel() no longer counts \"totp\" from ONLY the legacy table directly — it now delegates to countActiveTotpForType()",
    strpos($controllerSource, '$counts["totp"][$type] = self::countActiveTotpForType($type);') !== false,
    $failures,
    $passed
);
ntv_assert(
    "countActiveTotpForType() merges DISTINCT user_ids from both the legacy table AND mod_dct_totp_native_secrets, so the Security Overview \"Time-Based Token Active\" card counts real native-tracked enrollments instead of always showing 0",
    strpos($controllerSource, 'private static function countActiveTotpForType(string $type): int') !== false
        && strpos($controllerSource, '\Illuminate\Database\Capsule\Manager::table("mod_dct_totp_native_secrets")') !== false
        && strpos($controllerSource, "foreach (array_merge(\$legacyIds, \$nativeIds) as \$id) {") !== false,
    $failures,
    $passed
);
ntv_assert(
    "distinctTwoFactorIdentities() includes mod_dct_totp_native_secrets in its scanned table list (guarded by NativeTotpStatusBridge::tableExists()) — a native-only identity now actually appears in the admin reporting table at all, not merely with a corrected label",
    strpos($controllerSource, 'if(NativeTotpStatusBridge::tableExists()) {') !== false
        && strpos($controllerSource, '$tables[] = "mod_dct_totp_native_secrets";') !== false,
    $failures,
    $passed
);

// The pre-existing Users-tab overlay label mapping (a DIFFERENT admin
// screen from the one in this incident's screenshots — confirmed via
// TwoFactorAuthenticationService::status()'s own docblock distinguishing
// the two data sources) already recognized dct_totp_native as of 3.1.24;
// asserting it stays that way guards against a future regression
// re-introducing the exact "N/A" bug this project's history already
// fixed once.
ntv_assert(
    "TwoFactorController::labelFromSecondFactorModule() still recognizes dct_totp_native (pre-existing 3.1.24 fix for the SEPARATE Users-tab overlay column) — unchanged by this incident's fix, asserted here so it can't silently regress alongside it",
    strpos($controllerSource, '"dct_totp_native" => "Time-Based Token (Enhanced) Two-Factor Authentication",') !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Native TOTP dashboard-visibility regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
