<?php

/**
 * dct_totp_native — regression test for the 2026-08-27 incident:
 * "Administrator Manual Bypass also not working". An admin-granted
 * bypass (created via the DCTLAB Security Pack addon's own
 * TwoFactorBypassService/admin panel) had no effect on this module's
 * login challenge, because this module only ever checked its own
 * same-IP trusted-device Bypass class — it never consulted Security
 * Pack's bypass/IP-exemption store at all.
 *
 * FIX: dct_totp_native_addon_bypass_active() checks Security Pack's
 * TwoFactorBypassService::findActive() and TwoFactorIpExemptionService::
 * isExempt() (both resolved by string class name, guarded by
 * class_exists()) in addition to this module's own Bypass class, in both
 * _challenge() (deciding whether to show the auto-submit bypass path or
 * the code form) and _verify() (accepting the resulting hidden-field
 * submission).
 *
 * Delivered as its own standalone file (this module's own tests/run.php
 * was not part of what was available to inspect when this fix was made —
 * see secret_stability_regression.php's own docblock for the same
 * caveat); run alongside it, not merged into it:
 *
 *   php tests/admin_bypass_integration_regression.php
 *
 * Source-level checks only (no live database in this CLI runner), same
 * technique as this module's other standalone regression file here.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function abp_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function abp_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$moduleSource = abp_src("dct_totp_native.php");

abp_assert(
    "dct_totp_native_addon_bypass_active() is present",
    strpos($moduleSource, "function dct_totp_native_addon_bypass_active(int \$userId, string \$userType, string \$ip): bool") !== false,
    $failures,
    $passed
);
abp_assert(
    "dct_totp_native_addon_bypass_active() checks Security Pack's TwoFactorBypassService::findActive() by string class name, guarded by an explicit class_exists() early-return — never a hard `use` dependency, preserving this module's standalone design",
    strpos($moduleSource, 'if (!class_exists($bypassClass)) {') !== false
        && strpos($moduleSource, '$activeBypassRow = $bypassClass::findActive($userId, $userType, $ip);') !== false
        && strpos($moduleSource, 'if ($activeBypassRow !== null) {') !== false,
    $failures,
    $passed
);
abp_assert(
    "dct_totp_native_addon_bypass_active() logs an UNCONDITIONAL (not rate-limited) DIAGNOSTIC every time findActive() runs without throwing but finds nothing — added 2026-08-27 fourth pass, after bypass creation was confirmed working (via the Activity Log) but a subsequent login still didn't skip the challenge, so the next test gives hard evidence of the exact identity checked",
    strpos($moduleSource, 'DIAGNOSTIC: no addon bypass found for user_id=" . $userId . " user_type=" . $userType . " ip=" . $ip') !== false,
    $failures,
    $passed
);
abp_assert(
    "dct_totp_native_addon_bypass_active() logs a rate-limited (once/hour) DIAGNOSTIC event when the Security Pack bypass class cannot be found at all — added 2026-08-27 second pass, so a still-not-working report gives concrete evidence instead of a third guess",
    strpos($moduleSource, 'RateLimiter::hit("addon_bypass_class_missing_diag", 1, 3600)') !== false
        && strpos($moduleSource, 'DIAGNOSTIC: Security Pack\'s TwoFactorBypassService class') !== false,
    $failures,
    $passed
);
abp_assert(
    "dct_totp_native_addon_bypass_active() also checks Security Pack's TwoFactorIpExemptionService::isExempt(), same class_exists() guard",
    strpos($moduleSource, 'class_exists($exemptionClass) && $exemptionClass::isExempt($ip, $userId, $userType)') !== false,
    $failures,
    $passed
);
abp_assert(
    "dct_totp_native_addon_bypass_active() fails CLOSED (returns false) on any lookup error — never grants a bypass it isn't sure of",
    (bool) preg_match('/function dct_totp_native_addon_bypass_active\(int \$userId, string \$userType, string \$ip\): bool\s*\{([\s\S]*?)\n\}/', $moduleSource, $mFn)
        && strpos($mFn[1], "catch (\\Throwable \$e) {") !== false
        && strpos($mFn[1], "return false;") !== false,
    $failures,
    $passed
);

$challengeStart = strpos($moduleSource, "function dct_totp_native_challenge(");
$challengeEnd = strpos($moduleSource, "function dct_totp_native_verify(");
$challengeBody = ($challengeStart !== false && $challengeEnd !== false) ? substr($moduleSource, $challengeStart, $challengeEnd - $challengeStart) : "";
abp_assert(
    "dct_totp_native_challenge() calls dct_totp_native_addon_bypass_active() and ORs it with the existing same-IP trusted-device check, rather than replacing that check",
    strpos($challengeBody, "\$addonBypassActive = dct_totp_native_addon_bypass_active(\$context[\"id\"], \$context[\"type\"], \$ip);") !== false
        && strpos($challengeBody, "if (\$addonBypassActive || (!empty(\$settings[\"BypassSameIp\"]) && Bypass::isActive(") !== false,
    $failures,
    $passed
);

$verifyStart = strpos($moduleSource, "function dct_totp_native_verify(");
$verifyEnd = strpos($moduleSource, "\n}", $verifyStart);
$verifyBody = ($verifyStart !== false) ? substr($moduleSource, $verifyStart, ($verifyEnd !== false ? $verifyEnd - $verifyStart : null)) : "";
abp_assert(
    "dct_totp_native_verify()'s bypass hidden-field branch also accepts dct_totp_native_addon_bypass_active(), so the auto-submit path _challenge() offers actually verifies successfully",
    strpos($verifyBody, "return dct_totp_native_addon_bypass_active(\$context[\"id\"], \$context[\"type\"], \$ip)") !== false,
    $failures,
    $passed
);

// The original same-IP trusted-device bypass (this module's own,
// pre-existing feature) must remain fully intact — this fix only adds a
// second, independent path, never replaces the first.
abp_assert(
    "Bypass::isActive() (this module's own same-IP trusted-device bypass) is still checked in both _challenge() and _verify() — unchanged by this fix",
    strpos($challengeBody, "Bypass::isActive(\$context[\"id\"], \$context[\"type\"], \$ip)") !== false
        && strpos($verifyBody, "Bypass::isActive(\$context[\"id\"], \$context[\"type\"], \$ip)") !== false,
    $failures,
    $passed
);

// --- Redundant "Verify" button removed (2026-08-27, on request) ------

abp_assert(
    "the code-entry fragment no longer emits its own \"Verify\" submit button — WHMCS's own outer login form's \"Login\" button is now the only submit control on this screen",
    strpos($moduleSource, '<button type="submit" class="btn btn-primary btn-block">Verify</button>') === false,
    $failures,
    $passed
);
abp_assert(
    "the code input field itself is untouched by the button removal — still present with its name/maxlength/autocomplete attributes intact",
    strpos($moduleSource, 'name="dct_totp_native_code"') !== false && strpos($moduleSource, 'maxlength="19"') !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "dct_totp_native admin-bypass-integration regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
