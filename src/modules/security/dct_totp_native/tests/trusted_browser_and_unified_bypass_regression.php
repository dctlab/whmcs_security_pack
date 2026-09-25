<?php

/**
 * dct_totp_native — regression test for the 2026-08-27 report: "Client
 * #666503, logging into the client area with Time-Based Token —
 * Administrator Manual Bypass not added by system. Also 'Remember this
 * browser for 30 days' for Time-Based Token missing."
 *
 * ROOT CAUSE: neither feature was ever wired into this module, even
 * though both already exist as an ESTABLISHED pattern in the sibling
 * live security modules (dct_email_2fa, and the older dct_totp_2fa) —
 * which is exactly why a DIFFERENT account (client #666037, on Email
 * Verification) already showed a same-IP row in the Security Pack admin
 * "Administrator Manual Bypass" table (that one table lists every scope,
 * admin_manual AND same_ip, together) while a Time-Based Token account
 * never did. This is not a new auto-create rule being invented — it is
 * this module catching up to a feature its siblings already have:
 *
 *  1. "Remember this browser for 30 days" — TrustedBrowserService
 *     (Security Pack) was never referenced by this module's
 *     challenge()/verify() at all.
 *  2. Security Pack's UNIFIED same-IP bypass
 *     (TwoFactorBypassService::grantSameIpBypass() — the one that
 *     populates the shared admin table) was never called here; only
 *     this module's OWN separate, addon-independent Bypass::grant() was
 *     (a different table, unaffected by this fix, still called exactly
 *     as before).
 *
 * FIX: both are wired in behind the SAME existing `BypassSameIp`
 * setting/`Bypass::grant()` call site (never a new toggle) and the SAME
 * optional, fail-soft class_exists() pattern the bypass-CHECK
 * integration already established in this file — this module still
 * works completely standalone if the Security Pack addon isn't
 * installed.
 *
 * Delivered as its own standalone file, matching this module's existing
 * convention (see admin_bypass_integration_regression.php's own
 * docblock). Run alongside the other test files here, not merged into
 * one:
 *
 *   php tests/trusted_browser_and_unified_bypass_regression.php
 *
 * Source-level checks only (no live database in this CLI runner).
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function tbub_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function tbub_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$src = tbub_src("dct_totp_native.php");

// --- Trusted browser: challenge() ---------------------------------------

$trustedBrowserPos = strpos($src, '$trustedBrowserToken = dct_totp_native_trusted_browser_read_token();');
$addonBypassPos = strpos($src, '$addonBypassActive = dct_totp_native_addon_bypass_active(');
tbub_assert(
    "dct_totp_native_challenge() checks a trusted-browser cookie BEFORE the same-IP bypass check, mirroring dct_totp_2fa_challenge()'s own ordering",
    $trustedBrowserPos !== false && $addonBypassPos !== false && $trustedBrowserPos < $addonBypassPos,
    $failures,
    $passed
);
tbub_assert(
    "a recognized trusted browser auto-submits its own distinct hidden field (dct_totp_native_trusted_browser), never merged with the bypass auto-submit field",
    strpos($src, 'name="dct_totp_native_trusted_browser" value="1"') !== false,
    $failures,
    $passed
);
tbub_assert(
    "trusted-browser lookup is fully optional — resolved by string class name behind class_exists(), so this module still works standalone with no Security Pack addon installed",
    strpos($src, 'class_exists($class)') !== false
        && strpos($src, '"\\\\WHMCS\\\\Module\\\\Addon\\\\Security_Pack\\\\Security\\\\TwoFactor\\\\TrustedBrowserService"') !== false,
    $failures,
    $passed
);

// --- Trusted browser: the checkbox itself -------------------------------

tbub_assert(
    "the code-entry form now offers a \"Remember this browser for 30 days\" checkbox (dct_totp_native_remember_browser) — previously entirely absent from this module's challenge() output",
    strpos($src, 'name="dct_totp_native_remember_browser" value="1"') !== false
        && strpos($src, "Remember this browser for 30 days") !== false,
    $failures,
    $passed
);

// --- Trusted browser: verify() ------------------------------------------

tbub_assert(
    "verify() consumes the trusted-browser token on the auto-submit branch via TrustedBrowserService::consume(), BEFORE the bypass auto-submit branch is even reached",
    (bool) preg_match('/post_vars"\]\["dct_totp_native_trusted_browser"\][\s\S]{0,400}::consume\(\$token, \$context\["id"\], \$context\["type"\]\)[\s\S]{0,400}post_vars"\]\["dct_totp_native_bypass"\]/', $src),
    $failures,
    $passed
);
tbub_assert(
    "verify() only ever creates a NEW trusted-browser token on the genuine code/recovery-code success path — never inside the bypass or trusted-browser-itself auto-submit branches (both of those return earlier), matching TrustedBrowserService's own documented \"explicit opt-in on a REAL successful verification\" design",
    (bool) preg_match('/post_vars"\]\["dct_totp_native_remember_browser"\]\)\)[\s\S]{0,400}::create\(\$context\["id"\], \$context\["type"\], \$deviceLabel, \$ip\)/', $src),
    $failures,
    $passed
);
tbub_assert(
    "a created trusted-browser token is actually set as a cookie via TrustedBrowserService::setCookie() — not just created and discarded",
    strpos($src, "\$class::setCookie(\$rawToken)") !== false,
    $failures,
    $passed
);

// --- Unified same-IP bypass ----------------------------------------------

tbub_assert(
    "a successful login still grants this module's OWN local Bypass::grant() exactly as before — this fix does not remove or change that existing, unrelated table/feature",
    strpos($src, "Bypass::grant(\$context[\"id\"], \$context[\"type\"], \$ip, \$days)") !== false,
    $failures,
    $passed
);
$bypassSameIpBlockPos = strpos($src, 'if (!empty($settings["BypassSameIp"])) {');
$localGrantPos = strpos($src, 'Bypass::grant($context["id"], $context["type"], $ip, $days);');
$bypassClassDeclPos = strpos($src, "\$bypassClass = \"\\\\WHMCS\\\\Module\\\\Addon\\\\Security_Pack\\\\Security\\\\TwoFactor\\\\TwoFactorBypassService\";");
$unifiedGrantPos = strpos($src, '$bypassClass::grantSameIpBypass($context["id"], $context["type"], $ip, $days, "totp", "2fa");');
tbub_assert(
    "Security Pack's UNIFIED TwoFactorBypassService::grantSameIpBypass() is now ALSO called, under the exact same `BypassSameIp` condition as the module's own local Bypass::grant() — no new setting/toggle invented, both features share one on/off switch and can never drift out of sync",
    $bypassSameIpBlockPos !== false && $localGrantPos !== false && $unifiedGrantPos !== false
        && $bypassSameIpBlockPos < $localGrantPos && $localGrantPos < $unifiedGrantPos,
    $failures,
    $passed
);
tbub_assert(
    "the unified same-IP grant is resolved by string class name behind class_exists() — fully optional, same fail-soft pattern the bypass CHECK already established in this file, so a standalone install with no Security Pack addon is unaffected",
    $bypassClassDeclPos !== false
        && strpos($src, "\$classExists = class_exists(\$bypassClass);") !== false
        && strpos($src, "if (\$classExists) {") !== false
        && $bypassClassDeclPos < $unifiedGrantPos,
    $failures,
    $passed
);
tbub_assert(
    "a thrown exception from the (optional) unified bypass grant is caught and diagnostically logged, never allowed to break a login that otherwise succeeded",
    $unifiedGrantPos !== false && strpos($src, "TwoFactorBypassService::grantSameIpBypass() threw for") !== false
        && strpos($src, "TwoFactorBypassService::grantSameIpBypass() threw for") > $unifiedGrantPos,
    $failures,
    $passed
);

// --- 2026-08-27 (second pass) diagnostics: settle whether "no bypass row
// appears" means the setting is off vs. the grant call is failing --------

tbub_assert(
    "verify() unconditionally logs the raw BypassSameIp setting value on EVERY successful verification (not gated behind the truthy check) — so the next report distinguishes 'the setting is off' from 'the setting is on but the grant silently failed'",
    (bool) preg_match('/DIAGNOSTIC v5: verify\(\) success[\s\S]{0,300}settings\["BypassSameIp"\]/', $src),
    $failures,
    $passed
);
tbub_assert(
    "when BypassSameIp IS enabled, verify() logs whether TwoFactorBypassService::class_exists() resolved true or false — a false here (Security Pack not active/loaded) fully explains an empty admin table without any bug in the grant call itself",
    strpos($src, '$classExists = class_exists($bypassClass);') !== false
        && strpos($src, 'TwoFactorBypassService class_exists=" . ($classExists ? "true" : "false")') !== false,
    $failures,
    $passed
);
tbub_assert(
    "a successful (non-throwing) grantSameIpBypass() call is ALSO logged, not just a thrown one — confirms the call was reached and returned, so a missing admin-table row afterward points at the table/identity match, not the call site",
    strpos($src, 'grantSameIpBypass() returned without throwing for') !== false,
    $failures,
    $passed
);

// --- 2026-08-27 (third pass): the admin confirms "Allow Same-IP Bypass"
// IS on, yet the module still saw it as empty — dump the REAL $params
// keys/bypass-like values WHMCS hands this call, rather than guessing
// at a field-name/caching mismatch ---------------------------------------

tbub_assert(
    "verify() logs every top-level \$params KEY NAME it actually received for this call (never post_vars VALUES, which could contain the submitted code) — settles whether WHMCS is really using the field name this module assumed",
    strpos($src, 'verify() \$params top-level keys for this call') !== false,
    $failures,
    $passed
);
tbub_assert(
    "verify() separately logs the raw value of any \$params key that merely CONTAINS \"bypass\" (case-insensitive) — catches a differently-cased or differently-prefixed key WHMCS might actually be using instead of the exact \"BypassSameIp\" this module reads",
    strpos($src, 'stripos($k, "bypass") !== false') !== false
        && strpos($src, "NONE FOUND") !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "dct_totp_native trusted-browser & unified-bypass regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
