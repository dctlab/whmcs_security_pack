<?php

/**
 * dct_totp_native — regression test for the 2026-08-27 root cause behind
 * "Allow Same-IP Bypass is checked and saved, but the module still sees
 * it as off."
 *
 * ROOT CAUSE: dct_totp_native_settings_from_params() read this module's
 * own config()-declared field values (e.g. "BypassSameIp") from the
 * TOP LEVEL of $params, based on a docblock claim that this was
 * "confirmed against the sibling, already-verified dct_totp_2fa module."
 * That claim was never actually verified against a live WHMCS install —
 * it was wrong. A live diagnostic dump of the real $params keys for a
 * genuine login verify() call came back as exactly: whmcsVersion,
 * settings, user_info, user_settings, post_vars, twoFactorAuthentication
 * — no "BypassSameIp" (or anything else) at the top level at all. WHMCS
 * actually nests this module's own config field values under the
 * "settings" key.
 *
 * FIX: dct_totp_native_settings_from_params() now reads from
 * $params["settings"] first (the confirmed real location), falling back
 * to the previously-assumed top-level keys only if "settings" isn't
 * present — so a WHMCS version/context that genuinely puts them at the
 * top level still works, and this can't silently regress to the same
 * failure mode a second time.
 *
 * Delivered as its own standalone file, matching this module's existing
 * convention. Run alongside the other test files here:
 *
 *   php tests/settings_params_nesting_regression.php
 *
 * Source-level checks only (no live database/WHMCS runtime in this CLI
 * runner) — PLUS a direct behavioral unit test of
 * dct_totp_native_settings_from_params() itself, since this specific
 * function is small, pure, and safe to actually execute here.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function spn_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function spn_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$src = spn_src("dct_totp_native.php");

// --- Source-level: the fixed function reads from "settings" first -------

spn_assert(
    "dct_totp_native_settings_from_params() reads \$params[\"settings\"] first, not the top level, for BypassSameIp",
    (bool) preg_match('/\$settings = is_array\(\$params\["settings"\] \?\? null\) \? \$params\["settings"\] : \[\];\s*return \[\s*"BypassSameIp" => \$settings\["BypassSameIp"\] \?\? \$params\["BypassSameIp"\] \?\? "",/', $src),
    $failures,
    $passed
);
spn_assert(
    "the same fix applies to BypassDays, not just BypassSameIp",
    strpos($src, '"BypassDays" => $settings["BypassDays"] ?? $params["BypassDays"] ?? DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS,') !== false,
    $failures,
    $passed
);
spn_assert(
    "the previously-assumed top-level keys are kept as a fallback (never removed outright) — a WHMCS context that genuinely puts fields at the top level still works",
    strpos($src, '?? $params["BypassSameIp"] ?? ""') !== false,
    $failures,
    $passed
);
spn_assert(
    "the incorrect 'confirmed... never nested under a settings key' claim is no longer asserted as fact in this function's docblock",
    strpos($src, 'never nested under a "settings" key') === false,
    $failures,
    $passed
);

// --- Behavioral: actually execute the fixed function ---------------------

// A safe, minimal shim so this pure function can run standalone without
// the rest of the module's bootstrap (no WHMCS/Capsule/DB dependency —
// this function does no I/O of its own).
if (!function_exists("dct_totp_native_settings_from_params")) {
    if (!defined("DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS")) {
        define("DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS", 7);
    }
    // Extract JUST this one function's body from the real source and
    // eval it in isolation, rather than re-implementing the logic here
    // (which would test the test, not the actual fix).
    $start = strpos($src, "function dct_totp_native_settings_from_params(array \$params): array");
    $braceOpen = strpos($src, "{", $start);
    $depth = 0;
    $end = $braceOpen;
    for ($i = $braceOpen; $i < strlen($src); $i++) {
        if ($src[$i] === "{") {
            $depth++;
        } elseif ($src[$i] === "}") {
            $depth--;
            if ($depth === 0) {
                $end = $i;
                break;
            }
        }
    }
    $fnSrc = substr($src, $start, $end - $start + 1);
    eval($fnSrc);
}

if (function_exists("dct_totp_native_settings_from_params")) {
    $nestedOn = dct_totp_native_settings_from_params(["settings" => ["BypassSameIp" => "on", "BypassDays" => "14"]]);
    spn_assert(
        "given the REAL shape WHMCS actually sends (BypassSameIp nested under settings, value \"on\"), the function now correctly resolves it as truthy",
        !empty($nestedOn["BypassSameIp"]) && $nestedOn["BypassDays"] === "14",
        $failures,
        $passed
    );

    $nestedOff = dct_totp_native_settings_from_params(["settings" => ["BypassSameIp" => "", "BypassDays" => "7"]]);
    spn_assert(
        "given the setting genuinely OFF (nested, empty string), the function still correctly resolves it as falsy — this fix does not turn same-IP bypass on unconditionally",
        empty($nestedOff["BypassSameIp"]),
        $failures,
        $passed
    );

    $legacyTopLevel = dct_totp_native_settings_from_params(["BypassSameIp" => "on", "BypassDays" => "30"]);
    spn_assert(
        "given the OLD (incorrect but harmless-to-support) top-level shape with no \"settings\" key at all, the fallback still resolves it correctly — no regression for that hypothetical case",
        !empty($legacyTopLevel["BypassSameIp"]) && $legacyTopLevel["BypassDays"] === "30",
        $failures,
        $passed
    );

    $neither = dct_totp_native_settings_from_params([]);
    spn_assert(
        "given neither shape at all (missing entirely), the function fails safe to an empty/off BypassSameIp and the documented default BypassDays — never a fatal error",
        empty($neither["BypassSameIp"]) && $neither["BypassDays"] === DCT_TOTP_NATIVE_DEFAULT_BYPASS_DAYS,
        $failures,
        $passed
    );
} else {
    $failures[] = "could not isolate dct_totp_native_settings_from_params() for a direct behavioral test — source extraction failed";
}

// --- Summary ---

$totalTests = $passed + count($failures);
echo "dct_totp_native settings-\$params-nesting regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
