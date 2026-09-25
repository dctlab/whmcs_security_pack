<?php

/**
 * Security Pack — regression test for the 2026-08-27 request: "option in
 * security_pack to activate System Activity Log on or off."
 *
 * FEATURE: a new Settings page toggle, "Disable System Activity Log"
 * (setting key: disable_activity_log), lets an admin stop DCTLAB Security
 * Pack from writing its own entries (audit trail, diagnostic markers)
 * into WHMCS's native System Activity Log (Utilities > Logs > Activity
 * Log). This does NOT touch WHMCS's own logging, other modules/hooks
 * calling logActivity() directly, or any of this addon's OWN internal
 * event-history tables (security_pack_record_event(), the login-history
 * table, etc) — only calls this addon routes through the new
 * security_pack_log_activity() choke point (hooks.php) are affected.
 *
 * Default is ON (unset = logging happens exactly as it always has) — an
 * upgrade with no explicit choice made changes nothing.
 *
 * Run alongside the other test files here, not merged into run.php
 * (matching this project's established convention for a standalone
 * feature regression file):
 *
 *   php tests/system_activity_log_toggle_regression.php
 */

declare(strict_types=1);

define("WHMCS", true);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function salt_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

$hooksSrc = (string) file_get_contents($MODULE_DIR . "/hooks.php");
$settingsControllerSrc = (string) file_get_contents($MODULE_DIR . "/lib/Admin/SettingsController.php");
$settingsTplSrc = (string) file_get_contents($MODULE_DIR . "/templates/admin/settings.tpl");

// --- Source-level: the choke-point wrapper exists and defaults to ON ----

salt_assert(
    "hooks.php defines security_pack_log_activity() — the single choke point every addon-owned logActivity() call is meant to route through",
    strpos($hooksSrc, "function security_pack_log_activity(\$message, \$relid = 0)") !== false,
    $failures,
    $passed
);
salt_assert(
    "security_pack_log_activity() only skips logging when \"disable_activity_log\" is explicitly SET — unset (the upgrade default) means logging still happens, matching every existing install's current behavior",
    (bool) preg_match('/function security_pack_log_activity\(\$message, \$relid = 0\)\s*\{\s*\$settings = security_pack_settings\(\);\s*if\(isset\(\$settings\["disable_activity_log"\]\)\) \{\s*return;/', $hooksSrc),
    $failures,
    $passed
);
salt_assert(
    "security_pack_log_activity() still calls the real WHMCS logActivity() (wrapped in try/catch, never fatal) when NOT disabled — it's a gate, not a second logging system",
    (bool) preg_match('/function security_pack_log_activity[\s\S]{0,400}try \{[\s\S]{0,150}logActivity\(\$message/', $hooksSrc),
    $failures,
    $passed
);

// --- Source-level: settings.tpl's existing Language & Currency debug
// logger is also routed through the new choke point (was a bare
// logActivity() call before this change) -----------------------------

salt_assert(
    "security_pack_lc_debug_log() (Language & Currency debug logging) now routes through security_pack_log_activity() instead of a bare logActivity() call, so the new master switch also covers it",
    strpos($hooksSrc, 'security_pack_log_activity("[DCTLAB Security Pack] Language & Currency: " . $message);') !== false,
    $failures,
    $passed
);

// --- Source-level: every addon-owned logActivity() call site this
// change touched now prefers security_pack_log_activity(), falling back
// to a bare logActivity() call only if the wrapper somehow isn't loaded
// (defensive — mirrors this codebase's existing function_exists() guard
// convention, never removes the original fallback behavior) -----------

$touchedFiles = [
    "lib/Security/Email2faService.php",
    "lib/Security/TwoFactor/TwoFactorBypassService.php",
    "lib/Admin/TwoFactorController.php",
];
foreach ($touchedFiles as $relPath) {
    $src = (string) file_get_contents($MODULE_DIR . "/" . $relPath);
    salt_assert(
        "$relPath: at least one logActivity() call site now checks function_exists(\"security_pack_log_activity\") and prefers it",
        strpos($src, 'function_exists("security_pack_log_activity")') !== false,
        $failures,
        $passed
    );
    salt_assert(
        "$relPath: the original bare logActivity() call text is still present as a fallback — nothing was deleted, only gated",
        strpos($src, "logActivity(") !== false,
        $failures,
        $passed
    );
}

// --- Source-level: Settings page wiring -----------------------------

salt_assert(
    "SettingsController::OWNED_KEYS includes \"disable_activity_log\" — the save()/non-destructive-upsert loop is allowed to persist and clear this setting",
    (bool) preg_match('/private const OWNED_KEYS = \[[\s\S]{0,600}"disable_activity_log"/', $settingsControllerSrc),
    $failures,
    $passed
);
salt_assert(
    "SettingsController defines buildSystemActivityLogSection() rendering a single toggle for \"disable_activity_log\", checked when the setting is currently set",
    (bool) preg_match('/function buildSystemActivityLogSection\(\$settings\): array[\s\S]{0,500}"name" => "disable_activity_log"[\s\S]{0,400}"checked" => isset\(\$settings\["disable_activity_log"\]\)/', $settingsControllerSrc),
    $failures,
    $passed
);
salt_assert(
    "SettingsController::index() passes \"systemActivityLog\" into the rendered view-model",
    strpos($settingsControllerSrc, '"systemActivityLog" => $this->buildSystemActivityLogSection($settings),') !== false,
    $failures,
    $passed
);
salt_assert(
    "templates/admin/settings.tpl renders the new System Activity Log panel inside the same settings form (one form, one Save Changes button — no second form was introduced)",
    strpos($settingsTplSrc, '$systemActivityLog["title"]') !== false
        && strpos($settingsTplSrc, 'action="?module=security_pack&amp;c=settings&amp;a=save"') !== false,
    $failures,
    $passed
);

// --- Behavioral: actually execute security_pack_log_activity() against
// a real (fake) logActivity() and confirm the gate genuinely works ----

if (!function_exists("logActivity")) {
    $GLOBALS["__salt_log_calls"] = [];
    function logActivity($message, $relid = 0)
    {
        $GLOBALS["__salt_log_calls"][] = [$message, $relid];
    }
}

// Isolate JUST security_pack_settings()/security_pack_log_activity() by
// eval'ing their real source, with a controllable global settings array
// standing in for the DB-backed $SECURITY_PACK_SETTINGS this function
// normally reads via the global in hooks.php.
$fnStart = strpos($hooksSrc, "function security_pack_log_activity(\$message, \$relid = 0)");
$braceOpen = strpos($hooksSrc, "{", $fnStart);
$depth = 0;
$end = $braceOpen;
for ($i = $braceOpen; $i < strlen($hooksSrc); $i++) {
    if ($hooksSrc[$i] === "{") {
        $depth++;
    } elseif ($hooksSrc[$i] === "}") {
        $depth--;
        if ($depth === 0) {
            $end = $i;
            break;
        }
    }
}
$fnSrc = substr($hooksSrc, $fnStart, $end - $fnStart + 1);

$GLOBALS["__salt_settings"] = [];
if (!function_exists("security_pack_settings")) {
    eval("function security_pack_settings() { return \$GLOBALS['__salt_settings']; }");
}
if (!function_exists("security_pack_log_activity")) {
    eval($fnSrc);
}

if (function_exists("security_pack_log_activity")) {
    $GLOBALS["__salt_settings"] = [];
    $GLOBALS["__salt_log_calls"] = [];
    security_pack_log_activity("test message A");
    salt_assert(
        "behavioral: with \"disable_activity_log\" NOT set (default), security_pack_log_activity() DOES call through to logActivity()",
        count($GLOBALS["__salt_log_calls"]) === 1 && $GLOBALS["__salt_log_calls"][0][0] === "test message A",
        $failures,
        $passed
    );

    $GLOBALS["__salt_settings"] = ["disable_activity_log" => "on"];
    $GLOBALS["__salt_log_calls"] = [];
    security_pack_log_activity("test message B");
    salt_assert(
        "behavioral: with \"disable_activity_log\" SET, security_pack_log_activity() does NOT call through to logActivity() at all",
        count($GLOBALS["__salt_log_calls"]) === 0,
        $failures,
        $passed
    );

    $GLOBALS["__salt_settings"] = [];
    $GLOBALS["__salt_log_calls"] = [];
    security_pack_log_activity("test message C", 42);
    salt_assert(
        "behavioral: the optional \$relid parameter is still passed through correctly when logging is enabled",
        count($GLOBALS["__salt_log_calls"]) === 1 && $GLOBALS["__salt_log_calls"][0][1] === 42,
        $failures,
        $passed
    );
} else {
    $failures[] = "could not isolate security_pack_log_activity() for a direct behavioral test — source extraction failed";
}

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Security Pack system-activity-log-toggle regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
