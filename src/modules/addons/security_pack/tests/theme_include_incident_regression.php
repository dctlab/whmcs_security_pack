<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 production
 * incident and its full resolution.
 *
 * TIMELINE:
 *   1. `templates/settings.tpl` — the client-facing panel for Login
 *      Notification / Disable Forgot Password Reset / Session IP
 *      Security Limits, injected into a theme's native Security Settings
 *      page by security_pack_user_security_page()
 *      (core/user_security.php) — was found MISSING from the shipped
 *      module. Every matching theme's native Security Settings page
 *      threw "Smarty Error: ... No template default content for
 *      '...templates/settings.tpl'" on every load, with no self-recovery.
 *   2. First response: since the target file didn't exist and its exact
 *      prior markup/behavior couldn't be verified from the missing file
 *      alone, the injection was temporarily disabled and any
 *      already-corrupted theme file was self-healed by stripping the
 *      broken include.
 *   3. Root cause fully resolved: `SECURITY-AUDIT-PHASE-4.md` (a
 *      surviving prior audit report), `lib/Client/ClientController.php`
 *      (change_reset_password()/login_notification_alert()/
 *      limit_ip_range(), all unmodified), and `lang/english.php` (label
 *      keys already sitting unused) together gave enough surviving
 *      evidence to reconstruct `templates/settings.tpl` faithfully.
 *      Injection was restored to its original, simple form — the
 *      include line itself was never the problem, only its target file
 *      being missing.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging new regression tests into tests/run.php.
 * Run on its own:
 *
 *   php tests/theme_include_incident_regression.php
 *
 * No live theme file / live database is available in this CLI runner, so
 * these are source-level checks (same technique used throughout
 * tests/run.php and tests/phase4_rebrand_regression.php).
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function sp5_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function sp5_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

// =============================================================================
// 1) The template that was missing now genuinely exists and is non-empty.
// =============================================================================

sp5_assert(
    "templates/settings.tpl exists (the file whose absence caused this incident)",
    is_file($MODULE_DIR . "/templates/settings.tpl"),
    $failures,
    $passed
);
$settingsTplSource = sp5_src("templates/settings.tpl");
sp5_assert(
    "templates/settings.tpl is non-trivial content, not an empty placeholder",
    strlen($settingsTplSource) > 2000,
    $failures,
    $passed
);

// =============================================================================
// 2) core/user_security.php writes the include normally again (the
//    original, simple append-once-guarded-by-"security_pack" logic) —
//    no more self-heal/strip-only special-casing, since the actual
//    problem (a missing target file) is resolved, not worked around.
// =============================================================================

$userSecuritySource = sp5_src("core/user_security.php");
$fnStart = strpos($userSecuritySource, "function security_pack_user_security_page(");
sp5_assert("security_pack_user_security_page() is present in core/user_security.php", $fnStart !== false, $failures, $passed);
$fnBody = $fnStart !== false ? substr($userSecuritySource, $fnStart) : "";

sp5_assert(
    "security_pack_user_security_page() writes the include (file_put_contents with the include line) when the theme file does not already contain \"security_pack\"",
    (bool) preg_match('/if\(strpos\(\$template_content, "security_pack"\) === false\) \{\s*file_put_contents\(\$template_file, \$template_content \. PHP_EOL \. "\{include file=\\\\"modules\/addons\/security_pack\/templates\/settings\.tpl\\\\"\}"\);/', $fnBody),
    $failures,
    $passed
);
sp5_assert(
    "security_pack_user_security_page() no longer contains dead self-heal/strip-only logic (\$brokenInclude) from the temporary first-response fix",
    strpos($fnBody, '$brokenInclude') === false,
    $failures,
    $passed
);

// Everything else about the function must remain exactly as it always
// has — this incident's resolution changed only the template file and,
// briefly, this one write block; nothing else.
sp5_assert(
    "security_pack_user_security_page() still returns the full original vars array (nnmlang/login_notification/ip_limits/security_pack_csrf, etc.)",
    (bool) preg_match('/return \["nnmlang" => \$_ADDONLANG, "login_notification" => \$login_notification, "login_notification_allowed" => \$loginNotificationEnabled, "ip_limits" => \$ip_limits, "security_pack_ip_limits" => isset\(\$settings\["ip_range_limits"\]\), "security_pack_disable_password" => isset\(\$settings\["password_reset"\]\), "nnm_security_pack_successful" => \$success, "nnm_security_pack_error" => \$error, "remote_ip" => \$remote_ip, "disabled_reset_password" => Illuminate\\\\Database\\\\Capsule\\\\Manager::table\("dctlab_security_pack_dpass"\)->where\("user_id", \$user->id\)->count\(\), "security_pack_csrf" => security_pack_csrf_token\(\)\];/', $fnBody),
    $failures,
    $passed
);
sp5_assert(
    "security_pack_user_security_page() still gates on password_reset / ip_range_limits / login notification exactly as before (unchanged)",
    strpos($fnBody, 'isset($settings["password_reset"]) || isset($settings["ip_range_limits"]) || $loginNotificationEnabled') !== false,
    $failures,
    $passed
);
sp5_assert(
    "security_pack_user_security_page() still performs the path-traversal defense-in-depth check before ANY file write (realpath/strncmp against the templates root) — unchanged throughout this incident",
    strpos($fnBody, '$withinTemplatesDir = $templatesRoot && $resolvedTemplateFile') !== false,
    $failures,
    $passed
);

// =============================================================================
// 3) The reconstructed template correctly targets the surviving,
//    unmodified ClientController.php actions and CSRF field name — this
//    is the integration contract that made reconstruction possible at
//    all, so it must hold exactly.
// =============================================================================

$clientControllerSource = sp5_src("lib/Client/ClientController.php");

sp5_assert(
    "settings.tpl posts the Login Notification toggle to page=login_notification_alert (ClientController::login_notification_alert(), unmodified)",
    strpos($settingsTplSource, "page=\" + action") !== false && strpos($settingsTplSource, 'data-sp-toggle="login_notification_alert"') !== false
        && strpos($clientControllerSource, "public function login_notification_alert(") !== false,
    $failures,
    $passed
);
sp5_assert(
    "settings.tpl posts the Disable Password Reset toggle to page=change_reset_password (ClientController::change_reset_password(), unmodified)",
    strpos($settingsTplSource, 'data-sp-toggle="change_reset_password"') !== false
        && strpos($clientControllerSource, "public function change_reset_password(") !== false,
    $failures,
    $passed
);
sp5_assert(
    "settings.tpl's IP range add form posts ip_start_rang/ip_end_rang to page=limit_ip_range (ClientController::limit_ip_range(), unmodified)",
    strpos($settingsTplSource, 'name="ip_start_rang"') !== false
        && strpos($settingsTplSource, 'name="ip_end_rang"') !== false
        && strpos($settingsTplSource, "action=\"index.php?m=security_pack&page=limit_ip_range\"") !== false,
    $failures,
    $passed
);
sp5_assert(
    "settings.tpl's IP range remove action is a POST form carrying remove_ips (matches the PHASE4-01 POST-only fix — never a GET link)",
    strpos($settingsTplSource, 'name="remove_ips"') !== false
        && (bool) preg_match('/<form method="post" action="index\.php\?m=security_pack&page=limit_ip_range"[^>]*>\s*<input type="hidden" name="security_pack_token"[^>]*>\s*<input type="hidden" name="remove_ips"/', $settingsTplSource),
    $failures,
    $passed
);
sp5_assert(
    "settings.tpl includes the security_pack_token CSRF field on both POST forms, plus in the AJAX toggle body (matches security_pack_csrf_valid()'s expected field name in hooks.php, unmodified)",
    substr_count($settingsTplSource, 'name="security_pack_token"') === 2
        && strpos($settingsTplSource, "&security_pack_token=") !== false,
    $failures,
    $passed
);
sp5_assert(
    "settings.tpl escapes remote_ip and the IP range start/end values (matches SECURITY-AUDIT-PHASE-4.md's PHASE4-05 defense-in-depth fix, which named this exact file)",
    strpos($settingsTplSource, '{$remote_ip|escape}') !== false
        && strpos($settingsTplSource, '{$ip_limit->start_ip|escape}') !== false
        && strpos($settingsTplSource, '{$ip_limit->end_ip|escape}') !== false,
    $failures,
    $passed
);

// =============================================================================
// 4) Every label string settings.tpl uses actually exists in
//    lang/english.php — confirms nothing was invented that isn't backed
//    by the surviving language keys.
// =============================================================================

$langSource = sp5_src("lang/english.php");
$requiredLangKeys = [
    "login_notification", "login_notification_details",
    "disable_reset_password_title", "disable_reset_password_desc",
    "ip_login_limit", "ip_login_limit_desc", "ip_login_limit_current_ip",
    "ip_login_limit_start_ip", "ip_login_limit_end_ip", "ip_login_limit_add",
    "are_you_sure", "delete", "yes", "no",
];
$missingLangKeys = [];
foreach ($requiredLangKeys as $key) {
    if (strpos($langSource, "\$_ADDONLANG['" . $key . "']") === false) {
        $missingLangKeys[] = $key;
    }
    if (strpos($settingsTplSource, "nnmlang." . $key) === false) {
        $missingLangKeys[] = "settings.tpl never references \$nnmlang." . $key;
    }
}
sp5_assert(
    "every lang key settings.tpl relies on is defined in lang/english.php and actually used — " . (empty($missingLangKeys) ? "clean" : implode("; ", $missingLangKeys)),
    empty($missingLangKeys),
    $failures,
    $passed
);

// =============================================================================
// --- Summary ---
// =============================================================================

$totalTests = $passed + count($failures);
echo "Theme-include incident regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
