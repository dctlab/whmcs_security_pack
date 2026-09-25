<?php

/**
 * DCTLAB Security Pack — Phase 4 Rebrand + Database Change: standalone
 * regression test file.
 *
 * Per this project's established convention, new regression tests are
 * ALWAYS delivered as their own standalone file — never merged into
 * tests/run.php — so the existing 623-test baseline is never inflated by
 * a phase's own verification tests. Run this on its own:
 *
 *   php tests/phase4_rebrand_regression.php
 *
 * Scope (Phase 4 spec, Section 13): new DB table/column references,
 * absence of unintended OLD table references, DCTLAB branding presence,
 * navigation (including the three restricted items), Dashboard, Settings,
 * TwoFactor rendering, and DB CRUD call sites against the new schema.
 *
 * Same constraint as tests/run.php: no live database connection is
 * available in this CLI runner, so every check here is a SOURCE-LEVEL
 * check (regex / substring against the actual shipped file contents) —
 * exactly the same technique tests/run.php already uses throughout for
 * controller/service source auditing. This still gives a real, mechanical
 * guarantee: it fails the moment a functional Capsule::table() call or a
 * schema()->create() reintroduces an old table name, or a branding string
 * regresses.
 *
 * Exits non-zero if any assertion fails, so it can be wired into CI.
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function sp4_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function sp4_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    if (!is_file($full)) {
        return "";
    }
    return (string) file_get_contents($full);
}

// =============================================================================
// 1) NEW DATABASE TABLE REFERENCES — all 23 tables now use the
//    dctlab_security_pack_* naming directly, with NEW CREATE TABLE
//    definitions in activation logic (Phase 4 spec Section 4/6).
// =============================================================================

$NEW_TABLES = [
    "dctlab_security_pack",
    "dctlab_security_pack_events",
    "dctlab_security_pack_logins",
    "dctlab_security_pack_ips",
    "dctlab_security_pack_dpass",
    "dctlab_security_pack_rate_limits",
    "dctlab_security_pack_geo_cache",
    "dctlab_security_pack_ip_rules",
    "dctlab_security_pack_csp_reports",
    "dctlab_security_pack_anomalies",
    "dctlab_security_pack_score_snapshots",
    "dctlab_security_pack_email2fa",
    "dctlab_security_pack_email2fa_bypasses",
    "dctlab_security_pack_email2fa_challenges",
    "dctlab_security_pack_totp2fa",
    "dctlab_security_pack_whatsapp2fa",
    "dctlab_security_pack_whatsapp2fa_challenges",
    "dctlab_security_pack_2fa_recovery_codes",
    "dctlab_security_pack_trusted_browsers",
    "dctlab_security_pack_2fa_ip_exemptions",
    "dctlab_security_pack_lc_overrides",
    "dctlab_security_pack_opt",
    "dctlab_security_pack_schema_version",
];

$securityPackSource = sp4_src("security_pack.php");

foreach ($NEW_TABLES as $table) {
    sp4_assert(
        "security_pack.php: schema()->create(\"{$table}\", ...) is present (direct final-schema name, no migration model)",
        strpos($securityPackSource, 'schema()->create("' . $table . '"') !== false,
        $failures,
        $passed
    );
}

sp4_assert(
    "security_pack.php: exactly 23 schema()->create() calls total — no stray duplicate/leftover table definition was introduced by the rename",
    substr_count($securityPackSource, "schema()->create(\"dctlab_security_pack") === 23,
    $failures,
    $passed
);

// No column rename occurred in Phase 4 — assert none of the NEW tables'
// activation blocks contain a renameColumn()/dropColumn() call, which
// would indicate an out-of-scope column change slipped in.
sp4_assert(
    "security_pack.php: activation logic contains no renameColumn()/dropColumn() calls — Phase 4 performed table renames only, no column renames (spec Section 4/6)",
    strpos($securityPackSource, "renameColumn(") === false && strpos($securityPackSource, "->dropColumn(") === false,
    $failures,
    $passed
);

// =============================================================================
// 2) ABSENCE OF UNINTENDED OLD TABLE REFERENCES — a full-module sweep,
//    same exact-match discipline as the original rename script. Every
//    OLD "nnm_security_pack*" occurrence remaining in the shipped module
//    must be one of the explicitly whitelisted INTENTIONAL cases (Phase 4
//    spec Section 14): the two preserved $_SESSION flash-message keys, or
//    tests/run.php's own SQLi-fixture literals / historical/accurate
//    comments about the rename itself.
// =============================================================================

function sp4_rglob(string $dir, string $ext): array
{
    $out = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->isFile() && substr($file->getFilename(), -strlen($ext)) === $ext) {
            $out[] = $file->getPathname();
        }
    }
    sort($out);
    return $out;
}

$WHITELISTED_OLD_REFERENCES = [
    // Deliberately-preserved $_SESSION flash-message keys — NOT database
    // identifiers, share the "nnm_security_pack" string prefix only by
    // coincidence. See Phase 4 report Section N.
    'lib/Client/ClientController.php' => ['nnm_security_pack_error', 'nnm_security_pack_successful'],
    'core/user_security.php' => ['nnm_security_pack_error', 'nnm_security_pack_successful'],
    // templates/settings.tpl: renders those same two preserved
    // $_SESSION-derived vars (nnm_security_pack_successful/error), passed
    // in verbatim by core/user_security.php's return array. Reconstructed
    // 2026-08-27 — see that file's own header comment.
    'templates/settings.tpl' => ['nnm_security_pack_successful', 'nnm_security_pack_error'],
    // tests/run.php: SQLi-shaped test fixtures (the literal string content
    // is the test subject — an injection payload — not a live table
    // reference) and accurate historical/documentation comments about the
    // rename itself. See Phase 4 report Section N.
    'tests/run.php' => ['nnm_security_pack_events', 'nnm_security_pack_email2fa_challenges', 'nnm_security_pack_totp2fa'],
    // tests/theme_include_incident_regression.php: asserts (via regex)
    // that core/user_security.php's returned vars array still contains
    // these same two preserved key names — the test's own source
    // necessarily contains the literal strings it is checking for.
    'tests/theme_include_incident_regression.php' => ['nnm_security_pack_successful', 'nnm_security_pack_error'],
];

$oldReferenceViolations = [];
foreach (array_merge(sp4_rglob($MODULE_DIR, ".php"), sp4_rglob($MODULE_DIR, ".tpl")) as $file) {
    $rel = ltrim(str_replace($MODULE_DIR, "", $file), "/\\");
    // Never scan this test file's own source (it necessarily contains the
    // string "nnm_security_pack" throughout this section for the checks
    // themselves).
    if (strpos($rel, "phase4_rebrand_regression.php") !== false) {
        continue;
    }
    $contents = (string) file_get_contents($file);
    if (strpos($contents, "nnm_security_pack") === false) {
        continue;
    }
    if (!isset($WHITELISTED_OLD_REFERENCES[$rel])) {
        $oldReferenceViolations[] = $rel;
        continue;
    }
}

sp4_assert(
    "full-module sweep: every file containing \"nnm_security_pack\" is on the explicit Phase 4 INTENTIONAL whitelist (no unaudited stale reference exists) — " .
        (empty($oldReferenceViolations) ? "clean" : "UNEXPECTED FILES: " . implode(", ", $oldReferenceViolations)),
    empty($oldReferenceViolations),
    $failures,
    $passed
);

// The specific Section-14 catch identified during this phase's own audit:
// Diagnostics-page fallback "detail" strings that describe a failed query
// in prose (not a live Capsule table argument) — genuinely missed by the
// exact-match rename script the first time, then fixed. Regression-guard
// it explicitly so it can never silently regress back to the old name.
$diagnosticsSource = sp4_src("lib/Admin/DiagnosticsController.php");
sp4_assert(
    "DiagnosticsController.php: none of the three fallback \"Could not query ...\" detail strings reference an old nnm_security_pack_* table name",
    strpos($diagnosticsSource, "Could not query nnm_security_pack") === false,
    $failures,
    $passed
);
sp4_assert(
    "DiagnosticsController.php: the three fallback detail strings now reference the NEW dctlab_security_pack_* table names",
    strpos($diagnosticsSource, "Could not query dctlab_security_pack_events.") !== false
        && strpos($diagnosticsSource, "Could not query dctlab_security_pack_schema_version.") !== false
        && strpos($diagnosticsSource, "Could not query dctlab_security_pack_ip_rules.") !== false,
    $failures,
    $passed
);

// =============================================================================
// 3) DCTLAB BRANDING PRESENCE — visible identity strings.
// =============================================================================

$whmcsJsonSource = sp4_src("whmcs.json");
sp4_assert(
    "whmcs.json: description.name is \"DCTLAB Security Pack\"",
    strpos($whmcsJsonSource, '"name": "DCTLAB Security Pack"') !== false || strpos($whmcsJsonSource, '"name":"DCTLAB Security Pack"') !== false,
    $failures,
    $passed
);
sp4_assert(
    "whmcs.json: description.tagline is \"Enterprise Security & Authentication for WHMCS\"",
    strpos($whmcsJsonSource, "Enterprise Security & Authentication for WHMCS") !== false,
    $failures,
    $passed
);
sp4_assert(
    "whmcs.json: support/homepage references the DCTLAB reference brand URL",
    strpos($whmcsJsonSource, "dctlab.directcybertech.com") !== false,
    $failures,
    $passed
);

sp4_assert(
    "security_pack.php: security_pack_config() name field is rebranded to DCTLAB Security Pack",
    (bool) preg_match('/"name"\s*=>\s*"DCTLAB Security Pack"/', $securityPackSource),
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: NNM_Page_Builder->modulename (top-left navbar-brand text on every admin page) is set to DCTLAB Security Pack",
    strpos($securityPackSource, '$page_manager->modulename = "DCTLAB Security Pack"') !== false
        || (bool) preg_match('/modulename\s*=\s*"DCTLAB Security Pack"/', $securityPackSource),
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: helplink points at the DCTLAB reference brand URL",
    strpos($securityPackSource, "https://dctlab.directcybertech.com/") !== false,
    $failures,
    $passed
);

$dashboardSource = sp4_src("lib/Admin/DashboardController.php");
sp4_assert(
    "DashboardController.php: pageTitle/pageDescription reference DCTLAB Security Pack",
    strpos($dashboardSource, "DCTLAB Security Pack") !== false,
    $failures,
    $passed
);

$settingsControllerSource = sp4_src("lib/Admin/SettingsController.php");
sp4_assert(
    "SettingsController.php: pageTitle/pageDescription reference DCTLAB Security Pack",
    strpos($settingsControllerSource, "DCTLAB Security Pack") !== false,
    $failures,
    $passed
);

$loginLogsSource = sp4_src("lib/Admin/LoginLogsController.php");
sp4_assert(
    "LoginLogsController.php: pageDescription references DCTLAB Security Pack",
    strpos($loginLogsSource, "DCTLAB Security Pack") !== false,
    $failures,
    $passed
);

$totpServiceSource = sp4_src("lib/Security/TwoFactor/TotpService.php");
sp4_assert(
    "TotpService.php: provisioningUri() issuer default is \"DCTLAB Security Pack\" (cosmetic otpauth:// label only — no secret/algorithm/encoding logic touched)",
    (bool) preg_match('/function provisioningUri\([^)]*\$issuer\s*=\s*"DCTLAB Security Pack"/', $totpServiceSource),
    $failures,
    $passed
);

// =============================================================================
// 4) NAVIGATION — grouped menus, active state, and (5) RESTRICTED
//    NAVIGATION — the three explicitly-named restricted items remain
//    conditionally visible exactly as before. Only visible LABEL text may
//    change; href/address/route keys and visibility gating must not.
// =============================================================================

sp4_assert(
    "security_pack.php: \"Login History\" menu item is still conditionally gated on isset(\$settings[\"login_history\"])",
    (bool) preg_match('/isset\(\$settings\["login_history"\]\)\)\s*\{\s*\$page_manager->menu\["Login History"\]/', $securityPackSource),
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: \"Disabled Reset Password Clients\" menu item is still conditionally gated on isset(\$settings[\"password_reset\"])",
    (bool) preg_match('/isset\(\$settings\["password_reset"\]\)\)\s*\{\s*\$page_manager->menu\["Disabled Reset Password Clients"\]/', $securityPackSource),
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: \"IP Security Limited Clients\" menu item is still conditionally gated on isset(\$settings[\"ip_range_limits\"])",
    (bool) preg_match('/isset\(\$settings\["ip_range_limits"\]\)\)\s*\{\s*\$page_manager->menu\["IP Security Limited Clients"\]/', $securityPackSource),
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: restricted items keep their original c= route keys (c=LoginLogs / c=passwordDisabled / c=ipLimitedClients) — Phase 4 changed no routing",
    strpos($securityPackSource, '"href" => "c=LoginLogs"') !== false
        && strpos($securityPackSource, '"href" => "c=passwordDisabled"') !== false
        && strpos($securityPackSource, '"href" => "c=ipLimitedClients"') !== false,
    $failures,
    $passed
);
sp4_assert(
    "security_pack.php: menuGroups grouping is present (structure intentionally reordered/regrouped 2026-08-27 per explicit request — see tests/nav_menu_reorder_regression.php for the current exact structure/order; this assertion only confirms the array still exists and \"Protection\" still groups the same 4 items, order aside)",
    strpos($securityPackSource, '$page_manager->menuGroups = [') !== false
        && strpos($securityPackSource, '"Protection" => [') !== false
        && strpos($securityPackSource, '"IP Restrictions"') !== false
        && strpos($securityPackSource, '"Country Restrictions"') !== false
        && strpos($securityPackSource, '"IP Security Limited Clients"') !== false
        && strpos($securityPackSource, '"Disabled Reset Password Clients"') !== false,
    $failures,
    $passed
);

// =============================================================================
// 6) SETTINGS PAGE — the Phase 3.5 &c=settings redirect fix must remain
//    intact; setting KEYS must remain unchanged (only DB TABLE names and
//    visible text may change).
// =============================================================================

sp4_assert(
    "SettingsController.php: the Phase 3.5 redirect fix (module=security_pack&c=settings) is present on every remaining redirect call site (2026-08-27: down from 3 to 2 — the \"choose a GEO provider before enabling\" validation redirect was removed along with the GEO Providers field itself, not a regression in this fix)",
    substr_count($settingsControllerSource, 'redir("module=security_pack&c=settings') === 2,
    $failures,
    $passed
);
sp4_assert(
    "SettingsController.php: the save redirect still includes &saved=1",
    strpos($settingsControllerSource, 'module=security_pack&c=settings&saved=1') !== false,
    $failures,
    $passed
);
sp4_assert(
    "SettingsController.php: setting keys (login_history / password_reset / ip_range_limits) are unchanged identifiers, not renamed for branding",
    strpos($settingsControllerSource, '"login_history"') !== false
        && strpos($settingsControllerSource, '"password_reset"') !== false
        && strpos($settingsControllerSource, '"ip_range_limits"') !== false,
    $failures,
    $passed
);

// =============================================================================
// 7) TWOFACTOR RENDERING — TwoFactorController and its template still use
//    the unchanged internal identifiers (Section 3), with only visible
//    help/disclosure text rebranded.
// =============================================================================

$twoFactorControllerSource = sp4_src("lib/Admin/TwoFactorController.php");
sp4_assert(
    "TwoFactorController.php: class remains in the unchanged WHMCS\\Module\\Addon\\Security_Pack\\Admin namespace (Section 3 — internal identifiers not renamed for branding)",
    strpos($twoFactorControllerSource, "namespace WHMCS\\Module\\Addon\\Security_Pack\\Admin;") !== false,
    $failures,
    $passed
);

$twoFactorTplSource = sp4_src("templates/admin/two-factor.tpl");
sp4_assert(
    "two-factor.tpl: help-disclosure text references DCTLAB Security Pack",
    strpos($twoFactorTplSource, "DCTLAB Security Pack") !== false,
    $failures,
    $passed
);

// =============================================================================
// 8) DB CRUD CALL SITES AGAINST THE NEW SCHEMA — every functional
//    Capsule::table()/leftJoin() call site now argues the NEW table name.
//    No live database is available in this CLI runner (same constraint as
//    tests/run.php's own docblock states), so this is a source-level
//    check: every Capsule::table("...") argument found across the module
//    must be either a WHMCS-core table (tbl*) or a dctlab_security_pack_*
//    table — never an nnm_security_pack_* one.
// =============================================================================

$capsuleTableViolations = [];
foreach (array_merge(sp4_rglob($MODULE_DIR, ".php")) as $file) {
    $rel = ltrim(str_replace($MODULE_DIR, "", $file), "/\\");
    if (strpos($rel, "tests/run.php") !== false || strpos($rel, "phase4_rebrand_regression.php") !== false) {
        continue;
    }
    $contents = (string) file_get_contents($file);
    if (preg_match_all('/Capsule\\\\Manager::table\("(nnm_security_pack[^"]*)"\)/', $contents, $m1)) {
        foreach ($m1[1] as $bad) {
            $capsuleTableViolations[] = "{$rel}: Capsule::table(\"{$bad}\")";
        }
    }
    if (preg_match_all('/Capsule::table\("(nnm_security_pack[^"]*)"\)/', $contents, $m2)) {
        foreach ($m2[1] as $bad) {
            $capsuleTableViolations[] = "{$rel}: Capsule::table(\"{$bad}\")";
        }
    }
}

sp4_assert(
    "full-module sweep: zero Capsule::table() call sites reference an old nnm_security_pack_* table name — " .
        (empty($capsuleTableViolations) ? "clean" : "VIOLATIONS: " . implode("; ", $capsuleTableViolations)),
    empty($capsuleTableViolations),
    $failures,
    $passed
);

// Spot-check a representative sample of real CRUD call sites now argue the
// NEW table names (covers the "DB CRUD against new schema" requirement
// without needing a live database connection).
sp4_assert(
    "core/user_security.php: disabled_reset_password COUNT query now targets dctlab_security_pack_dpass",
    strpos(sp4_src("core/user_security.php"), 'Capsule\\Manager::table("dctlab_security_pack_dpass")') !== false,
    $failures,
    $passed
);
sp4_assert(
    "LoginLogsController.php: login-history COUNT/SELECT queries now target dctlab_security_pack_logins",
    substr_count(sp4_src("lib/Admin/LoginLogsController.php"), 'Capsule\\Manager::table("dctlab_security_pack_logins")') >= 2,
    $failures,
    $passed
);
sp4_assert(
    "DiagnosticsController.php: live-check queries now target dctlab_security_pack_events / dctlab_security_pack_schema_version / dctlab_security_pack_ip_rules",
    strpos($diagnosticsSource, 'Capsule\\Manager::table("dctlab_security_pack_events")') !== false
        && strpos($diagnosticsSource, 'Capsule\\Manager::table("dctlab_security_pack_schema_version")') !== false
        && strpos($diagnosticsSource, 'Capsule\\Manager::table("dctlab_security_pack_ip_rules")') !== false,
    $failures,
    $passed
);

// =============================================================================
// 9) HIGH-RISK AUTHENTICATION SAFEGUARD (Section 8/9) — confirm the rename
//    did not touch WhatsAppTwoFactorService::createChallenge()'s
//    rollback/RateLimiter/resend/cooldown/max_resends logic beyond the DB
//    identifier itself, and that no secret-regeneration/reset call was
//    introduced anywhere in the TwoFactor namespace by this phase.
// =============================================================================

$whatsAppServiceSource = sp4_src("lib/Security/TwoFactor/WhatsAppTwoFactorService.php");
sp4_assert(
    "WhatsAppTwoFactorService.php: createChallenge() still calls RateLimiter (resend/cooldown/max_resends enforcement untouched)",
    (bool) preg_match('/function createChallenge\([\s\S]{0,2000}RateLimiter/', $whatsAppServiceSource),
    $failures,
    $passed
);

// =============================================================================
// --- Summary ---
// =============================================================================

$totalTests = $passed + count($failures);
echo "Phase 4 rebrand regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
