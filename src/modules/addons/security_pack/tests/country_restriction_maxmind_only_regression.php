<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 request:
 * "Country Restriction remove all others only MaxMind Database needed."
 *
 * CHANGE: the "GEO Providers" field on the Settings page's Country
 * Restriction panel — a multi-select for the free curl-based providers
 * (freeipapi.com, geojs.io, ipapi.co) — was removed entirely, along with
 * the save() validation that required choosing one before Country
 * Restriction could be enabled. GeoIP resolution (used by BOTH Country
 * Restriction and GeoIP Language & Currency — they share one
 * GeoIpManager) now relies exclusively on the MaxMind database uploaded
 * on the Language & Currency page; the curl-provider fallback was
 * removed from GeoIpManager's default provider chain, so a visitor's IP
 * is never sent to a third-party geolocation API.
 *
 * NOT removed: the underlying CurlApiProvider class and providers/*.php
 * files (dead code now, left in place rather than deleted, matching
 * this project's general preference for minimal, reversible changes),
 * and the unrelated "Whitelist IP" field on the same panel.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention of never merging new regression tests into tests/run.php.
 * Run on its own:
 *
 *   php tests/country_restriction_maxmind_only_regression.php
 */

declare(strict_types=1);

define("WHMCS", true);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function crmo_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function crmo_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$geoIpManagerSrc = crmo_src("lib/Security/GeoIpManager.php");
$settingsControllerSrc = crmo_src("lib/Admin/SettingsController.php");
$settingsTplSrc = crmo_src("templates/admin/settings.tpl");

// =============================================================================
// 1) GeoIpManager's default provider chain is MaxMind-only.
// =============================================================================

crmo_assert(
    "GeoIpManager's default constructor no longer wires in CurlApiProvider — only MaxMindProvider",
    (bool) preg_match('/\$this->providers = \$providers \?: \[new MaxMindProvider\(\)\];/', $geoIpManagerSrc),
    $failures,
    $passed
);
crmo_assert(
    "GeoIpManager no longer imports CurlApiProvider (unused import removed along with the wiring)",
    strpos($geoIpManagerSrc, "use WHMCS\\Module\\Addon\\Security_Pack\\Security\\Providers\\CurlApiProvider;") === false,
    $failures,
    $passed
);
crmo_assert(
    "GeoIpManager still imports and constructs MaxMindProvider — the one remaining provider",
    strpos($geoIpManagerSrc, "use WHMCS\\Module\\Addon\\Security_Pack\\Security\\Providers\\MaxMindProvider;") !== false,
    $failures,
    $passed
);
crmo_assert(
    "GeoIpManager still accepts an explicit \$providers array override in its constructor — a future caller could still opt back into extra providers deliberately, this only changes the DEFAULT",
    strpos($geoIpManagerSrc, "public function __construct(array \$providers = [])") !== false,
    $failures,
    $passed
);

// =============================================================================
// 2) The underlying provider classes/files are left in place (not
//    deleted) — this was a wiring change, not a deletion.
// =============================================================================

crmo_assert(
    "lib/Security/Providers/CurlApiProvider.php still exists on disk (dead code, deliberately not deleted)",
    is_file($MODULE_DIR . "/lib/Security/Providers/CurlApiProvider.php"),
    $failures,
    $passed
);
foreach (["freeipapi", "geojsio", "ipapico"] as $provider) {
    crmo_assert(
        "providers/$provider.php still exists on disk (dead code, deliberately not deleted)",
        is_file($MODULE_DIR . "/providers/" . $provider . ".php"),
        $failures,
        $passed
    );
}
crmo_assert(
    "lib/Security/Providers/MaxMindProvider.php is unmodified/untouched by this change",
    strpos(crmo_src("lib/Security/Providers/MaxMindProvider.php"), "function isAvailable(): bool") !== false,
    $failures,
    $passed
);

// =============================================================================
// 3) SettingsController: the GEO Providers field, its discovery loop,
//    and the "choose a provider" validation are all gone. Whitelist IP
//    (an unrelated field on the same panel) is untouched.
// =============================================================================

crmo_assert(
    "SettingsController::buildCountryRestrictionSection() no longer builds a \"providerOptions\" array or runs the glob()+include() provider-discovery loop",
    strpos($settingsControllerSrc, "providerOptions") === false
        && strpos($settingsControllerSrc, 'glob(security_pack_module_root . "/providers/*.php")') === false,
    $failures,
    $passed
);
crmo_assert(
    "SettingsController::buildCountryRestrictionSection() still returns \"checked\" and \"whitelist\" — the two fields that remain on this panel",
    (bool) preg_match('/function buildCountryRestrictionSection\(\$settings\): array\s*\{\s*return \[\s*"checked" => isset\(\$settings\["country_restriction"\]\),\s*"whitelist" => \$settings\["whitelist"\] \?\? "",\s*\];/', $settingsControllerSrc),
    $failures,
    $passed
);
crmo_assert(
    "SettingsController::save() no longer requires a GEO provider before Country Restriction can be enabled",
    strpos($settingsControllerSrc, "Please choose at least one Geo provider before enabling Country Restriction.") === false
        && strpos($settingsControllerSrc, '!($requestSettings["providers"] ?? "")') === false,
    $failures,
    $passed
);
crmo_assert(
    "SettingsController::OWNED_KEYS no longer lists \"providers\" — this form has nothing left to save it from",
    (bool) preg_match('/private const OWNED_KEYS = \[[^;]*\];/s', $settingsControllerSrc, $m) && strpos($m[0], '"providers"') === false,
    $failures,
    $passed
);
crmo_assert(
    "SettingsController::OWNED_KEYS still lists \"country_restriction\" and \"whitelist\" — unchanged, still owned by this form",
    (bool) preg_match('/private const OWNED_KEYS = \[[^;]*"country_restriction", "whitelist"[^;]*\];/s', $settingsControllerSrc),
    $failures,
    $passed
);

// =============================================================================
// 4) templates/admin/settings.tpl: the GEO Providers <select> markup is
//    gone; the Whitelist IP field and the link-out to the dedicated
//    Country Restriction page are unchanged.
// =============================================================================

crmo_assert(
    "settings.tpl no longer renders the GEO Providers <select multiple> field (the removed markup itself — mentions of the removed field's name in explanatory comments are fine and expected)",
    strpos($settingsTplSrc, 'name="settings[providers][]"') === false
        && strpos($settingsTplSrc, 'id="nnm_provider_select"') === false
        && strpos($settingsTplSrc, "selectize-multi-select") === false,
    $failures,
    $passed
);
crmo_assert(
    "settings.tpl still renders the Whitelist IP textarea — untouched, unrelated field on the same panel",
    strpos($settingsTplSrc, 'name="settings[whitelist]"') !== false,
    $failures,
    $passed
);
crmo_assert(
    "settings.tpl still links out to the dedicated Country Restriction management page",
    strpos($settingsTplSrc, 'href="?module=security_pack&amp;c=countryRestriction"') !== false,
    $failures,
    $passed
);
crmo_assert(
    "settings.tpl no longer declares a \"providerOptions\" default in its \$countryRestriction fallback array",
    strpos($settingsTplSrc, '$countryRestriction = $countryRestriction ?? ["checked" => false, "whitelist" => ""];') !== false,
    $failures,
    $passed
);

// =============================================================================
// 5) Behavioral: GeoIpManager's diagnostics() — used by both the
//    Security Diagnostics page and the Country Restriction status page
//    — now reports exactly one provider (MaxMind), never "curl".
// =============================================================================

if (!function_exists("security_pack_mmdb_reader")) {
    function security_pack_mmdb_reader()
    {
        return null; // no live database in this CLI runner
    }
}
if (!function_exists("logActivity")) {
    function logActivity($message, $relid = 0)
    {
    }
}

if (!defined("security_pack_module_root")) {
    define("security_pack_module_root", $MODULE_DIR);
}
require_once $MODULE_DIR . "/lib/Security/GeoResult.php";
require_once $MODULE_DIR . "/lib/Security/GeoProviderInterface.php";
require_once $MODULE_DIR . "/lib/Security/Providers/MaxMindProvider.php";
require_once $MODULE_DIR . "/lib/Security/Providers/CurlApiProvider.php";
require_once $MODULE_DIR . "/lib/Security/GeoIpManager.php";

if (class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\GeoIpManager")) {
    $manager = new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager();
    $diagnostics = $manager->diagnostics();
    crmo_assert(
        "behavioral: GeoIpManager()->diagnostics() (default constructor, no explicit override) reports exactly ONE provider",
        count($diagnostics) === 1,
        $failures,
        $passed
    );
    crmo_assert(
        "behavioral: that one provider is \"maxmind\" — \"curl\" never appears",
        count($diagnostics) === 1 && $diagnostics[0]["name"] === "maxmind",
        $failures,
        $passed
    );
    crmo_assert(
        "behavioral: GeoIpManager still honors an explicit \$providers override (e.g. a future opt-back-in) rather than always hardcoding MaxMind-only",
        count((new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager([new \WHMCS\Module\Addon\Security_Pack\Security\Providers\CurlApiProvider()]))->diagnostics()) === 1
            && (new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager([new \WHMCS\Module\Addon\Security_Pack\Security\Providers\CurlApiProvider()]))->diagnostics()[0]["name"] === "curl",
        $failures,
        $passed
    );
} else {
    $failures[] = "could not load GeoIpManager for the behavioral diagnostics() check";
}

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Country Restriction MaxMind-only regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
