<?php

/**
 * Security Pack — regression test for the 2026-08-27 admin navigation
 * menu reorder/regroup request:
 *
 *   Overview
 *   Two-Factor Authentication
 *   Protection ▼ [IP Restrictions, Country Restrictions, Disabled Reset
 *                 Password Clients]
 *   Activity ▼   [All Events, Analytics, Anomalies, Alerts]
 *   Login History
 *   Language & Currency
 *   System ▼     [Security Diagnostics, CSP Reports]
 *   Settings
 *
 * SCOPE: purely a display-order/grouping change. No route, permission,
 * page content, database, or security logic was touched — every href/
 * address in security_pack.php's $page_manager->menu[...] construction
 * is byte-for-byte the same string as before this change, and no menu
 * item was removed or duplicated.
 *
 * "IP Security Limited Clients" is NOT part of the user's given target
 * tree, but it is still a live, reachable controller/route
 * (c=ipLimitedClients) — kept available exactly once, appended to the
 * end of the "Protection" dropdown, per the explicit instruction "Do not
 * create duplicate menu entries. Keep each existing page available
 * exactly once."
 *
 * navigation.tpl previously rendered ALL $menuGroups dropdowns first,
 * then ALL ungrouped $menu items — dropdowns could never be interleaved
 * with top-level items, which made the requested order (alternating
 * ungrouped items and dropdowns) unrenderable. Fixed with a single pass
 * over $menu in insertion order: each dropdown now renders at the
 * position of its first member's position in $menu. This test verifies
 * both the new $menu/$menuGroups data AND the actual rendered output
 * order (a direct behavioral check, not just source pattern matching).
 *
 * Run alongside the other test files here, not merged into run.php
 * (matching this project's established convention for a standalone
 * feature regression file — see e.g.
 * admin_bypass_client_user_identity_regression.php's own docblock):
 *
 *   php tests/nav_menu_reorder_regression.php
 */

declare(strict_types=1);

define("WHMCS", true);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function nmr_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

$securityPackSrc = (string) file_get_contents($MODULE_DIR . "/security_pack.php");
$navTplSrc = (string) file_get_contents($MODULE_DIR . "/templates/admin/navigation.tpl");

// --- Source-level: every existing href/address string is unchanged ------

$expectedHrefs = [
    "Overview" => "",
    "Two-Factor Authentication" => "c=twoFactor",
    "IP Restrictions" => "c=ipRestrictions",
    "Country Restrictions" => "c=countryRestriction",
    "Disabled Reset Password Clients" => "c=passwordDisabled",
    "IP Security Limited Clients" => "c=ipLimitedClients",
    "All Events" => "c=activity",
    "Analytics" => "c=analytics",
    "Anomalies" => "c=anomalies",
    "Alerts" => "c=alerts",
    "Login History" => "c=LoginLogs",
    "Language & Currency" => "c=langCurrency",
    "Security Diagnostics" => "c=diagnostics",
    "CSP Reports" => "c=cspReports",
    "Settings" => "c=settings",
];
foreach ($expectedHrefs as $label => $href) {
    nmr_assert(
        "menu item \"$label\" still has its original href (\"$href\") — no route changed",
        strpos($securityPackSrc, '$page_manager->menu["' . $label . '"] = ["href" => "' . $href . '"') !== false,
        $failures,
        $passed
    );
}

// --- Source-level: menuGroups reduced to exactly the 3 requested groups,
// each with the exact requested sub-item order --------------------------

nmr_assert(
    "menuGroups defines exactly \"Protection\", \"Activity\", \"System\" — the single-item \"Authentication\"/\"Geo & Localization\"/\"Clients\" groups from before this change are gone (those items are top-level now)",
    strpos($securityPackSrc, '"Authentication" =>') === false
        && strpos($securityPackSrc, '"Geo & Localization" =>') === false
        && strpos($securityPackSrc, '"Clients" =>') === false,
    $failures,
    $passed
);
nmr_assert(
    "\"Protection\" group is exactly [IP Restrictions, Country Restrictions, Disabled Reset Password Clients, IP Security Limited Clients] in that order",
    strpos($securityPackSrc, '"Protection" => ["IP Restrictions", "Country Restrictions", "Disabled Reset Password Clients", "IP Security Limited Clients"]') !== false,
    $failures,
    $passed
);
nmr_assert(
    "\"Activity\" group is exactly [All Events, Analytics, Anomalies, Alerts] in that order — unchanged from before",
    strpos($securityPackSrc, '"Activity" => ["All Events", "Analytics", "Anomalies", "Alerts"]') !== false,
    $failures,
    $passed
);
nmr_assert(
    "\"System\" group is exactly [Security Diagnostics, CSP Reports] in that order — unchanged from before",
    strpos($securityPackSrc, '"System" => ["Security Diagnostics", "CSP Reports"]') !== false,
    $failures,
    $passed
);

// --- Source-level: $menu insertion order places each group's first
// member exactly where the dropdown must render ---------------------------

$pos = [];
foreach (array_keys($expectedHrefs) as $label) {
    $pos[$label] = strpos($securityPackSrc, '$page_manager->menu["' . $label . '"] =');
    nmr_assert("menu item \"$label\" is present exactly once in \$page_manager->menu", $pos[$label] !== false, $failures, $passed);
}
nmr_assert(
    "\$menu insertion order: Overview < Two-Factor Authentication < IP Restrictions (Protection anchor) < All Events (Activity anchor) < Language & Currency < Security Diagnostics (System anchor) < Settings",
    $pos["Overview"] < $pos["Two-Factor Authentication"]
        && $pos["Two-Factor Authentication"] < $pos["IP Restrictions"]
        && $pos["IP Restrictions"] < $pos["All Events"]
        && $pos["All Events"] < $pos["Language & Currency"]
        && $pos["Language & Currency"] < $pos["Security Diagnostics"]
        && $pos["Security Diagnostics"] < $pos["Settings"],
    $failures,
    $passed
);
nmr_assert(
    "Login History sits between the Activity group members and Language & Currency in \$menu insertion order, matching its top-level target position",
    isset($pos["Login History"]) && $pos["Alerts"] < $pos["Login History"] && $pos["Login History"] < $pos["Language & Currency"],
    $failures,
    $passed
);

// --- Source-level: navigation.tpl renders in a single interleaved pass,
// not "all groups then all ungrouped" ------------------------------------

nmr_assert(
    "navigation.tpl no longer has two separate foreach passes (menuGroups-first, then ungrouped \$menu) — it now does one foreach(\$menu) pass",
    substr_count($navTplSrc, "foreach (\$menu as \$label => \$item)") === 1
        && strpos($navTplSrc, "foreach (\$menuGroups as \$groupLabel => \$keys):") === false,
    $failures,
    $passed
);
nmr_assert(
    "navigation.tpl renders a group's dropdown at the position of that group's FIRST member as encountered while iterating \$menu, and skips later members of an already-rendered group",
    strpos($navTplSrc, "\$renderedGroups[\$groupLabel] = true;") !== false
        && strpos($navTplSrc, "if(isset(\$renderedGroups[\$groupLabel])) {") !== false,
    $failures,
    $passed
);

// --- Behavioral: actually render the navigation and assert the real
// output order matches the exact requested tree ---------------------------

require $MODULE_DIR . "/lib/Admin/template_functions.php";

$settingsAllOn = ["login_history" => "on", "password_reset" => "on", "ip_range_limits" => "on"];
$page_manager = new class {
    public $menu = [];
    public $menuGroups = [];
};
$blockStart = strpos($securityPackSrc, '$page_manager->menu["Overview"]');
$blockEnd = strpos($securityPackSrc, '$bareOutputActions = ["user"];');
if ($blockStart !== false && $blockEnd !== false) {
    $settings = $settingsAllOn;
    eval(substr($securityPackSrc, $blockStart, $blockEnd - $blockStart));
}

if (count($page_manager->menu) > 0) {
    $menu = $page_manager->menu;
    $menuGroups = $page_manager->menuGroups;
    $modulelink = "security_pack";
    $activeAddress = "";

    ob_start();
    include $MODULE_DIR . "/templates/admin/navigation.tpl";
    $html = (string) ob_get_clean();

    preg_match_all('/<a[^>]*>\s*([^<]+?)\s*(?:<span class="caret">.*?<\/span>)?\s*<\/a>/s', $html, $labelMatches);
    $renderedTopLevel = [];
    // Only keep labels that are direct children of the root <ul> (i.e.
    // NOT inside a nested <ul class="dropdown-menu">...</ul>) — strip
    // dropdown-menu contents first, then extract what's left.
    $withoutDropdownContents = (string) preg_replace('#<ul class="dropdown-menu">.*?</ul>#s', '', $html);
    preg_match_all('/<a[^>]*>\s*([^<]+?)\s*(?:<span class="caret">.*?<\/span>)?\s*<\/a>/s', $withoutDropdownContents, $topLevelMatches);
    foreach ($topLevelMatches[1] as $label) {
        $renderedTopLevel[] = html_entity_decode(trim($label));
    }

    nmr_assert(
        "rendered top-level nav order is EXACTLY: Overview, Two-Factor Authentication, Protection, Activity, Login History, Language & Currency, System, Settings — matching the requested target tree",
        $renderedTopLevel === [
            "Overview",
            "Two-Factor Authentication",
            "Protection",
            "Activity",
            "Login History",
            "Language & Currency",
            "System",
            "Settings",
        ],
        $failures,
        $passed
    );

    nmr_assert(
        "the rendered \"Protection\" dropdown contains all 4 items, including \"IP Security Limited Clients\" (kept available, not dropped)",
        strpos($html, ">IP Restrictions<") !== false
            && strpos($html, ">Country Restrictions<") !== false
            && strpos($html, ">Disabled Reset Password Clients<") !== false
            && strpos($html, ">IP Security Limited Clients<") !== false,
        $failures,
        $passed
    );

    nmr_assert(
        "every menu label appears exactly once in the rendered output — no duplicate menu entries",
        (function () use ($html) {
            foreach (["Overview", "Two-Factor Authentication", "IP Restrictions", "Country Restrictions", "Disabled Reset Password Clients", "IP Security Limited Clients", "All Events", "Analytics", "Anomalies", "Alerts", "Login History", "Language &amp; Currency", "Security Diagnostics", "CSP Reports", "Settings"] as $label) {
                if (substr_count($html, ">" . $label . "<") !== 1) {
                    return false;
                }
            }
            return true;
        })(),
        $failures,
        $passed
    );

    // --- Active-state behavior preserved for both an ungrouped item and
    // a grouped (dropdown) item ---------------------------------------
    foreach (["twoFactor" => "Two-Factor Authentication (ungrouped)", "ipRestrictions" => "Protection dropdown (grouped item)"] as $addr => $desc) {
        $activeAddress = $addr;
        ob_start();
        include $MODULE_DIR . "/templates/admin/navigation.tpl";
        $activeHtml = (string) ob_get_clean();
        nmr_assert(
            "active-state class still applies correctly when the current page is \"$desc\"",
            strpos($activeHtml, 'class="active"') !== false || strpos($activeHtml, 'dropdown active') !== false,
            $failures,
            $passed
        );
    }
} else {
    $failures[] = "could not evaluate security_pack.php's menu-construction block in isolation — behavioral render check skipped";
}

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Security Pack nav-menu-reorder regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
