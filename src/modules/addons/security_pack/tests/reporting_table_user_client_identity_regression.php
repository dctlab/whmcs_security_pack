<?php

/**
 * DCTLAB Security Pack — regression test for the "Users / 2FA Overview
 * shows the wrong person" bug.
 *
 * BUG: the "Users / 2FA Overview" admin reporting table displayed the
 * wrong name for a `client`/`user` 2FA identity. Concrete reported case:
 *
 *   WHMCS Client ID: 666310
 *   WHMCS User ID:   666316   (already the correct stored 2FA user_id)
 *   Client/User:     Sanitha Mary
 *   Email:           sanitha@the-experience.com
 *
 * The overview rendered "Manoj Kumar (#666316)" instead of
 * "Sanitha Mary (#666316)".
 *
 * ROOT CAUSE: TwoFactorController::resolveUserLabel() looked up a
 * `client`/`user` identity's display name by querying
 * `tblclients.id = $userId`. A client/user 2FA identity's $userId is a
 * WHMCS **User** ID (`tblusers.id` — the same
 * `$params["user_info"]["id"]` every dct_*_2fa provider's
 * _challenge()/_activate() receives), a completely different ID space
 * from `tblclients.id` (see Email2faService::resolveClientIdForUser(),
 * whose entire purpose is separately, best-effort resolving a Client ID
 * FROM a User ID — proof the two are never interchangeable). On this
 * install, User ID 666316 numerically collided with an unrelated
 * tblclients row ("Manoj Kumar"), so the overview showed that unrelated
 * client's name instead of the real User 666316 (Sanitha Mary).
 *
 * FIX: resolveUserLabel() is split into two PURE, DB-free pieces —
 * resolveUserLabelSource(string $userType), which decides table +
 * first/last-name column pair per identity type, and
 * formatUserLabelFromRow($row, $source, $userType), which formats the
 * name from an already-fetched row. client/user now resolves against
 * `tblusers` (columns `first_name`/`last_name` — note the underscore,
 * different from tblclients/tbladmins/tblcontacts's `firstname`/
 * `lastname`) — NEVER `tblclients`. administrator → tbladmins and
 * contact/sub-account → tblcontacts are unchanged.
 *
 * This file asserts the exact Sanitha Mary / User 666316 / Client
 * 666310 case renders correctly, that a tblclients-shaped row
 * (Client 666310, "Manoj Kumar") does NOT coincidentally satisfy the
 * client/user source spec, and audits the whole module tree for any
 * other `tblclients->where("id", $userId)`-shaped User-ID-as-Client-ID
 * confusion. No live database is available in this CLI runner —
 * PURE-function execution plus source-level checks, same technique as
 * this project's other standalone regression files. Run on its own:
 *
 *   php tests/reporting_table_user_client_identity_regression.php
 */

declare(strict_types=1);

define("WHMCS", true);

require __DIR__ . "/../lib/Security/TwoFactor/UserIdentityType.php";

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\UserIdentityType;

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function rtuci_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function rtuci_src(string $path): string
{
    return is_file($path) ? (string) file_get_contents($path) : "";
}

// A TwoFactorController instance is not constructible standalone (its
// constructor pulls in live WHMCS admin dependencies), but
// resolveUserLabelSource()/formatUserLabelFromRow() are `public static`
// PURE functions specifically so they can be exercised here without one.
require $MODULE_DIR . "/lib/Admin/TwoFactorController.php";

use WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController;

// --- The exact reported case: Client 666310 / User 666316 / Sanitha Mary ---

$clientRow = (object) ["id" => 666310, "firstname" => "Manoj", "lastname" => "Kumar", "email" => "manoj@example.com"];
$userRow = (object) ["id" => 666316, "first_name" => "Sanitha", "last_name" => "Mary", "email" => "sanitha@the-experience.com"];

$source = TwoFactorController::resolveUserLabelSource(UserIdentityType::CLIENT);

rtuci_assert(
    "resolveUserLabelSource(CLIENT) resolves against tblusers (User ID space), never tblclients (Client ID space)",
    $source["table"] === "tblusers",
    $failures,
    $passed
);
rtuci_assert(
    "resolveUserLabelSource(CLIENT) uses tblusers' actual column names — first_name/last_name (with the underscore), not tblclients'/tbladmins'/tblcontacts' firstname/lastname",
    $source["first_col"] === "first_name" && $source["last_col"] === "last_name",
    $failures,
    $passed
);

$label = TwoFactorController::formatUserLabelFromRow($userRow, $source, UserIdentityType::CLIENT);
rtuci_assert(
    'Given the real tblusers row for User ID 666316, the resolved display name is exactly "Sanitha Mary" (the reported bug\'s expected-correct value) — never "Manoj Kumar"',
    $label === "Sanitha Mary",
    $failures,
    $passed
);
rtuci_assert(
    "The resolved label is not the unrelated Client 666310 row's name",
    $label !== "Manoj Kumar",
    $failures,
    $passed
);

// The overview's own "{name} (#{id})" formatting is a template-layer
// concern (not resolveUserLabel()'s job — it only returns the bare
// name), but the assembled string is what the bug report actually
// quoted, so assert it end-to-end as the admin would have seen it.
$displayString = $label . " (#" . 666316 . ")";
rtuci_assert(
    'The assembled overview-row string for this case is exactly "Sanitha Mary (#666316)"',
    $displayString === "Sanitha Mary (#666316)",
    $failures,
    $passed
);
rtuci_assert(
    'The assembled overview-row string is never "Manoj Kumar (#666316)" — the exact wrong value the bug report quoted',
    $displayString !== "Manoj Kumar (#666316)",
    $failures,
    $passed
);

// --- Regression guard: a tblclients-shaped row must NOT coincidentally
// resolve correctly through the tblusers-shaped source (proves the fix
// is a real table switch, not a lucky column-name overlap) -------------

$clientShapedLabel = TwoFactorController::formatUserLabelFromRow($clientRow, $source, UserIdentityType::CLIENT);
rtuci_assert(
    "A tblclients-shaped row (firstname/lastname, no first_name/last_name) does not resolve a name through the tblusers-shaped source — it falls back to the generic label, proving the lookup is genuinely keyed off tblusers.id and would simply find no matching row in production rather than silently reading the wrong table's columns",
    $clientShapedLabel === UserIdentityType::label(UserIdentityType::CLIENT),
    $failures,
    $passed
);

// --- Fail-soft behavior is preserved (null row / blank name) -----------

rtuci_assert(
    "A null row (no matching tblusers record) falls back to the generic Client/User label rather than throwing or showing a blank name",
    TwoFactorController::formatUserLabelFromRow(null, $source, UserIdentityType::CLIENT) === UserIdentityType::label(UserIdentityType::CLIENT),
    $failures,
    $passed
);
$blankRow = (object) ["id" => 1, "first_name" => "", "last_name" => ""];
rtuci_assert(
    "A row with blank first/last name also falls back to the generic label, not an empty string",
    TwoFactorController::formatUserLabelFromRow($blankRow, $source, UserIdentityType::CLIENT) === UserIdentityType::label(UserIdentityType::CLIENT),
    $failures,
    $passed
);

// --- Array-row support (Capsule can return arrays depending on fetch
// mode/config) ------------------------------------------------------------

$userRowArray = ["id" => 666316, "first_name" => "Sanitha", "last_name" => "Mary"];
rtuci_assert(
    "formatUserLabelFromRow() also works when the row is a plain array, not just an object (Sanitha Mary case again, array form)",
    TwoFactorController::formatUserLabelFromRow($userRowArray, $source, UserIdentityType::CLIENT) === "Sanitha Mary",
    $failures,
    $passed
);

// --- administrator/contact branches are unchanged by this fix ----------

$adminSource = TwoFactorController::resolveUserLabelSource(UserIdentityType::ADMIN);
rtuci_assert(
    "resolveUserLabelSource(ADMIN) still resolves against tbladmins with firstname/lastname — unchanged by this fix",
    $adminSource === ["table" => "tbladmins", "first_col" => "firstname", "last_col" => "lastname"],
    $failures,
    $passed
);

$contactSource = TwoFactorController::resolveUserLabelSource(UserIdentityType::CONTACT);
rtuci_assert(
    "resolveUserLabelSource(CONTACT) still resolves against tblcontacts with firstname/lastname — unchanged by this fix",
    $contactSource === ["table" => "tblcontacts", "first_col" => "firstname", "last_col" => "lastname"],
    $failures,
    $passed
);

// --- Source-level checks on TwoFactorController.php itself -------------

$controllerSource = rtuci_src($MODULE_DIR . "/lib/Admin/TwoFactorController.php");

rtuci_assert(
    "The old buggy literal — a client/user identity queried straight against tblclients by \$userId — is gone from TwoFactorController.php",
    !preg_match('/\$row\s*=\s*\\\\?Illuminate\\\\Database\\\\Capsule\\\\Manager::table\("tblclients"\)->where\("id",\s*\$userId\)->first\(\)/', $controllerSource),
    $failures,
    $passed
);
rtuci_assert(
    "resolveUserLabel() now delegates to resolveUserLabelSource()/formatUserLabelFromRow() rather than branching on tblclients/tbladmins/tblcontacts inline",
    strpos($controllerSource, "\$source = self::resolveUserLabelSource(\$userType);") !== false
        && strpos($controllerSource, "self::formatUserLabelFromRow(\$row, \$source, \$userType)") !== false,
    $failures,
    $passed
);
rtuci_assert(
    "resolveUserLabel()'s DB lookup is keyed off the resolved \$source[\"table\"] (tblusers for client/user), never a hardcoded tblclients",
    strpos($controllerSource, 'Manager::table($source["table"])->where("id", $userId)->first()') !== false,
    $failures,
    $passed
);

// --- Module-wide audit: no OTHER place in the module resolves a raw
// User ID against tblclients (the same bug class, anywhere else) --------
//
// Deliberately excludes the two ->exists() checks inside
// looksLikeClientIdMistakenForUserId() (a DIFFERENT, already-correct
// guard in the admin bypass-creation flow that checks tblusers AND
// tblclients to detect an admin mistakenly typing a Client ID into a
// "User ID" field — that guard's tblclients existence-check is
// intentional and is covered by its own regression test,
// admin_bypass_client_user_identity_regression.php).

$auditHits = [];
$roots = [$MODULE_DIR . "/lib", $MODULE_DIR . "/core", $MODULE_DIR . "/templates"];
$secDir = dirname($MODULE_DIR, 2) . "/security";
if (is_dir($secDir)) {
    $roots[] = $secDir;
}
foreach ($roots as $root) {
    if (!is_dir($root)) {
        continue;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->getExtension() !== "php") {
            continue;
        }
        $path = $file->getPathname();
        $src = (string) file_get_contents($path);
        if (preg_match('/table\("tblclients"\)\s*->where\("id",\s*\$userId\)\s*->first\(\)/', $src)) {
            $auditHits[] = $path;
        }
    }
}
rtuci_assert(
    "Module-wide audit: no file under lib/, core/, templates/, or the sibling security/ modules resolves a raw \$userId against tblclients via ->first() (the exact User-ID-as-Client-ID display bug) anywhere else in the codebase" . ($auditHits ? " — found in: " . implode(", ", $auditHits) : ""),
    count($auditHits) === 0,
    $failures,
    $passed
);

// --- Sibling guard (looksLikeClientIdMistakenForUserId) is untouched by
// this fix — a quick smoke check that its intentional tblclients
// ->exists() checks are still present, so this file's audit above is
// verifiably not what's making the module clean ---------------------------

rtuci_assert(
    "The unrelated looksLikeClientIdMistakenForUserId() guard (admin bypass-creation flow) is still present and untouched by this display-bug fix",
    strpos($controllerSource, "private static function looksLikeClientIdMistakenForUserId(int \$userId, string \$userType): ?array") !== false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Reporting-table User/Client identity regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
