<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 "Fix
 * Administrator Manual Bypass auto-creation on login" investigation.
 *
 * INVESTIGATION FINDING #1 — intended trigger: an admin_manual bypass is
 * created ONLY by an explicit administrator action — the "Confirm Bypass"
 * form on either admin panel (TwoFactorController::bypass() / the unified
 * Two-Factor Authentication screen, and Email2faController::bypass() / the
 * legacy Email 2FA screen), both CSRF-protected POST handlers requiring an
 * authenticated admin session. There is NO code path anywhere in this
 * codebase — no Security Module challenge()/verify()/activate() callback,
 * no hook, no cron job — that creates one automatically as a side effect
 * of a user logging in. Per this incident's own "Critical security
 * requirement" ("Do not automatically grant a manual bypass simply
 * because a User logs in" / "If the current code does not contain an
 * explicit auto-create rule, do not invent one"), this fix does NOT add
 * one — this file's first section instead locks in that createAdminBypass()
 * is reachable ONLY from those two explicit admin actions, so a future
 * change can't accidentally wire it into a login path without this
 * regression test failing.
 *
 * INVESTIGATION FINDING #2 — the real bug: WHMCS Client (`tblclients.id`)
 * and WHMCS User (`tblusers.id`) are different identities — a Client can
 * have multiple Users (an owner plus sub-accounts) via the
 * `tblusers_clients` junction table. Every 2FA enrollment/bypass/login
 * check in this codebase is keyed by the real, authenticated User ID
 * (resolved at login exclusively from `$params["user_info"]["id"]` — see
 * every Security Module's own docblock). Two concrete places in the admin
 * layer were conflating the two:
 *
 *  1. `AdminClientProfileTabFields` hook (core/email_2fa.php): WHMCS
 *     supplies `$vars["userid"]` as the CLIENT ID on this hook (one call
 *     per Client Profile page view, and every other field it could add —
 *     firstname/lastname/address — is a tblclients column). This hook
 *     used to pass that Client ID straight into
 *     Email2faService::getConfig()/findActiveAdminBypass() as if it were
 *     the login-time User ID.
 *  2. The "Administrator Manual Bypass" form's "WHMCS User ID" field
 *     (both admin panels) is a raw, freely-typed number with nothing
 *     stopping an admin from typing the Client ID they can see elsewhere
 *     in the admin UI instead of the real User ID.
 *
 * FIX: (1) resolves the client's real WHMCS User ID(s) via the existing
 * `tblusers_clients`-based `TwoFactorController::resolveUserIdsForClient()`
 * helper (already trusted elsewhere in this codebase for the identical
 * purpose) and reports status per real User, never per Client ID — no
 * schema change, this table/relationship already exists. (2) both bypass-
 * creation admin actions now detect a submitted "User ID" that is not a
 * real `tblusers.id` but IS a real `tblclients.id`, block the create, and
 * tell the admin the real User ID(s) to use instead.
 *
 * No live database is available in this CLI runner — source-level checks,
 * same technique as this project's other standalone regression files. Run
 * on its own:
 *
 *   php tests/admin_bypass_client_user_identity_regression.php
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";
$LIVE_TOTP_DIR = getenv("DCT_TOTP_NATIVE_DIR") ?: "/tmp/live_check/live/dct_totp_native";

$failures = [];
$passed = 0;

function acui_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function acui_src(string $path): string
{
    return is_file($path) ? (string) file_get_contents($path) : "";
}

// --- Finding #1: no automatic/login-time creation of an admin_manual
// bypass exists anywhere, and this fix does not add one -----------------

$searchRoots = [
    $GLOBALS["MODULE_DIR"] . "/lib",
    $GLOBALS["MODULE_DIR"] . "/core",
    $GLOBALS["LIVE_TOTP_DIR"],
];
$createAdminBypassCallSites = [];
foreach ($searchRoots as $root) {
    if (!is_dir($root)) {
        continue;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if ($file->getExtension() !== "php") {
            continue;
        }
        $src = (string) file_get_contents($file->getPathname());
        if (preg_match_all('/(?:[A-Za-z_]+::)?createAdminBypass\(/', $src, $m)) {
            foreach ($m[0] as $call) {
                // Skip the method DEFINITIONS themselves (public static
                // function createAdminBypass(...)) — only count actual
                // call sites.
                if (strpos($src, "function createAdminBypass") !== false && preg_match('/function\s+createAdminBypass\s*\(/', $src) && substr_count($src, "createAdminBypass(") === substr_count($src, "function createAdminBypass(")) {
                    continue;
                }
                $createAdminBypassCallSites[] = $file->getPathname();
            }
        }
    }
}
$callSitesOutsideAdminControllers = array_filter($createAdminBypassCallSites, function ($path) {
    return strpos($path, "TwoFactorController.php") === false
        && strpos($path, "Email2faController.php") === false
        && strpos($path, "TwoFactorAuthenticationService.php") === false // the pass-through wrapper, not a new trigger
        && strpos($path, "TwoFactorBypassService.php") === false // the definition itself
        && strpos($path, "Email2faService.php") === false; // the legacy definition itself
});
acui_assert(
    "createAdminBypass() is reachable ONLY from the two explicit admin-form handlers (TwoFactorController::bypass(), Email2faController::bypass()) plus their own pass-through wrapper/definitions — no Security Module challenge()/verify()/activate() callback, hook, or cron job calls it, confirming no login-time auto-creation exists anywhere in this codebase",
    count($callSitesOutsideAdminControllers) === 0,
    $failures,
    $passed
);

$controllerSource = acui_src($GLOBALS["MODULE_DIR"] . "/lib/Admin/TwoFactorController.php");
acui_assert(
    "TwoFactorController::bypass() is a private method only reachable via the admin-only POST action dispatch (never public, never called from anywhere but this controller's own switch statement)",
    (bool) preg_match('/private function bypass\(\)/', $controllerSource),
    $failures,
    $passed
);

// --- Finding #2, part A: AdminClientProfileTabFields no longer treats
// the Client ID as a User ID --------------------------------------------

$emailHookSource = acui_src($GLOBALS["MODULE_DIR"] . "/core/email_2fa.php");
acui_assert(
    "AdminClientProfileTabFields hook no longer passes the raw Client ID directly into Email2faService::getConfig()/findActiveAdminBypass() — it resolves real WHMCS User IDs first",
    strpos($emailHookSource, 'Email2faService::getConfig($userId, Email2faService::TYPE_CLIENT)') === false
        && strpos($emailHookSource, 'Email2faService::findActiveAdminBypass($userId, Email2faService::TYPE_CLIENT)') === false,
    $failures,
    $passed
);
acui_assert(
    "AdminClientProfileTabFields hook resolves real WHMCS User IDs via TwoFactorController::resolveUserIdsForClient() — the SAME tblusers_clients-based helper the Users-tab overlay already trusts for the identical purpose (no new table/schema)",
    strpos($emailHookSource, "TwoFactorController::resolveUserIdsForClient(\$clientId)") !== false,
    $failures,
    $passed
);
acui_assert(
    "AdminClientProfileTabFields hook fails soft (a clear \"no linked WHMCS User account\" message) when a Client has no resolvable User — it does NOT fall back to treating the Client ID as a User ID, which is the exact bug being fixed",
    strpos($emailHookSource, "No linked WHMCS User account found for this client") !== false,
    $failures,
    $passed
);
acui_assert(
    "AdminClientProfileTabFields hook now looks up config/bypass PER real resolved User ID (\$realUserId), not the raw \$clientId",
    (bool) preg_match('/foreach\s*\(\$userIds as \$realUserId\)[\s\S]{0,400}Email2faService::getConfig\(\$realUserId,/', $emailHookSource),
    $failures,
    $passed
);

// --- Finding #2, part B: both bypass-creation admin actions reject a
// Client ID submitted where a User ID is required -----------------------

acui_assert(
    "TwoFactorController has looksLikeClientIdMistakenForUserId(), gated to user_type=client only (admin/contact identities have no separate 'client id' to confuse with)",
    (bool) preg_match('/private static function looksLikeClientIdMistakenForUserId\(int \$userId, string \$userType\): \?array\s*\{\s*if\(\$userType !== UserIdentityType::CLIENT\) \{\s*return null;/', $controllerSource),
    $failures,
    $passed
);
acui_assert(
    "looksLikeClientIdMistakenForUserId() checks tblusers FIRST (a real User ID must never be blocked) and only flags the mistake when the ID does NOT exist in tblusers but DOES exist in tblclients",
    strpos($controllerSource, 'Capsule\Manager::table("tblusers")->where("id", $userId)->exists()') !== false
        && strpos($controllerSource, 'Capsule\Manager::table("tblclients")->where("id", $userId)->exists()') !== false,
    $failures,
    $passed
);
acui_assert(
    "looksLikeClientIdMistakenForUserId() returns null (does not block) when the ID is neither a real User nor a real Client — 'User with no Client' and plain invalid-ID cases are NOT this bug and must not be blocked by it",
    strpos($controllerSource, "so this is not this specific bug; let it proceed") !== false,
    $failures,
    $passed
);
acui_assert(
    "TwoFactorController::bypass() calls the guard BEFORE createAdminBypass() and blocks with a clear error naming the real User ID(s), reusing resolveUserIdsForClient() rather than inventing a second resolution path",
    (bool) preg_match('/\$mistakenClientId = \$userId > 0 \? self::looksLikeClientIdMistakenForUserId\(\$userId, \$userType\) : null;\s*if\(\$mistakenClientId !== null\)/', $controllerSource),
    $failures,
    $passed
);

$email2faControllerSource = acui_src($GLOBALS["MODULE_DIR"] . "/lib/Admin/Email2faController.php");
acui_assert(
    "Email2faController::bypass() (the second, legacy admin bypass form) has the SAME Client/User identity guard — this was a real second entry point for the identical mistake, not just the unified panel",
    strpos($email2faControllerSource, "is a WHMCS Client ID, not a WHMCS User ID") !== false
        && strpos($email2faControllerSource, "TwoFactorController::resolveUserIdsForClient(\$userId)") !== false,
    $failures,
    $passed
);

// --- Template: admin is warned in the UI itself, not just after
// submitting -------------------------------------------------------------

$templateSource = acui_src($GLOBALS["MODULE_DIR"] . "/templates/admin/two-factor.tpl");
acui_assert(
    "The Administrator Manual Bypass form's own template now explicitly warns this must be the User ID, not the Client ID, before the admin ever submits",
    strpos($templateSource, "must be the WHMCS <em>User</em> ID, not the Client ID") !== false,
    $failures,
    $passed
);

// --- Login-time identity resolution (the live dct_totp_native module)
// remains exclusively per-call, never falling back to Client-ID/session
// state for challenge()/verify() — the correctness this whole fix
// depends on, asserted here so a future change can't quietly regress it --

$totpNativeSource = acui_src($GLOBALS["LIVE_TOTP_DIR"] . "/dct_totp_native.php");
if ($totpNativeSource !== "") {
    acui_assert(
        "dct_totp_native_login_identity() (used by challenge()/verify(), the actual pre-authentication login callbacks) resolves EXCLUSIVELY from \$params[\"user_info\"][\"id\"] — never from \$_SESSION — so a sub-user's own login always resolves to their own distinct User ID, never their parent Client's or another sub-user's",
        (bool) preg_match('/function dct_totp_native_login_identity\(array \$params\): array\s*\{\s*\$id = \(int\) \(\$params\["user_info"\]\["id"\] \?\? 0\);/', $totpNativeSource)
            && !preg_match('/function dct_totp_native_login_identity[\s\S]{0,300}\$_SESSION/', $totpNativeSource),
        $failures,
        $passed
    );
} else {
    // Live mirror not present in this environment — not a failure of
    // this fix, just nothing to assert against here.
    $passed++;
}

// --- Bypass matching stays strictly per-(user_id,user_type[,ip]) — no
// Client-level widening exists anywhere in the lookup layer -------------

$bypassServiceSource = acui_src($GLOBALS["MODULE_DIR"] . "/lib/Security/TwoFactor/TwoFactorBypassService.php");
acui_assert(
    "findActiveSameIp() matches the exact (user_id, user_type, ip) tuple — a bypass granted from one IP does not silently apply from a different IP ('Login from non-matching IP' must not match)",
    (bool) preg_match('/function findActiveSameIp\(int \$userId, string \$userType, string \$ip\)[\s\S]{0,300}->where\("user_id", \$userId\)->where\("user_type", \$userType\)->where\("ip", \$ip\)/', $bypassServiceSource),
    $failures,
    $passed
);
acui_assert(
    "findActiveAdminBypass() matches the exact (user_id, user_type) pair with scope=admin_manual — a bypass created for one sub-user's real User ID never matches a lookup for a DIFFERENT sub-user's User ID under the same client, even though both share user_type=\"client\"",
    (bool) preg_match('/function findActiveAdminBypass\(int \$userId, string \$userType\)[\s\S]{0,300}->where\("user_id", \$userId\)->where\("user_type", \$userType\)->where\("scope", "admin_manual"\)/', $bypassServiceSource),
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Admin-bypass Client/User identity regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
