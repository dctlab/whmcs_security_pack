<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-09-23 "WhatsApp 2FA
 * offered/sent a code to a different client's phone number" investigation.
 *
 * REPORTED CASE: WHMCS User #666043 (login rajesh@orangelabz.com) is a
 * real, legitimate authorized user on THREE separate WHMCS Client
 * accounts (a `tblusers_clients` junction fact, confirmed live via
 * Admin > Users > Manage User): #666250 (Shabeer Ahammed / Orbiz
 * Creativez Pvt Ltd, phone +91.9020044994), #666308 (Rajesh jayadevan —
 * this user's OWN account, phone +91.9846560111), and #666338 (Suhad
 * KT). Opening "Enable Two-Factor Authentication" (WhatsApp) from
 * Rajesh's own account showed a code already sent to a number ending
 * "...994" — Shabeer's (#666250's) stored phone, not Rajesh's own.
 *
 * ROOT CAUSE: WhatsAppTwoFactorService::resolveClientIdForUser() picked
 * the numerically LOWEST matching `tblusers_clients.client_id` — a raw
 * `->orderBy($clientCol, "asc")->value($clientCol)` — whenever a User
 * was linked to more than one Client. #666250 < #666308 < #666338, so
 * the unrelated #666250 silently won every time, regardless of which
 * account the 2FA action was actually for. The same "lowest id wins"
 * shortcut applied to the email-match fallback (`tblclients.email`)
 * too — two different Client accounts can share an email address in
 * WHMCS. This directly contradicted resolveAccountPhone()'s own
 * documented contract ("...never silently switching the destination").
 *
 * FIX: WhatsAppTwoFactorService::pickUnambiguousClientId(array
 * $candidateIds): ?int — a PURE function — now decides this: returns
 * the id only when there is EXACTLY ONE distinct real candidate,
 * otherwise null (fail soft — no phone resolved, exactly like "no match
 * at all" already behaved). resolveClientIdForUser() fetches every
 * distinct candidate (not just the first, ordered one) for both the
 * junction-table step and the email-match fallback, and routes each
 * through pickUnambiguousClientId(). A second, defense-in-depth gate,
 * DctWhatsAppNotificationsBridge::clientOwnsPhone(), stops the
 * templated (addon-driven, $clientId-only) send path from ever being
 * used unless that client's OWN stored phone number actually matches
 * the verified destination phone the OTP is for — otherwise the send
 * falls through to sendPlainMessage($phoneNumber), which always
 * addresses the correct, already-known number directly.
 *
 * No live database is available in this CLI runner — PURE-function
 * execution plus source-level checks, same technique as this project's
 * other standalone regression files. Run on its own:
 *
 *   php tests/whatsapp_cross_client_phone_regression.php
 */

declare(strict_types=1);

define("WHMCS", true);

$MODULE_DIR = __DIR__ . "/..";

require $MODULE_DIR . "/lib/Security/TwoFactor/OtpEngine.php";
require $MODULE_DIR . "/lib/Security/TwoFactor/WhatsAppTwoFactorService.php";

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\WhatsAppTwoFactorService;

$failures = [];
$passed = 0;

function wccp_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function wccp_src(string $path): string
{
    return is_file($path) ? (string) file_get_contents($path) : "";
}

// --- The exact reported case: User #666043 linked to Clients
// #666250 / #666308 / #666338 (three distinct candidates) ----------------

wccp_assert(
    "pickUnambiguousClientId() refuses to guess when User #666043 is linked to all three real Client accounts (#666250, #666308, #666338) — returns null rather than silently picking the lowest (#666250, Shabeer Ahammed's account, the exact wrong destination this bug delivered to)",
    WhatsAppTwoFactorService::pickUnambiguousClientId([666250, 666308, 666338]) === null,
    $failures,
    $passed
);
wccp_assert(
    "pickUnambiguousClientId() specifically never returns #666250 (Shabeer Ahammed / Orbiz Creativez) for this candidate set — the reported wrong destination",
    WhatsAppTwoFactorService::pickUnambiguousClientId([666250, 666308, 666338]) !== 666250,
    $failures,
    $passed
);
wccp_assert(
    "pickUnambiguousClientId() order-independence — the same three candidates in a different order (as a real, unordered junction-table result set might arrive) still resolve to null, not whichever happens to sort first",
    WhatsAppTwoFactorService::pickUnambiguousClientId([666308, 666338, 666250]) === null,
    $failures,
    $passed
);

// --- Unambiguous cases still resolve normally (no regression for the
// common, single-client-account case) ------------------------------------

wccp_assert(
    "pickUnambiguousClientId() still resolves a single real candidate normally — Client #666308 alone (e.g. Rajesh's OWN account, in isolation) resolves to 666308",
    WhatsAppTwoFactorService::pickUnambiguousClientId([666308]) === 666308,
    $failures,
    $passed
);
wccp_assert(
    "pickUnambiguousClientId() treats duplicate rows for the SAME client id as unambiguous (still exactly one DISTINCT candidate), not as a false ambiguity",
    WhatsAppTwoFactorService::pickUnambiguousClientId([666308, 666308, 666308]) === 666308,
    $failures,
    $passed
);
wccp_assert(
    "pickUnambiguousClientId() returns null for no candidates at all (unchanged fail-soft behavior for 'no match')",
    WhatsAppTwoFactorService::pickUnambiguousClientId([]) === null,
    $failures,
    $passed
);
wccp_assert(
    "pickUnambiguousClientId() ignores non-positive/junk ids (0, negative) rather than counting them as real candidates",
    WhatsAppTwoFactorService::pickUnambiguousClientId([0, -1, 666308]) === 666308,
    $failures,
    $passed
);

// --- OtpEngine::normalizePhoneForComparison() — the defense-in-depth
// gate's comparison primitive -------------------------------------------

wccp_assert(
    'normalizePhoneForComparison() treats "+91.9846560111", "+919846560111", "09846560111", and "9846560111" (Rajesh\'s #666308 number in differing formats) as the SAME number',
    OtpEngine::normalizePhoneForComparison("+91.9846560111") === OtpEngine::normalizePhoneForComparison("+919846560111")
        && OtpEngine::normalizePhoneForComparison("+91.9846560111") === OtpEngine::normalizePhoneForComparison("09846560111")
        && OtpEngine::normalizePhoneForComparison("+91.9846560111") === OtpEngine::normalizePhoneForComparison("9846560111"),
    $failures,
    $passed
);
wccp_assert(
    "normalizePhoneForComparison() treats Rajesh's #666308 number (+91.9846560111) and Shabeer's #666250 number (+91.9020044994) — the two real numbers this exact bug confused — as DIFFERENT",
    OtpEngine::normalizePhoneForComparison("+91.9846560111") !== OtpEngine::normalizePhoneForComparison("+91.9020044994"),
    $failures,
    $passed
);
wccp_assert(
    "normalizePhoneForComparison() returns an empty string for a blank/null number rather than matching everything",
    OtpEngine::normalizePhoneForComparison("") === "" && OtpEngine::normalizePhoneForComparison(null) === "",
    $failures,
    $passed
);

// --- Source-level checks: the fix is actually wired up as described ----

$whatsappSource = wccp_src($MODULE_DIR . "/lib/Security/TwoFactor/WhatsAppTwoFactorService.php");

wccp_assert(
    "resolveClientIdForUser()'s tblusers_clients step no longer takes the raw ->orderBy(...)->value(...) lowest-id shortcut — it fetches every candidate via ->pluck() and routes it through pickUnambiguousClientId()",
    strpos($whatsappSource, '->where($userCol, $userId)->pluck($clientCol)->all()') !== false
        && !preg_match('/where\(\$userCol,\s*\$userId\)->orderBy\(\$clientCol/', $whatsappSource),
    $failures,
    $passed
);
wccp_assert(
    "resolveClientIdForUser()'s email-match fallback also fetches every candidate via ->pluck() and routes it through pickUnambiguousClientId(), not the raw lowest-id ->orderBy(\"id\", \"asc\")->value(\"id\") shortcut",
    strpos($whatsappSource, 'where("email", $userEmail)->pluck("id")->all()') !== false
        && !preg_match('/where\("email",\s*\$userEmail\)->orderBy\("id"/', $whatsappSource),
    $failures,
    $passed
);
wccp_assert(
    "Both resolution steps call self::pickUnambiguousClientId(\$candidateIds) exactly as the pure function above expects",
    substr_count($whatsappSource, "self::pickUnambiguousClientId(\$candidateIds)") === 2,
    $failures,
    $passed
);

$bridgeSource = wccp_src($MODULE_DIR . "/lib/Security/TwoFactor/Providers/DctWhatsAppNotificationsBridge.php");

wccp_assert(
    "DctWhatsAppNotificationsBridge::sendCode() gates the templated (\$clientId-addon-driven) send path on clientOwnsPhone(\$clientId, \$phoneNumber) — it can no longer hand the addon a bare \$clientId without first confirming that client actually owns the destination number",
    (bool) preg_match('/if\s*\(\s*\$userType === "client" && \$clientId !== null && \$clientId > 0 && self::clientOwnsPhone\(\$clientId, \$phoneNumber\)\s*\)/', $bridgeSource),
    $failures,
    $passed
);
wccp_assert(
    "clientOwnsPhone() compares via OtpEngine::normalizePhoneForComparison() (tolerant of formatting) rather than a brittle exact string match, and fails soft (false) on any DB error — never lets an exception make the templated path look safe by accident",
    strpos($bridgeSource, "OtpEngine::normalizePhoneForComparison(\$storedPhone) === OtpEngine::normalizePhoneForComparison(\$phoneNumber)") !== false
        && (bool) preg_match('/private static function clientOwnsPhone\(int \$clientId, string \$phoneNumber\): bool\s*\{\s*try\s*\{/', $bridgeSource),
    $failures,
    $passed
);
wccp_assert(
    "A missing/blank stored phone on the candidate client is treated as NOT owning the destination number (clientOwnsPhone returns false for an empty \$storedPhone) — never a vacuous match",
    (bool) preg_match('/if\s*\(\$storedPhone === ""\)\s*\{\s*return false;/', $bridgeSource),
    $failures,
    $passed
);

// --- Sibling awareness: Email2faService::resolveClientIdForUser() has
// the SAME latent "lowest id wins" shape, deliberately left unmodified
// here (this fix's scope is the WhatsApp path this bug report is about)
// — but it is already safely GATED at its one call site (an exact,
// byte-for-byte client-email == user-email match before ever being
// trusted as a send destination — see that file's own 2026-08-26
// SEVENTH-correction docblock), unlike the WhatsApp path this bug
// exploited, which used to trust it unconditionally. This assertion
// exists so a future change that loosens that gate — or copies the
// unguarded pattern into a NEW call site — fails this suite rather than
// going unnoticed.
$email2faSource = wccp_src($MODULE_DIR . "/lib/Security/Email2faService.php");
wccp_assert(
    "Email2faService's own resolveClientIdForUser() result is still only trusted as an email send destination when byte-for-byte identical to the target user's own email (strcasecmp === 0) — its pre-existing safety gate is untouched by this fix",
    strpos($email2faSource, "strcasecmp(\$clientEmail, \$email) === 0") !== false,
    $failures,
    $passed
);

// --- Module-wide audit: no OTHER unguarded "lowest id wins" client
// resolution was introduced/left anywhere a WhatsApp send could reach --

$auditHits = [];
$roots = [$MODULE_DIR . "/lib", $MODULE_DIR . "/core"];
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
        if (strpos($path, "WhatsAppTwoFactorService.php") !== false || strpos($path, "DctWhatsAppNotificationsBridge.php") !== false) {
            continue; // already asserted precisely above
        }
        $src = (string) file_get_contents($path);
        if (preg_match('/tblusers_clients"\)\s*\n?\s*->where\([^)]*\)->orderBy\([^)]*"asc"\)->value\(/', $src)) {
            $auditHits[] = $path;
        }
    }
}
wccp_assert(
    "Module-wide audit: no other file under lib/ or core/ resolves a WHMCS User's Client id via the same unguarded 'orderBy asc, take first' tblusers_clients pattern this bug fixed" . ($auditHits ? " — found in: " . implode(", ", $auditHits) : ""),
    count($auditHits) === 0,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "WhatsApp cross-client phone regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
