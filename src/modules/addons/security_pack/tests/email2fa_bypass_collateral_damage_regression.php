<?php

/**
 * DCTLAB Security Pack — regression test for the 2026-08-27 "Administrator
 * Manual Bypass still not automatically added" incident (fifth and final
 * pass). Root cause found via a raw-row diagnostic dump added in the
 * previous pass: a bypass was confirmed created and persisted, but showed
 * up REVOKED a few minutes later with no admin action taken.
 *
 * ROOT CAUSE: Email2faService::disable() and ::handleEmailChanged() both
 * used to unconditionally revoke EVERY bypass row for the identity
 * (`dctlab_security_pack_email2fa_bypasses`, whereNull("revoked_at") ->
 * update(["revoked_at" => ...])) — a holdover from when that table was
 * Email 2FA's own private bypass store, before it became the ONE shared,
 * method-agnostic bypass system all three 2FA methods now use (see
 * TwoFactorBypassService's own class docblock: "A bypass is NOT scoped
 * by method... applies regardless of the configured method"). Nothing
 * updated Email2faService::disable()/handleEmailChanged() when that
 * unification happened.
 *
 * The trigger: TwoFactorAuthenticationService::reconcileNativeSecondFactorDrift()
 * runs automatically every time status() is read for an identity (e.g.
 * every time the admin Two-Factor Authentication reporting table or
 * "Manage a User" panel loads for that user) and self-heals ANY provider
 * whose tracked pending/active state no longer matches WHMCS's live
 * `second_factor` column — including a stale abandoned Email 2FA
 * enrollment attempt that has nothing to do with the account's actual,
 * currently-active method. That self-heal call reached
 * Email2faService::disable(), which then wiped out ALL of the identity's
 * bypasses as an undocumented side effect — including a Time-Based Token
 * Administrator Manual Bypass that had nothing to do with email at all.
 *
 * FIX: Email2faService::disable()/handleEmailChanged() no longer touch
 * the shared bypass table. Revoking every bypass for an identity is now
 * exclusively TwoFactorAuthenticationService::disableAllMethods()'s job —
 * the one place that already does this deliberately, only when an admin
 * explicitly turns 2FA off entirely for that user, never as a side
 * effect of a single provider's own disable()/self-heal.
 *
 * Delivered as its own standalone file, per this project's standing
 * convention. Run on its own:
 *
 *   php tests/email2fa_bypass_collateral_damage_regression.php
 *
 * Source-level checks only (no live database in this CLI runner).
 */

declare(strict_types=1);

$MODULE_DIR = __DIR__ . "/..";

$failures = [];
$passed = 0;

function ebcd_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if ($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

function ebcd_src(string $path): string
{
    $full = $GLOBALS["MODULE_DIR"] . "/" . $path;
    return is_file($full) ? (string) file_get_contents($full) : "";
}

$emailServiceSource = ebcd_src("lib/Security/Email2faService.php");

$disableStart = strpos($emailServiceSource, "public static function disable(int \$userId, string \$userType, string \$actor = \"user\"): void");
$disableEnd = strpos($emailServiceSource, "public static function handleEmailChanged(");
$disableBody = ($disableStart !== false && $disableEnd !== false) ? substr($emailServiceSource, $disableStart, $disableEnd - $disableStart) : "";

ebcd_assert(
    "Email2faService::disable() is present",
    $disableStart !== false,
    $failures,
    $passed
);
ebcd_assert(
    "Email2faService::disable() no longer touches dctlab_security_pack_email2fa_bypasses at all — that table is Security Pack's ONE shared, method-agnostic bypass store, and disabling only Email 2FA must not strip a bypass protecting a different, currently active method",
    $disableBody !== "" && strpos($disableBody, "email2fa_bypasses") === false,
    $failures,
    $passed
);
ebcd_assert(
    "Email2faService::disable() still does its OWN job — marking the email2fa config row disabled and invalidating pending challenges — unaffected by removing the bypass side effect",
    strpos($disableBody, '->update(["status" => "disabled", "deactivated_at" => $now, "updated_at" => $now]);') !== false
        && strpos($disableBody, '->update(["status" => "invalidated"]);') !== false,
    $failures,
    $passed
);
ebcd_assert(
    "Email2faService::disable() still records the email_2fa.disabled event — audit trail unaffected by this fix",
    strpos($disableBody, '"email_2fa.disabled"') !== false,
    $failures,
    $passed
);

$handleChangedStart = strpos($emailServiceSource, "public static function handleEmailChanged(");
$handleChangedBody = $handleChangedStart !== false ? substr($emailServiceSource, $handleChangedStart, 1200) : "";
ebcd_assert(
    "Email2faService::handleEmailChanged() also no longer touches dctlab_security_pack_email2fa_bypasses — same fix, same reasoning, applied to the OTHER place this table was written from this class",
    $handleChangedBody !== "" && strpos($handleChangedBody, "email2fa_bypasses") === false,
    $failures,
    $passed
);
ebcd_assert(
    "Email2faService::handleEmailChanged() still re-pends the email row on an address change — unaffected by removing the bypass side effect",
    strpos($handleChangedBody, '"status" => "pending", "activated_at" => null') !== false,
    $failures,
    $passed
);

// --- Confirm the CORRECT, unified place for a full bypass wipe is
// unchanged and still does this deliberately ---

$tfaServiceSource = ebcd_src("lib/Security/TwoFactor/TwoFactorAuthenticationService.php");
ebcd_assert(
    "TwoFactorAuthenticationService::disableAllMethods() still explicitly revokes all bypasses for the identity — the ONE deliberate place this should happen (an admin explicitly disabling 2FA entirely), untouched by this fix",
    strpos($tfaServiceSource, "TwoFactorBypassService::revokeAllForUser(\$userId, \$userType, \$actor);") !== false,
    $failures,
    $passed
);

// --- Confirm WhatsApp/TOTP's own disable() never had this bug in the
// first place (so nothing needed changing there) — asserted here so a
// future regression can't quietly reintroduce the same mistake in any
// of the three methods ---

$whatsappSource = ebcd_src("lib/Security/TwoFactor/WhatsAppTwoFactorService.php");
$totpSource = ebcd_src("lib/Security/TwoFactor/TotpEnrollmentService.php");
ebcd_assert(
    "WhatsAppTwoFactorService::disable() does not touch the shared bypass table (confirms this collateral-damage bug was unique to Email2faService, not systemic across all three methods)",
    strpos($whatsappSource, "email2fa_bypasses") === false,
    $failures,
    $passed
);
ebcd_assert(
    "TotpEnrollmentService::disable() does not touch the shared bypass table either",
    strpos($totpSource, "email2fa_bypasses") === false,
    $failures,
    $passed
);

// --- Summary ---

$totalTests = $passed + count($failures);
echo "Email2faService bypass collateral-damage regression: " . $totalTests . " assertions / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if ($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
