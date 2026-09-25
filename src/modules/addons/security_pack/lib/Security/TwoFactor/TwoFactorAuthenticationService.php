<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\EmailTwoFactorProvider;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\TotpTwoFactorProvider;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\WhatsAppTwoFactorProvider;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — the ONE authoritative 2FA orchestrator
 * (Section 5). Coordinates cross-cutting status/policy questions across
 * the three providers, bypass, and recovery codes. Deliberately
 * contains NO provider-specific OTP/TOTP implementation details — those
 * stay in Email2faService / WhatsAppTwoFactorService / TotpEnrollmentService
 * and their own WHMCS Security Modules (which remain the actual
 * pre-session authentication gate — see Section 4's WHMCS-auth-lifecycle
 * discussion; this class is a status/policy helper for admin and client
 * area screens, not itself part of the pre-session login path).
 *
 * MUTUAL EXCLUSION (added post-3.1.0, fixing a real bug where the
 * Client Security Center could show more than one method as "Active"
 * simultaneously): only ONE of Email / DCTLAB WhatsApp / Time-Based
 * Token may be the active primary 2FA method for a given (user_id,
 * user_type) at any time. This is enforced HERE, server-side, at the
 * two places a method's active/inactive state can change — never as a
 * UI-only label:
 *   1. {@see activateExclusive()} — called by each method's own WHMCS
 *      Security Module, immediately after ITS OWN completeActivation()/
 *      verifyAndActivate() call succeeds (the one place a method
 *      transitions to "active"). Disables any OTHER currently-active
 *      method via that method's own EXISTING disable() implementation
 *      (Email2faService::disable() / WhatsAppTwoFactorService::disable()
 *      / TotpEnrollmentService::disable()) — every one of those already
 *      preserves the enrollment/config row (status flips to "disabled",
 *      nothing is deleted; TOTP's secret is kept — only reset() wipes
 *      it) and already emits its own audit event, so re-enrolling later
 *      does not require starting over from nothing more than
 *      necessary.
 *   2. {@see enforceSingleActiveMethod()} — a self-healing check run at
 *      the top of {@see status()} (i.e. every time the Client Security
 *      Center or admin overview reads status). Repairs accounts that
 *      already have more than one method active (data from before this
 *      rule existed) by keeping the most-recently-activated method and
 *      disabling the rest the same way. Idempotent — a no-op once an
 *      account is already consistent.
 * No new schema/table was added for this — both methods above reuse
 * each provider's existing isActive()/disable() and each service's
 * existing "activated_at" column for the self-heal tie-break.
 */
class TwoFactorAuthenticationService
{
    /** @return TwoFactorProviderInterface[] keyed by method key */
    public static function providers(): array
    {
        return [
            "email" => new EmailTwoFactorProvider(),
            "whatsapp" => new WhatsAppTwoFactorProvider(),
            "totp" => new TotpTwoFactorProvider(),
        ];
    }

    /**
     * Enrollment status across all three methods, for status/overview
     * screens (the Client Security Center, the admin overview panel).
     * This is the ONE authoritative status read — callers must use this
     * rather than independently querying each method's own table, so
     * every screen agrees on which single method (if any) is active.
     * Self-heals any pre-existing mutual-exclusion violation before
     * building the returned array (see class docblock).
     */
    public static function status(int $userId, string $userType): array
    {
        self::reconcileNativeSecondFactorDrift($userId, $userType);
        self::enforceSingleActiveMethod($userId, $userType, "system-selfheal");

        $status = [];
        $activeMethod = null;
        foreach (self::providers() as $key => $provider) {
            $active = $provider->isActive($userId, $userType);
            if($active) {
                $activeMethod = $key;
            }
            $status[$key] = [
                "label" => $provider->label(),
                "active" => $active,
                "pending" => $provider->isPending($userId, $userType),
            ];
        }
        $status["active_method"] = $activeMethod;
        $status["recovery_codes_remaining"] = RecoveryCodeService::remainingCount($userId, $userType);
        return $status;
    }

    /**
     * Called by each method's own WHMCS Security Module immediately
     * after IT transitions a user to "active" (the one moment a method
     * newly becomes the active method). Disables every OTHER
     * currently-active method for this (user_id, user_type) via that
     * method's own existing disable() — never deletes its enrollment,
     * never touches bypass/rate-limit state, never invents a second
     * "active method" field. A no-op if no other method is active.
     *
     * $activatedMethod must be one of the keys returned by providers()
     * ("email" | "whatsapp" | "totp"); unknown keys are ignored.
     */
    public static function activateExclusive(string $activatedMethod, int $userId, string $userType, string $actor = "user"): void
    {
        $providers = self::providers();
        if(!isset($providers[$activatedMethod])) {
            return;
        }
        foreach ($providers as $key => $provider) {
            if($key === $activatedMethod) {
                continue;
            }
            if(!$provider->isActive($userId, $userType)) {
                continue;
            }
            $provider->disable($userId, $userType, $actor);
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.method.switched",
                    "Activating \"" . $providers[$activatedMethod]->label() . "\" automatically deactivated \"" . $provider->label() . "\" — only one Two-Factor Authentication method can be active at a time. The previous method's enrollment was not deleted.",
                    ["user_id" => $userId, "user_type" => $userType, "activated_method" => $activatedMethod, "deactivated_method" => $key, "actor" => $actor]
                );
            }
        }
    }

    /**
     * Self-heals accounts where more than one 2FA method is currently
     * active — e.g. rows created before this mutual-exclusion rule
     * existed. Keeps the most-recently-activated method (by each
     * table's own "activated_at" column) and disables the rest via
     * their own existing disable() (enrollment preserved, same as
     * activateExclusive() above). Idempotent: a no-op when 0 or 1
     * methods are active. Returns the key of the one method left
     * active, or null if none are.
     */
    public static function enforceSingleActiveMethod(int $userId, string $userType, string $actor = "system"): ?string
    {
        $providers = self::providers();
        $activeKeys = [];
        foreach ($providers as $key => $provider) {
            if($provider->isActive($userId, $userType)) {
                $activeKeys[] = $key;
            }
        }
        if(count($activeKeys) <= 1) {
            return $activeKeys[0] ?? null;
        }

        $winner = self::mostRecentlyActivatedMethod($activeKeys, $userId, $userType);
        foreach ($activeKeys as $key) {
            if($key === $winner) {
                continue;
            }
            $providers[$key]->disable($userId, $userType, $actor);
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.method.autocorrected",
                    "Multiple active Two-Factor Authentication methods were found for this account — only one may be active at a time. \"" . $providers[$key]->label() . "\" was automatically deactivated (enrollment preserved); \"" . $providers[$winner]->label() . "\" remains active.",
                    ["user_id" => $userId, "user_type" => $userType, "kept_method" => $winner, "deactivated_method" => $key, "actor" => $actor],
                    "warning"
                );
            }
        }
        return $winner;
    }

    /** @param string[] $keys */
    private static function mostRecentlyActivatedMethod(array $keys, int $userId, string $userType): string
    {
        $timestamps = [];
        foreach ($keys as $key) {
            $timestamps[$key] = self::activatedAtTimestamp($key, $userId, $userType);
        }
        return self::pickMostRecentTimestamp($timestamps);
    }

    /**
     * PURE decision logic (no DB access, unit tested directly — see
     * tests/run.php) behind {@see mostRecentlyActivatedMethod()}: given
     * a map of method key => activated_at unix timestamp (0 meaning
     * "unknown/never"), returns the key with the highest timestamp.
     * Ties (including all-zero, e.g. rows with no recorded
     * activated_at) resolve to the FIRST key in iteration order, which
     * callers pass in providers()' fixed email/whatsapp/totp order —
     * deterministic, never random.
     *
     * @param array<string,int> $timestamps
     */
    public static function pickMostRecentTimestamp(array $timestamps): string
    {
        $best = array_key_first($timestamps);
        $bestTime = $timestamps[$best];
        foreach ($timestamps as $key => $t) {
            if($t > $bestTime) {
                $best = $key;
                $bestTime = $t;
            }
        }
        return $best;
    }

    private static function activatedAtTimestamp(string $methodKey, int $userId, string $userType): int
    {
        return self::columnTimestamp($methodKey, $userId, $userType, "activated_at");
    }

    /**
     * 2026-08-22 — Requirements doc Step 6 ("Use the existing
     * `last_verified_at` fields where they already exist. Do not create
     * duplicate date fields."). Mirrors activatedAtTimestamp() exactly,
     * just reading the OTHER existing column instead — no new schema,
     * no new class, no provider-specific logic duplicated here beyond
     * what activatedAtTimestamp() already contained (refactored both
     * into the one shared columnTimestamp() helper below).
     */
    private static function lastVerifiedAtTimestamp(string $methodKey, int $userId, string $userType): int
    {
        return self::columnTimestamp($methodKey, $userId, $userType, "last_verified_at");
    }

    /**
     * 2026-08-27 — same production fix as TotpTwoFactorProvider's own
     * isActive()/isPending(): "totp" now prefers a row in
     * dct_totp_native's own table (NativeTotpStatusBridge — that module's
     * schema uses the identical column names, activated_at/
     * last_verified_at included, so no further translation is needed)
     * whenever one exists for this identity, falling back to the legacy
     * dct_totp_2fa-backed table only when it doesn't. Without this, a
     * native-tracked user's activated_at/last_verified_at read as blank
     * everywhere this helper feeds — the admin reporting table's
     * "Activated"/"Last Verified" columns, and enforceSingleActiveMethod()'s
     * own tie-break — even though status()/isActive() (via the provider
     * fix) already correctly show that method as active/pending.
     */
    private static function configRow(string $methodKey, int $userId, string $userType)
    {
        try {
            switch ($methodKey) {
                case "email":
                    return Email2faService::getConfig($userId, $userType);
                case "whatsapp":
                    return WhatsAppTwoFactorService::getConfig($userId, $userType);
                case "totp":
                    $nativeRow = NativeTotpStatusBridge::getConfig($userId, $userType);
                    return $nativeRow !== null ? $nativeRow : TotpEnrollmentService::getConfig($userId, $userType);
                default:
                    return null;
            }
        } catch (\Throwable $e) {
            return null;
        }
    }

    private static function columnTimestamp(string $methodKey, int $userId, string $userType, string $column): int
    {
        $row = self::configRow($methodKey, $userId, $userType);
        if(!$row || empty($row->{$column})) {
            return 0;
        }
        return strtotime((string) $row->{$column}) ?: 0;
    }

    /**
     * Reporting (Step 6): activated_at, per method, for every provider —
     * 0 meaning "this method was never activated for this identity".
     * Public wrapper around the existing private per-method timestamp
     * lookup (unchanged) — used by the admin reporting overview to show
     * "2FA enrollment/activation date" without re-querying each
     * provider's table a second time from the controller.
     *
     * @return array<string,int>
     */
    public static function activatedAtTimestampsForIdentity(int $userId, string $userType): array
    {
        $out = [];
        foreach (self::providers() as $key => $provider) {
            $out[$key] = self::activatedAtTimestamp($key, $userId, $userType);
        }
        return $out;
    }

    /**
     * Reporting (Step 6): last_verified_at, per method, for every
     * provider — 0 meaning "no successful verification recorded for
     * this method". This is a SUCCESSFUL VERIFICATION timestamp, not an
     * enrollment timestamp — every provider's own module already writes
     * this column only on a genuine OTP/TOTP-code/recovery-code success
     * (confirmed by inspection for this step, see the Step 6 report):
     * dct_email_2fa_verify()/dct_whatsapp_2fa_verify() write it directly
     * after Email2faService::verify()/WhatsAppTwoFactorService::verify()
     * return "valid"; dct_totp_2fa_verify() writes it after either a
     * valid TOTP code (TotpEnrollmentService::verifyLogin()) or a valid
     * recovery code (TwoFactorAuthenticationService::attemptRecoveryCode(),
     * fixed in 3.1.29) — never on enrollment alone, and never on a
     * bypass/IP-exemption/trusted-browser shortcut (those branches
     * return before reaching that write, same as they return before the
     * "remember browser" logic — see TrustedBrowserService's Step 5
     * wiring for the identical pattern).
     *
     * @return array<string,int>
     */
    public static function lastVerifiedAtTimestampsForIdentity(int $userId, string $userType): array
    {
        $out = [];
        foreach (self::providers() as $key => $provider) {
            $out[$key] = self::lastVerifiedAtTimestamp($key, $userId, $userType);
        }
        return $out;
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): the
     * three-state 2FA status label for the admin reporting overview
     * (Step 6, Section 1). "Enabled" when a method is currently active;
     * "Disabled" when no method is currently active but at least one was
     * successfully activated before (activated_at is set on some
     * provider, even though it's since been turned off/switched); never
     * an inference layered on top of $status["active_method"] alone.
     */
    public static function reportStatusLabel(bool $hasActiveMethod, bool $hasEverActivatedAnyMethod): string
    {
        if($hasActiveMethod) {
            return "Enabled";
        }
        if($hasEverActivatedAnyMethod) {
            return "Disabled";
        }
        return "Not Configured";
    }

    /**
     * Requirements doc Section 1: "Add an option for administrators to
     * disable 2FA for selected users." Reuses each provider's own
     * EXISTING disable() — the same one activateExclusive()/
     * enforceSingleActiveMethod() already call — never a new/duplicate
     * disable implementation.
     *
     * 2026-08-25 — production bug fix: this previously only disabled a
     * provider that was already "active" (fully verified), on the
     * assumption documented here at the time — "an incomplete enrollment
     * isn't '2FA enabled' yet... the user can simply abandon or
     * re-attempt that enrollment on their own." That assumption is
     * false: WHMCS core's own login gate (`tblusers.second_factor` /
     * `tbladmins.second_factor`, see clearNativeSecondFactorIfOurs()) is
     * set as soon as a user STARTS enrollment (WHMCS's native
     * `_activate()` step), independent of whether our own
     * status/isActive() tracking ever reaches "active". A user who began
     * enrollment in one of our methods and never finished verifying it
     * (status stays "pending" forever) was already being routed through
     * that method's login challenge by WHMCS core — which correctly
     * refuses to issue a real OTP for a not-yet-verified method — with
     * no way to "simply abandon" it: every login attempt hit a dead end,
     * and this admin action reported "nothing to disable" and did
     * nothing, because isActive() was false. Widened to also disable
     * (and therefore unstick) a provider that is merely "pending" —
     * every disable() implementation this calls already updates
     * unconditionally (no status="active" filter), so calling it on a
     * pending row is exactly as safe as on an active one.
     *
     * Audit logging: emits "2fa.admin.disabled" (only when something was
     * actually disabled — never a no-op event) via the same
     * security_pack_record_event() pipeline every other 2FA event in
     * this codebase uses, so it shows up in Activity/Analytics/Anomalies
     * like any other security event, not a bespoke log.
     *
     * @return string[] the provider key(s) actually disabled (empty if the user had no active or pending method)
     */
    public static function disableAllMethods(int $userId, string $userType, string $actor): array
    {
        $providers = self::providers();
        $disabled = [];
        $disabledLabels = [];
        foreach ($providers as $key => $provider) {
            if(!$provider->isActive($userId, $userType) && !$provider->isPending($userId, $userType)) {
                continue;
            }
            $provider->disable($userId, $userType, $actor);
            $disabled[] = $key;
            $disabledLabels[] = $provider->label();
        }
        if($disabled && function_exists("security_pack_record_event")) {
            security_pack_record_event(
                "2fa.admin.disabled",
                "Administrator disabled Two-Factor Authentication for " . $userType . " #" . $userId . ". Method(s) disabled: " . implode(", ", $disabledLabels) . ". Enrollment was preserved (not deleted) — the user can re-verify to turn it back on.",
                ["user_id" => $userId, "user_type" => $userType, "methods" => $disabled, "actor" => $actor],
                "warning"
            );
        }
        // 2026-08-23 — production bug fix: disable() on each provider
        // above only flips THIS module's own status/enrollment tables
        // (Email2faService::disable() / WhatsAppTwoFactorService::
        // disable() / TotpEnrollmentService::disable()) — it never
        // touched WHMCS core's OWN pointer to which Security Module a
        // login must pass through, `tblusers.second_factor` (for
        // client/contact identities) / `tbladmins.second_factor` (for
        // admin identities). That column is what
        // modules/security/dct_*_2fa's _challenge()/_verify() entry
        // points are actually gated on at login time — it is completely
        // independent of this class's own isActive()/status() tracking
        // (see core/two_factor_admin_display.php's docblock, which
        // reads this same column directly for the same reason).
        //
        // Left unset, an account this method disables via the admin
        // "Manage a User's Two-Factor Authentication" panel keeps
        // second_factor pointing at the now-disabled module: WHMCS core
        // still routes the next login through that module's challenge(),
        // which correctly reports "not active" and refuses to issue a
        // real OTP — an unbreakable "incorrect code" retry loop with no
        // way to submit a valid one, since there is no valid one to
        // submit. Clearing it here (only when it currently names one of
        // OUR three modules — never a native/third-party method we don't
        // know about) is what actually lifts the login gate.
        //
        // 2026-08-25 — production bug fix: this used to only run when
        // $disabled was non-empty, i.e. only for provider(s) this exact
        // call happened to flip via the isActive()/isPending() checks
        // above. That left a gap whenever our own per-provider tracking
        // and WHMCS core's native second_factor column could diverge in
        // a way neither isActive() nor isPending() catches (e.g. a
        // provider row deleted/reset out-of-band, or any other drift) —
        // the admin action's actual purpose ("disable 2FA for this
        // user") is a promise about the LOGIN GATE, not about which
        // provider flags happened to be true a moment earlier. Now
        // checked unconditionally, straight off the live native column,
        // for every admin-triggered disable — still narrow: only ever
        // clears it when the column currently names one of OUR three
        // modules, exactly as before.
        self::clearNativeSecondFactorIfOurs($userId, $userType);
        // 2026-08-22 — Requirements doc Section 3: an admin turning 2FA
        // off entirely is a "protection removed" event — any trusted
        // browser for this identity would otherwise keep bypassing a
        // challenge that, once re-enabled, the user never actually
        // re-verified against. Deliberately NOT called from
        // activateExclusive()'s automatic method-switch disable
        // elsewhere in this class — switching methods isn't a
        // protection-removed event, the account still has active 2FA
        // via the newly-selected method at that exact moment.
        if($disabled && class_exists(TrustedBrowserService::class)) {
            TrustedBrowserService::revokeAll($userId, $userType, $actor);
        }
        // 2026-08-25 — same "protection removed" reasoning as the
        // trusted-browser revoke immediately above, applied to admin
        // manual/same-IP bypasses: an admin explicitly turning 2FA off
        // for this user must not leave a still-active bypass quietly
        // skipping the challenge once they re-enroll. Same guard
        // ($disabled only — never on a true no-op), same actor label.
        if($disabled && class_exists(TwoFactorBypassService::class)) {
            TwoFactorBypassService::revokeAllForUser($userId, $userType, $actor);
        }
        return $disabled;
    }

    /**
     * Maps this codebase's own provider keys (as returned by
     * providers()) to the exact `modules/security/{folder}` name(s) WHMCS
     * core stores in `tblusers.second_factor` / `tbladmins.second_factor`
     * once that method is the one active login gate — confirmed via
     * TwoFactorController::labelFromSecondFactorModule() and
     * core/two_factor_admin_display.php, which read this exact mapping
     * off the live column for the admin Users-tab overlay.
     *
     * "totp" lists TWO folders (2026-08-27 production fix): this install
     * turned out to actually run modules/security/dct_totp_native, a
     * separate standalone Security Module from modules/security/
     * dct_totp_2fa (which this addon was originally built against and
     * has zero real enrollments here). Both are listed so that whichever
     * one WHMCS core's native column actually names is recognized as
     * "one of ours" — see NativeTotpStatusBridge's own docblock for the
     * full incident. Every value in here is checked with in_array()/
     * membership, never a single-value === comparison, specifically to
     * support a key mapping to more than one folder.
     */
    private const SECOND_FACTOR_MODULE_FOLDERS = [
        "email" => ["dct_email_2fa"],
        "whatsapp" => ["dct_whatsapp_2fa"],
        "totp" => ["dct_totp_2fa", "dct_totp_native"],
    ];

    /**
     * Clears WHMCS core's native second-factor pointer for this identity
     * when — and only when — it currently names ANY one of our three
     * modules (see SECOND_FACTOR_MODULE_FOLDERS below). Deliberately
     * narrow: if second_factor is empty, or names a module we don't
     * recognize (a native WHMCS method like Time-Based Tokens configured
     * outside this addon, or a different third-party security module
     * entirely), this leaves it completely alone — disabling OUR
     * tracking must never silently disable protection this addon didn't
     * put in place.
     *
     * client/contact identities are both keyed by `tblusers.id` (the
     * same `$params['user_info']['id']` every dct_*_2fa module's
     * `_challenge()`/`_activate()` receives — see Email2faService's own
     * identity-resolution fix earlier in this project); admin identities
     * are keyed by `tbladmins.id`. Fail-soft throughout — a lookup/write
     * error here must never abort the disable that already succeeded
     * above.
     *
     * 2026-08-25: no longer takes a $disabledKeys parameter — reads the
     * live native column directly and clears it whenever it names ANY
     * one of our three modules, regardless of which provider(s) this
     * particular call disabled. See disableAllMethods()'s call-site
     * comment for why.
     */
    private static function clearNativeSecondFactorIfOurs(int $userId, string $userType): void
    {
        if($userId <= 0) {
            return;
        }
        $table = $userType === "admin" ? "tbladmins" : "tblusers";
        try {
            $capsule = \Illuminate\Database\Capsule\Manager::class;
            $row = $capsule::table($table)->where("id", $userId)->first(["id", "second_factor"]);
            if(!$row) {
                return;
            }
            $current = is_array($row) ? ($row["second_factor"] ?? "") : ($row->second_factor ?? "");
            if($current === "" || $current === null) {
                return;
            }
            $allOurFolders = array_merge(...array_values(self::SECOND_FACTOR_MODULE_FOLDERS));
            if(!in_array((string) $current, $allOurFolders, true)) {
                // Points at something that isn't one of our three
                // modules (a native WHMCS method, or a different
                // third-party security module entirely) — leave WHMCS
                // core's gate exactly as it is.
                return;
            }
            $capsule::table($table)->where("id", $userId)->update(["second_factor" => ""]);
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.admin.disabled.native_cleared",
                    "Cleared WHMCS's native second-factor login requirement (previously \"" . $current . "\") for " . $userType . " #" . $userId . " so the account is no longer routed through a Two-Factor Authentication challenge for a method that was just disabled.",
                    ["user_id" => $userId, "user_type" => $userType, "previous_second_factor" => (string) $current],
                    "warning"
                );
            }
        } catch (\Throwable $e) {
            // Fail-soft: the addon-level disable above already
            // succeeded and was already logged; a failure to also touch
            // WHMCS core's own column must not surface as an error to
            // the admin, only silently leave the mitigation in the
            // existing native Setup > Security > Two-Factor
            // Authentication screen (the guidance already given for
            // this exact bug) as a fallback.
        }
    }

    /**
     * 2026-08-26 — production bug fix: the reverse direction of
     * clearNativeSecondFactorIfOurs() above. That method keeps WHMCS
     * core's native second_factor column in sync when OUR OWN code path
     * disables a method (admin panel, mutual-exclusion switch). It does
     * NOT cover the other direction: a client or admin disabling
     * Two-Factor Authentication from WHMCS's own native Security
     * Settings page ({$WEB_ROOT}/user/security's "Two-Factor
     * Authentication" tab). That native disable is a WHMCS-core-only
     * operation — no dct_email_2fa/dct_whatsapp_2fa/dct_totp_2fa module
     * file defines, or is ever called with, any kind of per-user
     * "deactivate" entry point, and WHMCS's own Security Module contract
     * for Two-Factor Authentication (_activate/_activateverify/
     * _challenge/_verify) has no such hook — so a native disable only
     * ever clears tblusers.second_factor / tbladmins.second_factor and
     * never informs this addon at all.
     *
     * Left unreconciled, this addon's own per-provider tables
     * (dctlab_security_pack_*2fa.status) keep reporting "active" forever
     * after a real native disable — confirmed live: the client's own
     * Security Settings page correctly said "disabled" (it reads the
     * native column) and the admin Manage User modal correctly said
     * "OFF" (same native column), but this addon's own admin 2FA
     * overview kept saying "Enabled" for the same account — three
     * screens disagreeing about the same, currently-enforced 2FA state.
     *
     * 2026-08-26, same day, second pass — confirmed live the identical
     * drift also affects a "pending" row, not just "active" ones: after
     * the first pass here fixed the "Enabled" mismatch on the overview
     * table, "Manage a User's Two-Factor Authentication" still showed a
     * "Disable Two-Factor Authentication For This User" button for the
     * same account, because a stale Email Verification row was still
     * sitting at status="pending" from a long-abandoned enrollment
     * attempt, and buildManageUserViewModel() (2026-08-25's own fix)
     * deliberately treats "pending" as disableable too, for good reason
     * — see that fix's own docblock. So this now checks BOTH isActive()
     * and isPending() providers, not active-only.
     *
     * Fix: whenever our own tracking says a provider is active OR
     * pending, cross-check it against the SAME live native column
     * clearNativeSecondFactorIfOurs() already treats as the
     * authoritative WHMCS-core login gate. If that column no longer
     * names this provider's module (cleared, or repointed at something
     * else — a native method or a different third-party module we don't
     * own), our own tracking is stale: self-heal it via the SAME
     * existing disable() every other self-heal path in this class
     * already calls (enrollment preserved, not deleted — identical
     * convention to enforceSingleActiveMethod()'s self-heal). Narrow and
     * fail-soft: only ever acts on a provider THIS class already
     * considers active or pending, only ever compares against the live
     * column (never writes to it — that stays
     * clearNativeSecondFactorIfOurs()'s job, the opposite direction),
     * and any lookup/write error leaves status() exactly as it was
     * before this fix (fails toward the pre-fix, already-shipped
     * behavior, never toward a new one).
     */
    private static function reconcileNativeSecondFactorDrift(int $userId, string $userType): void
    {
        if($userId <= 0) {
            return;
        }
        $providers = self::providers();
        $trackedProviders = [];
        foreach ($providers as $key => $provider) {
            if($provider->isActive($userId, $userType) || $provider->isPending($userId, $userType)) {
                $trackedProviders[$key] = $provider;
            }
        }
        if(!$trackedProviders) {
            return;
        }
        $table = $userType === "admin" ? "tbladmins" : "tblusers";
        try {
            $row = \Illuminate\Database\Capsule\Manager::table($table)->where("id", $userId)->first(["id", "second_factor"]);
        } catch (\Throwable $e) {
            return;
        }
        if(!$row) {
            return;
        }
        $native = (string) (is_array($row) ? ($row["second_factor"] ?? "") : ($row->second_factor ?? ""));

        foreach ($trackedProviders as $key => $provider) {
            $expectedFolders = self::SECOND_FACTOR_MODULE_FOLDERS[$key] ?? null;
            if($expectedFolders !== null && in_array($native, $expectedFolders, true)) {
                // Native column still agrees this provider is the
                // current login gate — nothing to reconcile.
                continue;
            }
            $provider->disable($userId, $userType, "system-native-sync");
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.method.native_disabled_synced",
                    "\"" . $provider->label() . "\" was recorded as active or pending by DCTLAB Security Pack, but WHMCS's own native Two-Factor Authentication setting for this account no longer points to it (most likely the user disabled it themselves from their native Security Settings page, or never completed an old enrollment attempt). Synced our own tracking to match — enrollment was not deleted.",
                    ["user_id" => $userId, "user_type" => $userType, "method" => $key, "native_second_factor" => $native],
                    "warning"
                );
            }
        }
    }

    /** Is ANY method actively enrolled for this user? */
    public static function hasAnyActiveMethod(int $userId, string $userType): bool
    {
        foreach (self::providers() as $provider) {
            if($provider->isActive($userId, $userType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Section 20's "Require 2FA" policy check — whether the site-wide
     * setting demands 2FA be enrolled at all. This does NOT decide
     * whether a specific login needs a challenge right now (that stays
     * the security module's own responsibility, checked against the
     * live bypass/enrollment state at auth time) — it is a policy flag
     * for admin-area / status-page display (e.g. "2FA is required by
     * policy but you have not enrolled yet").
     */
    public static function isRequiredByPolicy(array $settings): bool
    {
        $value = $settings["twofactor_require"] ?? "";
        return $value === "on" || $value === "1" || $value === 1 || $value === true;
    }

    public static function defaultMethod(array $settings): string
    {
        $method = (string) ($settings["twofactor_default_method"] ?? "email");
        return in_array($method, ["email", "whatsapp", "totp"], true) ? $method : "email";
    }

    // --- Bypass (Section 21/22/23) — delegates to the ONE bypass store ---

    public static function findActiveBypass(int $userId, string $userType, string $ip)
    {
        return TwoFactorBypassService::findActive($userId, $userType, $ip);
    }

    /**
     * 2026-08-27 — now returns bool (previously void), propagating
     * TwoFactorBypassService::createAdminBypass()'s own real
     * success/failure so TwoFactorController::bypass() can report the
     * true outcome instead of an unconditional success message — see
     * that method's own docblock for the incident this fixes.
     */
    public static function createAdminBypass(int $userId, string $userType, int $days, string $actorLabel, string $reason = ""): bool
    {
        return TwoFactorBypassService::createAdminBypass($userId, $userType, $days, $actorLabel, $reason, "manual", "2fa");
    }

    public static function revokeBypass(int $bypassId, string $actorLabel): void
    {
        TwoFactorBypassService::revokeBypass($bypassId, $actorLabel, "2fa");
    }

    // --- Recovery codes (Section 16/17) ------------------------------

    public static function regenerateRecoveryCodes(int $userId, string $userType): array
    {
        return RecoveryCodeService::regenerate($userId, $userType);
    }

    public static function attemptRecoveryCode(int $userId, string $userType, string $candidate, string $ip): bool
    {
        return RecoveryCodeService::attemptConsume($userId, $userType, $candidate);
    }
}
