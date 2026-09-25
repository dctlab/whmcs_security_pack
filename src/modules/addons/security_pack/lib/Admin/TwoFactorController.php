<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\NativeTotpStatusBridge;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpEnrollmentService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorBypassService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorIpExemptionService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TrustedBrowserService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\UserIdentityType;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\WhatsAppTwoFactorService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — Two-Factor Authentication (Security Center >
 * Authentication > Two-Factor Authentication).
 *
 * This is the ONE unified admin surface for cross-method policy and the
 * administrator manual bypass (Section 21: "move it to the unified 2FA
 * layer") — it does NOT duplicate WHMCS's own native
 * Setup > Security > Two-Factor Authentication screen, which remains
 * the place each method (Email Verification / DCTLAB WhatsApp /
 * Time-Based Token) is individually activated and where each method's
 * own OTP-length/validity/attempts fields live (as of 3.1, DCTLAB
 * WhatsApp's platform credentials themselves — Botms.in/Baileys/Meta —
 * live in the separate "dct_whatsapp_notifications" addon this module
 * integrates with, not in this module's own settings) —
 * exactly the same relationship the existing Email 2FA page already has
 * to that native screen. This page only adds what WHMCS's native screen
 * has no equivalent for: an enrollment overview across all three
 * methods, the "Require 2FA" / default-method policy, and the unified
 * administrator manual bypass (one bypass system, applies regardless of
 * which method the user has enrolled).
 */
class TwoFactorController
{
    public function index($vars = [])
    {
        // 2026-08-27 — build marker for the "Administrator Manual Bypass"
        // incident, fifth pass: logs once per admin page load so a simple
        // page visit (no bypass action needed) proves definitively which
        // build of this file is actually executing on the live server —
        // settles whether a recurrence is a new bug or a stale-deploy /
        // opcache issue (both previously confirmed relevant on this host).
        if(function_exists("security_pack_log_activity")) {
            security_pack_log_activity("[security_pack] DIAGNOSTIC v5 BUILD MARKER: Two-Factor Authentication admin page loaded — if you see this line, v5 is the code actually running.");
        } elseif(function_exists("logActivity")) {
            try {
                logActivity("[security_pack] DIAGNOSTIC v5 BUILD MARKER: Two-Factor Authentication admin page loaded — if you see this line, v5 is the code actually running.");
            } catch (\Throwable $e) {
            }
        }
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        $postOnly = ["bypass", "revoke", "save", "disableUser", "addIpExemption", "removeIpExemption", "revokeTrustedBrowsers"];
        if(in_array($action, $postOnly, true)) {
            if($_SERVER["REQUEST_METHOD"] !== "POST") {
                redir("module=security_pack&c=twoFactor", "addonmodules.php");
            }
            if(!security_pack_csrf_valid()) {
                // 2026-08-27 — diagnostic added during the "Administrator
                // Manual Bypass still not working" incident: if the
                // report of "no error shown" ever turns out to mean this
                // silent redirect (CSRF token mismatch/expiry) rather
                // than bypass() itself failing, this makes that visible
                // in the Activity Log too, instead of only a session
                // flash message that's easy to miss if the page navigated
                // away before it was read.
                if(function_exists("security_pack_log_activity")) {
                    security_pack_log_activity("[security_pack] Two-Factor Authentication admin action \"" . $action . "\" was blocked: CSRF token missing or invalid.");
                } elseif(function_exists("logActivity")) {
                    try {
                        logActivity("[security_pack] Two-Factor Authentication admin action \"" . $action . "\" was blocked: CSRF token missing or invalid.");
                    } catch (\Throwable $e) {
                    }
                }
                $_SESSION["nnm_2fa_error"] = "Your session token expired — please try again.";
                redir("module=security_pack&c=twoFactor", "addonmodules.php");
            }
        }
        switch ($action) {
            case "bypass":
                $this->bypass();
                return;
            case "revoke":
                $this->revoke();
                return;
            case "save":
                $this->save();
                return;
            case "disableUser":
                $this->disableUser();
                return;
            case "revokeTrustedBrowsers":
                $this->revokeTrustedBrowsers();
                return;
            case "addIpExemption":
                $this->addIpExemption();
                return;
            case "removeIpExemption":
                $this->removeIpExemption();
                return;
        }
        $this->render();
    }

    private function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
    }

    /**
     * PHASE 3.8 (navigation-wiring-follow-on, 2026-08-24): migrated to the
     * templates/admin/ presentation layer (Controller -> view model ->
     * TemplateRenderer -> templates/admin/two-factor.tpl -> DCTLAB .sp-*
     * components), matching every other already-migrated controller.
     *
     * SECURITY-SENSITIVE FILE — what changed vs. what didn't:
     *   - Every POST/state-changing action (save/bypass/revoke/disableUser/
     *     revokeTrustedBrowsers/addIpExemption/removeIpExemption), the
     *     CSRF+POST guard in index(), the pure report-decision helpers, and
     *     the Admin Client Profile > Users tab AJAX-support methods below
     *     are 100% UNCHANGED — not touched by this migration at all.
     *   - Every DB read/query this method's helpers make is copied
     *     verbatim from the pre-migration renderOverview()/renderReporting()/
     *     renderManageUser()/renderIpExemptions()/renderPolicy()/
     *     renderBypasses() (now buildOverviewViewModel()/buildManageUserViewModel()/
     *     buildIpExemptionsViewModel()/buildPolicyViewModel()/
     *     buildBypassesViewModel() — same queries, same services, only
     *     returning an array instead of echoing HTML directly).
     *   - Every form's method/action/hidden CSRF token field/field name and
     *     every table's columns are preserved exactly — see
     *     templates/admin/two-factor.tpl.
     *   - The Email2faController embedding contract
     *     ((new Email2faController())->renderContent(false)) is NOT
     *     changed — same call, same argument, same try/catch. It is only
     *     now captured via ob_start()/ob_get_clean() (the same technique
     *     already proven safe for the AdminInterface-driven controllers in
     *     the WHMCS-compatibility phase) instead of echoing straight into
     *     the legacy panel wrapper, so its output can be placed inside the
     *     new layout.tpl content area at the same position it always
     *     rendered in.
     */
    private function render()
    {
        $token = security_pack_csrf_token();
        $settings = security_pack_settings();

        $errorMessage = null;
        if(isset($_SESSION["nnm_2fa_error"])) {
            $errorMessage = (string) $_SESSION["nnm_2fa_error"];
            unset($_SESSION["nnm_2fa_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_2fa_success"])) {
            $successMessage = (string) $_SESSION["nnm_2fa_success"];
            unset($_SESSION["nnm_2fa_success"]);
        }

        $overviewStats = $this->buildOverviewViewModel();
        $reportRows = $this->buildReportRows($settings, 200);
        $manageUser = $this->buildManageUserViewModel($token);
        $ipExemptions = $this->buildIpExemptionsViewModel($token);
        $policy = $this->buildPolicyViewModel($settings, $token);
        $bypasses = $this->buildBypassesViewModel($token);

        // 3.1.25 (unchanged by this migration): Email 2FA's own page
        // (enrollment overview + its separate, Email-specific bypass
        // table) is embedded here directly. Email2faController's own
        // bypass()/revoke()/renderOverview()/renderContent() are
        // completely untouched — same tables, same CSRF-protected POST
        // targets — this only captures its rendered output (still a
        // direct echo from renderContent(), same as before) so it can be
        // placed inside this page's new templated layout. c=email2fa on
        // its own still redirects here (Email2faController::index()
        // unchanged), so this remains the one place both live.
        ob_start();
        try {
            (new Email2faController())->renderContent(false);
        } catch (\Throwable $e) {
        }
        $email2faEmbedHtml = ob_get_clean();

        $content = TemplateRenderer::render("two-factor", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "overviewStats" => $overviewStats,
            "reportRows" => $reportRows,
            "manageUser" => $manageUser,
            "ipExemptions" => $ipExemptions,
            "policy" => $policy,
            "bypasses" => $bypasses,
            "email2faEmbedHtml" => $email2faEmbedHtml,
            "userTypeOptions" => $this->userTypeOptions(),
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Two-Factor Authentication",
            "pageDescription" => "Unified enrollment overview, policy, and administrator manual bypass across Email, DCTLAB WhatsApp, and Time-Based Token 2FA.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /** @return array<string,string> type => label, same order as UserIdentityType::ALL, for every &lt;select&gt; on this page */
    private function userTypeOptions(): array
    {
        $out = [];
        foreach (UserIdentityType::ALL as $type) {
            $out[$type] = UserIdentityType::label($type);
        }
        return $out;
    }

    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderOverview()'s data preparation — the SAME three queries per
     * UserIdentityType, the SAME fail-soft all-zero fallback on any
     * \Throwable, and the SAME per-method total/breakdown computation.
     * Returns a stat-card view model (matching every other migrated
     * controller's stat-card usage) instead of echoing hand-built HTML.
     *
     * PHASE 3.8C: additive only — clientCount/adminCount/subAccountCount
     * were added alongside the existing hint/value/label keys (not in
     * place of them) so the template can render each count on its own
     * line without parsing the pre-formatted "hint" string. These are
     * the exact same integers already computed into $breakdown above,
     * just also exposed structured — no new query, no behavior change to
     * "hint", "value", or "label" for anything that still reads them.
     *
     * @return array<int,array{label:string,value:int,hint:string,clientCount:int,adminCount:int,subAccountCount:int}>
     */
    private function buildOverviewViewModel(): array
    {
        $counts = [];
        try {
            // Sub-account foundation: loops over UserIdentityType::ALL
            // (client/admin/contact), not a hardcoded 2-value list — a
            // future contact-enrolled row is counted here rather than
            // silently dropped. No contact rows exist in any install
            // today (nothing in this codebase writes user_type=contact
            // yet), so this is architecture-readiness, not a behavior
            // change for any current install.
            foreach (UserIdentityType::ALL as $type) {
                $counts["email"][$type] = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->where("user_type", $type)->where("status", "active")->count();
                $counts["whatsapp"][$type] = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_whatsapp2fa")->where("user_type", $type)->where("status", "active")->count();
                $counts["totp"][$type] = self::countActiveTotpForType($type);
            }
        } catch (\Throwable $e) {
            $counts = [
                "email" => [UserIdentityType::CLIENT => 0, UserIdentityType::ADMIN => 0, UserIdentityType::CONTACT => 0],
                "whatsapp" => [UserIdentityType::CLIENT => 0, UserIdentityType::ADMIN => 0, UserIdentityType::CONTACT => 0],
                "totp" => [UserIdentityType::CLIENT => 0, UserIdentityType::ADMIN => 0, UserIdentityType::CONTACT => 0],
            ];
        }
        $stats = [];
        foreach (["email" => "Email Verification", "whatsapp" => "DCTLAB WhatsApp", "totp" => "Time-Based Token"] as $key => $label) {
            $total = $counts[$key][UserIdentityType::CLIENT] + $counts[$key][UserIdentityType::ADMIN] + $counts[$key][UserIdentityType::CONTACT];
            $breakdown = $counts[$key][UserIdentityType::CLIENT] . " client(s), " . $counts[$key][UserIdentityType::ADMIN] . " admin(s)";
            // Only appended once a contact-typed row actually exists —
            // keeps today's display identical for every install with
            // zero contacts, per "don't disrupt current behavior".
            if($counts[$key][UserIdentityType::CONTACT] > 0) {
                $breakdown .= ", " . $counts[$key][UserIdentityType::CONTACT] . " sub-account(s)";
            }
            $stats[] = [
                "label" => $label . " Active",
                "value" => $total,
                "hint" => $breakdown,
                "clientCount" => $counts[$key][UserIdentityType::CLIENT],
                "adminCount" => $counts[$key][UserIdentityType::ADMIN],
                "subAccountCount" => $counts[$key][UserIdentityType::CONTACT],
            ];
        }
        return $stats;
    }

    /**
     * 2026-08-27 — production bug fix: the "Time-Based Token Active"
     * Security Overview card previously counted ONLY the legacy
     * dct_totp_2fa-backed table (dctlab_security_pack_totp2fa), which has
     * zero real rows on installs actually running the separate,
     * standalone modules/security/dct_totp_native module instead (see
     * NativeTotpStatusBridge's own docblock for the full incident) — the
     * card showed "0 clients 0 administrators" even while a real client
     * was actively enrolling.
     *
     * Counts DISTINCT (user_id, user_type) identities active in EITHER
     * table for the given type — never double-counted even in the
     * unlikely case a single identity somehow has an active row in both
     * (mutual exclusion is enforced going forward by
     * TwoFactorAuthenticationService, but this count must stay correct
     * even for pre-existing/inconsistent data).
     */
    private static function countActiveTotpForType(string $type): int
    {
        try {
            $legacyIds = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_totp2fa")
                ->where("user_type", $type)->where("status", "active")->pluck("user_id")->all();
        } catch (\Throwable $e) {
            $legacyIds = [];
        }
        $nativeIds = [];
        if(NativeTotpStatusBridge::tableExists()) {
            try {
                $nativeIds = \Illuminate\Database\Capsule\Manager::table("mod_dct_totp_native_secrets")
                    ->where("user_type", $type)->where("status", "active")->pluck("user_id")->all();
            } catch (\Throwable $e) {
                $nativeIds = [];
            }
        }
        $distinct = [];
        foreach (array_merge($legacyIds, $nativeIds) as $id) {
            $distinct[(int) $id] = true;
        }
        return count($distinct);
    }

    /**
     * Requirements doc Step 6, Section 1/8 — "Admin Users / 2FA
     * Overview" reporting table. Deliberately built ENTIRELY on top of
     * what 3.1.28-3.1.30 already established — no schema changes, no new
     * decision architecture:
     *   - status/active method: TwoFactorAuthenticationService::status()
     *     (the SAME authoritative read every other screen already uses)
     *   - activation/last-verified dates: the EXISTING activated_at /
     *     last_verified_at columns, via the new
     *     activatedAtTimestampsForIdentity()/lastVerifiedAtTimestampsForIdentity()
     *     wrappers added this step (thin wrappers around the SAME
     *     per-method lookup mostRecentlyActivatedMethod() already used)
     *   - trusted browsers: TrustedBrowserService::listForIdentity() +
     *     the new summarize() pure helper — same data the client's own
     *     Security Center and this page's "Manage a User's 2FA" panel
     *     already read, never the token/hash
     *   - trusted IP: the new TwoFactorIpExemptionService::
     *     hasActiveGlobalExemption()/hasActiveUserExemption()
     *     existence-only checks + the new reportLabel() pure helper
     *
     * SCOPE: this table lists every (user_id, user_type) identity that
     * has AT LEAST ONE row in any of the three method tables (i.e. has
     * ever started or completed an enrollment) — it does not attempt to
     * enumerate every WHMCS user account that exists (that would mean
     * scanning tblclients/tbladmins/tblcontacts in full and cross-
     * referencing against tblusers.second_factor, which is a materially
     * different, heavier query the existing Users-tab overlay
     * (core/two_factor_admin_display.php,
     * buildUsersTwoFactorMappingForClient()) already does per-client on
     * that native page — this panel complements that mechanism, it does
     * not replace it. A user who is required by policy but has NEVER
     * enrolled in anything therefore will not appear in THIS table (they
     * have no row anywhere) — that gap is exactly what the existing
     * Users-tab "Required — Not Enrolled" badge already covers; a user
     * who appears HERE and is both policy-required and not currently
     * Enabled gets the identical badge text inline, computed from the
     * SAME isRequiredByPolicy() check, so the two indicators can never
     * disagree with each other.
     *
     * Bounded to 200 identities (same limit convention as
     * TwoFactorIpExemptionService::listGlobal()/listUserScoped()),
     * sorted by most recent activity (last verification, falling back to
     * activation) so the users an admin is most likely to care about
     * surface first.
     */
    /**
     * PHASE 3.8: the former renderReporting()'s presentation (panel/table
     * markup) now lives in templates/admin/two-factor.tpl, which receives
     * $reportRows straight from buildReportRows() below — UNCHANGED,
     * still called directly from render() — and derives the same
     * status_class (Enabled -> text-success, Disabled -> text-warning,
     * else text-muted) and the same UserIdentityType::label() call
     * in-template from that unchanged data, so no new PHP method was
     * needed here. buildReportRows() itself, and every method it calls,
     * is completely untouched below — it is still DB-backed
     * orchestration: every value is read from an EXISTING table/service,
     * nothing new is written or computed beyond display formatting, and
     * it remains fully fail-soft (any error resolving the identity list
     * returns an empty array, same "an empty result is always safe"
     * convention as buildUsersTwoFactorMappingForClient()).
     */
    private function buildReportRows($settings, int $limit): array
    {
        $identities = $this->distinctTwoFactorIdentities($limit);
        if(!$identities) {
            return [];
        }
        $requiredByPolicy = false;
        try {
            $requiredByPolicy = TwoFactorAuthenticationService::isRequiredByPolicy($settings);
        } catch (\Throwable $e) {
            $requiredByPolicy = false;
        }
        $rows = [];
        foreach ($identities as $identity) {
            $userId = (int) $identity->user_id;
            $userType = UserIdentityType::normalize((string) $identity->user_type);
            if($userId <= 0) {
                continue;
            }
            $status = TwoFactorAuthenticationService::status($userId, $userType);
            $activatedTimestamps = TwoFactorAuthenticationService::activatedAtTimestampsForIdentity($userId, $userType);
            $verifiedTimestamps = TwoFactorAuthenticationService::lastVerifiedAtTimestampsForIdentity($userId, $userType);
            $statusLabel = self::reportStatusLabelForStatus($status, $activatedTimestamps);
            $dates = self::reportDates($status["active_method"], $activatedTimestamps, $verifiedTimestamps);
            $activatedTs = $dates["activated_ts"];
            $verifiedTs = $dates["verified_ts"];

            $trustedBrowserSummary = ["count" => 0, "has_any" => false, "latest_expires_at" => null];
            if(class_exists(TrustedBrowserService::class)) {
                try {
                    $trustedBrowserSummary = TrustedBrowserService::summarize(TrustedBrowserService::listForIdentity($userId, $userType));
                } catch (\Throwable $e) {
                }
            }
            $formattedLatestExpiry = !empty($trustedBrowserSummary["latest_expires_at"]) ? fromMySQLDate((string) $trustedBrowserSummary["latest_expires_at"], true) : "";
            $trustedBrowserLabel = self::reportTrustedBrowserLabel($trustedBrowserSummary, $formattedLatestExpiry);

            $hasGlobalExemption = TwoFactorIpExemptionService::hasActiveGlobalExemption();
            $hasUserExemption = TwoFactorIpExemptionService::hasActiveUserExemption($userId, $userType);
            $trustedIpLabel = TwoFactorIpExemptionService::reportLabel($hasGlobalExemption, $hasUserExemption);

            $rows[] = [
                "user_id" => $userId,
                "user_type" => $userType,
                "user_label" => $this->resolveUserLabel($userId, $userType),
                "status" => $statusLabel,
                "required_not_enrolled" => self::isRequiredNotEnrolled($requiredByPolicy, $statusLabel),
                "method" => self::reportMethodLabel($status["active_method"], $status),
                "activated_at" => $activatedTs > 0 ? fromMySQLDate(date("Y-m-d H:i:s", $activatedTs), true) : "",
                "last_verified_at" => $verifiedTs > 0 ? fromMySQLDate(date("Y-m-d H:i:s", $verifiedTs), true) : "",
                "trusted_browser_label" => $trustedBrowserLabel,
                "trusted_ip_label" => $trustedIpLabel,
                "_sort" => max($verifiedTs, $activatedTs),
            ];
        }
        usort($rows, function ($a, $b) {
            return $b["_sort"] <=> $a["_sort"];
        });
        return $rows;
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): the
     * "Method" column — the currently active method's own label, or ""
     * when nothing is currently active (never a stale/inactive method
     * shown as if it were current — Step 6, Section 2 — and never a
     * guess when $activeMethod is null).
     *
     * @param array<string,array{label:string,active:bool,pending:bool}> $status
     */
    public static function reportMethodLabel(?string $activeMethod, array $status): string
    {
        if($activeMethod === null) {
            return "";
        }
        return $status[$activeMethod]["label"] ?? "";
    }

    /** @param array<string,int> $activatedTimestamps */
    public static function reportStatusLabelForStatus(array $status, array $activatedTimestamps): string
    {
        $hasEverActivatedAnyMethod = max(array_merge([0], array_values($activatedTimestamps))) > 0;
        return TwoFactorAuthenticationService::reportStatusLabel($status["active_method"] !== null, $hasEverActivatedAnyMethod);
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): which
     * method's activated_at/last_verified_at to show as "the" date for
     * this identity. The currently active method when there is one;
     * otherwise the most recently activated method (still meaningful for
     * a "Disabled" row — "this is when it was last on"); null (blank
     * dates) only when truly Not Configured (no method ever activated).
     *
     * @param array<string,int> $activatedTimestamps
     * @param array<string,int> $verifiedTimestamps
     * @return array{activated_ts:int,verified_ts:int,reference_method:?string}
     */
    public static function reportDates(?string $activeMethod, array $activatedTimestamps, array $verifiedTimestamps): array
    {
        $referenceMethod = $activeMethod ?? self::methodKeyWithHighestTimestamp($activatedTimestamps);
        $activatedTs = $referenceMethod !== null ? ($activatedTimestamps[$referenceMethod] ?? 0) : 0;
        $verifiedTs = $referenceMethod !== null ? ($verifiedTimestamps[$referenceMethod] ?? 0) : 0;
        return ["activated_ts" => $activatedTs, "verified_ts" => $verifiedTs, "reference_method" => $referenceMethod];
    }

    /** @param array<string,int> $timestamps */
    public static function methodKeyWithHighestTimestamp(array $timestamps): ?string
    {
        $best = null;
        $bestTs = 0;
        foreach ($timestamps as $key => $ts) {
            if($ts > $bestTs) {
                $best = $key;
                $bestTs = $ts;
            }
        }
        return $best;
    }

    /**
     * PURE decision logic (no DB access, no WHMCS runtime dependency —
     * unit tested directly): the "Trusted Browser" column text, from an
     * already-summarized result (TrustedBrowserService::summarize() —
     * never the token/hash, never a raw row list here). Takes the
     * already-formatted expiry string (fromMySQLDate() is applied by the
     * caller, per Step 6 Section 9's "use the existing application/WHMCS
     * timezone conventions" — this function itself has no WHMCS runtime
     * dependency, keeping it directly unit-testable with no environment
     * to stub).
     *
     * @param array{count:int,has_any:bool,latest_expires_at:?string} $summary
     */
    public static function reportTrustedBrowserLabel(array $summary, string $formattedLatestExpiry = ""): string
    {
        if(!$summary["has_any"]) {
            return "No";
        }
        $label = "Yes (" . $summary["count"] . ($summary["count"] === 1 ? " device" : " devices");
        if($formattedLatestExpiry !== "") {
            $label .= ", until " . $formattedLatestExpiry;
        }
        return $label . ")";
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): Step 6,
     * Section 6 — the "Required — Not Enrolled" flag for THIS reporting
     * table, computed from the EXACT SAME isRequiredByPolicy() check the
     * existing Users-tab badge already uses, so the two indicators can
     * never disagree. Never flagged for a row that IS Enabled, no matter
     * what the policy setting is.
     */
    public static function isRequiredNotEnrolled(bool $requiredByPolicy, string $statusLabel): bool
    {
        return $requiredByPolicy && $statusLabel !== "Enabled";
    }

    /**
     * Every distinct (user_id, user_type) with a row in ANY of the three
     * method tables — no new table, no new column (except one, see
     * below). Deliberately separate bounded queries merged/deduped in PHP
     * rather than a SQL UNION (nothing else in this codebase relies on
     * Capsule's union() support, and this keeps behavior identical across
     * whatever MySQL/MariaDB version the install is actually running) —
     * each table is still individually bounded so a very large install
     * can't turn this into an unbounded scan.
     *
     * 2026-08-27 — production bug fix: added
     * mod_dct_totp_native_secrets (dct_totp_native's own table — see
     * NativeTotpStatusBridge's docblock) alongside the three original
     * Security Pack tables. Without it, an identity tracked only by
     * dct_totp_native (every real TOTP enrollment on the reporting
     * install) never appeared in this admin reporting table at all —
     * not merely mislabeled, entirely absent — even after the
     * TotpTwoFactorProvider/configRow() fixes made status()/isActive()/
     * the activated-date lookups correct for identities that DO appear
     * here.
     */
    private function distinctTwoFactorIdentities(int $limit): array
    {
        $perTableLimit = max($limit, 200);
        $seen = [];
        $out = [];
        $tables = ["dctlab_security_pack_email2fa", "dctlab_security_pack_whatsapp2fa", "dctlab_security_pack_totp2fa"];
        if(NativeTotpStatusBridge::tableExists()) {
            $tables[] = "mod_dct_totp_native_secrets";
        }
        foreach ($tables as $table) {
            try {
                $rows = \Illuminate\Database\Capsule\Manager::table($table)
                    ->select("user_id", "user_type")->orderBy("id", "DESC")->limit($perTableLimit)->get();
            } catch (\Throwable $e) {
                continue;
            }
            foreach ($rows as $row) {
                $key = ((int) $row->user_id) . ":" . ((string) $row->user_type);
                if(isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $out[] = $row;
            }
        }
        return $out;
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): which
     * table, and which first/last-name column pair, a given identity
     * type's display name is resolved against.
     *
     * BUG FIX (2fa reporting table showed the wrong person, e.g. WHMCS
     * User ID 666316 rendered as "Manoj Kumar (#666316)" instead of
     * "Sanitha Mary (#666316)"): a `client`/`user` 2FA identity's
     * $userId is a WHMCS **User** ID (`tblusers.id`) — the same
     * `$params['user_info']['id']` every dct_*_2fa provider's
     * _challenge()/_activate() receives (see the "client/contact
     * identities are both keyed by tblusers.id" note in
     * TwoFactorAuthenticationService::clearNativeSecondFactorIfOurs(),
     * and Email2faService::resolveClientIdForUser()'s whole existence —
     * that method exists specifically because a WHMCS Client ID has to
     * be separately, best-effort resolved FROM a User ID, they are not
     * the same ID space). This method previously queried
     * `tblclients.id = $userId` for that branch, which can — and, on
     * this install, did — collide with an unrelated tblclients row that
     * happens to share the same numeric id, displaying a completely
     * different person's name. `tblusers` also uses `first_name`/
     * `last_name` (with an underscore) rather than `tblclients`/
     * `tbladmins`/`tblcontacts`'s `firstname`/`lastname` — using the
     * wrong column pair here would silently resolve to an empty name
     * and fall back to the generic "Client/User #id" label, masking the
     * mis-resolution rather than fixing it.
     *
     * administrator → tbladmins (unchanged); contact/sub-account →
     * tblcontacts (unchanged — no live code creates contact-typed 2FA
     * rows yet, see UserIdentityType's own docblock; this branch is
     * deliberately left as-is here, pending the still-unverified Step 7
     * live sub-account/contact authentication work); client/user →
     * tblusers (fixed — never tblclients).
     *
     * @return array{table:string, first_col:string, last_col:string}
     */
    public static function resolveUserLabelSource(string $userType): array
    {
        if($userType === UserIdentityType::ADMIN) {
            return ["table" => "tbladmins", "first_col" => "firstname", "last_col" => "lastname"];
        }
        if($userType === UserIdentityType::CONTACT) {
            return ["table" => "tblcontacts", "first_col" => "firstname", "last_col" => "lastname"];
        }
        return ["table" => "tblusers", "first_col" => "first_name", "last_col" => "last_name"];
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): formats
     * the display name from an already-fetched row (or null) plus the
     * table/column spec resolveUserLabelSource() returned, falling back
     * to the generic "{Type} #{id}"-style label (via
     * UserIdentityType::label()) when there is no row or no name on it —
     * same fail-soft behavior as before this fix, just split out so it
     * can be exercised without a database.
     *
     * @param array{table:string, first_col:string, last_col:string} $source
     */
    public static function formatUserLabelFromRow($row, array $source, string $userType): string
    {
        if($row) {
            $first = (string) (is_array($row) ? ($row[$source["first_col"]] ?? "") : ($row->{$source["first_col"]} ?? ""));
            $last = (string) (is_array($row) ? ($row[$source["last_col"]] ?? "") : ($row->{$source["last_col"]} ?? ""));
            $name = trim($first . " " . $last);
            if($name !== "") {
                return $name;
            }
        }
        return UserIdentityType::label($userType);
    }

    /**
     * Identity-aware display-name resolution (Requirements doc Step 6,
     * Section 7 — "do not assume admin -> admin, everything else ->
     * client"): branches on the ACTUAL UserIdentityType, not a binary
     * coalesce, so a future `contact` row resolves against tblcontacts,
     * never silently treated as a client or admin. Fail-soft — any
     * lookup error/missing row falls back to a generic, still-correct
     * "{Type} #{id}" label rather than guessing or throwing. Which
     * table/columns to use is now resolveUserLabelSource()'s decision
     * (see that method's docblock for the tblusers-vs-tblclients bug
     * this split guards against); this method is left as the thin DB
     * orchestrator around it.
     */
    private function resolveUserLabel(int $userId, string $userType): string
    {
        $source = self::resolveUserLabelSource($userType);
        try {
            if($source["table"] === "tblcontacts" && !\Illuminate\Database\Capsule\Manager::schema()->hasTable("tblcontacts")) {
                $row = null;
            } else {
                $row = \Illuminate\Database\Capsule\Manager::table($source["table"])->where("id", $userId)->first();
            }
        } catch (\Throwable $e) {
            $row = null;
        }
        return self::formatUserLabelFromRow($row, $source, $userType);
    }

    /**
     * Requirements doc Section 1: "Add an option for administrators to
     * disable 2FA for selected users." Look-up is GET (read-only, no
     * state change, no CSRF needed) so an admin can bookmark/link
     * directly to a specific user's status; the actual disable action is
     * its own CSRF-protected POST (see disableUser()) with a confirm()
     * dialog, matching every other destructive action on this page.
     *
     * Reuses TwoFactorAuthenticationService::status() — the SAME
     * authoritative status read the Client Security Center uses — so
     * this panel can never show a different answer than what the user
     * themselves would see. Reuses TwoFactorAuthenticationService::
     * disableAllMethods() (new — see that class) which itself reuses
     * each provider's own existing disable(), never reimplementing
     * per-method disable logic here.
     */
    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderManageUser()'s data preparation. Same GET-only, no-CSRF
     * lookup (Requirements doc Section 1) reading the SAME
     * $_GET["manage_user_id"]/["manage_user_type"] params, the SAME
     * TwoFactorAuthenticationService::status()/providers() reads, the
     * SAME TrustedBrowserService::listForIdentity() read when the class
     * exists — nothing DB-backed or security-relevant changed, only
     * returned as an array instead of echoed. The disableUser/
     * revokeTrustedBrowsers POST forms' action/hidden-field values are
     * preserved exactly (built by the template from this view model —
     * see templates/admin/two-factor.tpl).
     *
     * @return array{userId:int,userType:string,lookedUp:bool,providerRows:array,recoveryCodesRemaining:int,trustedBrowsersAvailable:bool,trustedBrowsers:array,trustedBrowserCount:int,activeMethod:?string,token:string}
     */
    private function buildManageUserViewModel($token): array
    {
        $userId = isset($_GET["manage_user_id"]) && is_numeric($_GET["manage_user_id"]) ? (int) $_GET["manage_user_id"] : 0;
        $userType = UserIdentityType::normalize(isset($_GET["manage_user_type"]) ? (string) $_GET["manage_user_type"] : null);

        $vm = [
            "userId" => $userId,
            "userType" => $userType,
            "lookedUp" => $userId > 0,
            "providerRows" => [],
            "recoveryCodesRemaining" => 0,
            "trustedBrowsersAvailable" => false,
            "trustedBrowsers" => [],
            "trustedBrowserCount" => 0,
            "activeMethod" => null,
            "hasDisableableMethod" => false,
            "token" => $token,
        ];

        if($userId <= 0) {
            return $vm;
        }

        $status = TwoFactorAuthenticationService::status($userId, $userType);
        foreach (TwoFactorAuthenticationService::providers() as $key => $provider) {
            $info = $status[$key] ?? null;
            $state = "Not enrolled";
            if(is_array($info)) {
                if(!empty($info["active"])) {
                    $state = "Active";
                    $vm["hasDisableableMethod"] = true;
                } elseif(!empty($info["pending"])) {
                    // 2026-08-25 — production bug fix: a method stuck at
                    // "pending" (enrollment started, never verified) can
                    // already be the one WHMCS core routes login through
                    // (see TwoFactorAuthenticationService::disableAllMethods()'s
                    // own fix note) — it needs the SAME disable button a
                    // fully-active method gets, or an admin has no way to
                    // reach the fix that already exists server-side.
                    $state = "Pending verification";
                    $vm["hasDisableableMethod"] = true;
                }
            }
            $vm["providerRows"][] = ["label" => $provider->label(), "state" => $state];
        }
        $vm["recoveryCodesRemaining"] = (int) ($status["recovery_codes_remaining"] ?? 0);
        $vm["activeMethod"] = !empty($status["active_method"]) ? (string) $status["active_method"] : null;

        // 2026-08-22 — Requirements doc Section 3: admin visibility into
        // this user's trusted browsers, plus a revoke-all control. Scoped
        // to the exact looked-up (user_id, user_type) identity, same
        // isolation guarantee as every other lookup on this page.
        // Read-only list; no per-device admin revoke UI (only
        // revoke-all) — see the original docblock this method was
        // extracted from for the full rationale.
        if(class_exists(TrustedBrowserService::class)) {
            $vm["trustedBrowsersAvailable"] = true;
            $trustedBrowsers = TrustedBrowserService::listForIdentity($userId, $userType);
            $vm["trustedBrowserCount"] = count($trustedBrowsers);
            foreach ($trustedBrowsers as $row) {
                $vm["trustedBrowsers"][] = [
                    "deviceLabel" => (string) ($row->device_label ?? "Unknown"),
                    "createdAt" => (string) $row->created_at,
                    "lastUsedAt" => (string) ($row->last_used_at ?? "Never"),
                    "expiresAt" => (string) $row->expires_at,
                ];
            }
        }

        return $vm;
    }

    /**
     * Requirements doc Section 1: "Allow administrators and clients to
     * configure and exclude static company IP addresses/IP ranges from
     * 2FA requirements." This panel covers the ADMINISTRATOR half —
     * both the global/"company IP" list and per-user exemptions on
     * behalf of a specific identity. Client self-service configuration
     * of their OWN exemption is a separate, not-yet-built client-area
     * addition — see TwoFactorIpExemptionService::addForUser(), which
     * this panel already calls and a future client-area page could call
     * identically, scoped to only the logged-in client's own identity.
     *
     * Deliberately backed by TwoFactorIpExemptionService, NOT
     * IpRestrictionService/IpRestrictionsController — see that class's
     * docblock for why this is a genuinely separate system.
     */
    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderIpExemptions()'s data preparation. Same
     * TwoFactorIpExemptionService::listGlobal()/listUserScoped() reads,
     * same two forms' action/hidden-field values (a=addIpExemption
     * scope=global|user, a=removeIpExemption) — the template builds the
     * exact same markup from this array instead of this method echoing
     * it directly. addIpExemption()/removeIpExemption() themselves
     * (the actual POST handlers) are untouched below.
     *
     * @return array{token:string,globalRows:array,userRows:array}
     */
    private function buildIpExemptionsViewModel($token): array
    {
        $globalRows = [];
        foreach (TwoFactorIpExemptionService::listGlobal() as $row) {
            $globalRows[] = [
                "id" => (int) $row->id,
                "entry" => (string) $row->entry,
                "reason" => (string) $row->reason,
                "createdBy" => (string) $row->created_by,
                "createdAt" => (string) $row->created_at,
            ];
        }
        $userRows = [];
        foreach (TwoFactorIpExemptionService::listUserScoped() as $row) {
            $userRows[] = [
                "id" => (int) $row->id,
                "userId" => (int) $row->user_id,
                "userType" => (string) $row->user_type,
                "entry" => (string) $row->entry,
                "reason" => (string) $row->reason,
                "createdBy" => (string) $row->created_by,
            ];
        }
        return ["token" => $token, "globalRows" => $globalRows, "userRows" => $userRows];
    }

    private function addIpExemption()
    {
        $adminId = (int) ($_SESSION["adminid"] ?? 0);
        $actor = "admin#" . $adminId;
        $entry = (string) ($_POST["entry"] ?? "");
        $reason = (string) ($_POST["reason"] ?? "");
        $scope = (string) ($_POST["scope"] ?? "global");

        if($scope === "user") {
            $userId = (int) ($_POST["user_id"] ?? 0);
            $userType = UserIdentityType::normalize($_POST["user_type"] ?? null);
            $result = TwoFactorIpExemptionService::addForUser($userId, $userType, $entry, $actor, $reason);
        } else {
            $result = TwoFactorIpExemptionService::addGlobal($entry, $actor, $reason);
        }

        if($result["ok"]) {
            $_SESSION["nnm_2fa_success"] = "2FA IP exemption added.";
        } else {
            $_SESSION["nnm_2fa_error"] = $result["error"] ?? "Could not add the exemption.";
        }
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    private function removeIpExemption()
    {
        $id = (int) ($_POST["id"] ?? 0);
        if($id > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            TwoFactorIpExemptionService::remove($id, "admin#" . $adminId);
        }
        $_SESSION["nnm_2fa_success"] = "2FA IP exemption removed.";
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    private function disableUser()
    {
        $userId = (int) ($_POST["user_id"] ?? 0);
        $userType = UserIdentityType::normalize($_POST["user_type"] ?? null);
        if($userId > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            $disabled = TwoFactorAuthenticationService::disableAllMethods($userId, $userType, "admin#" . $adminId);
            $_SESSION["nnm_2fa_success"] = $disabled
                ? "Two-Factor Authentication disabled for this user."
                : "This user had no active Two-Factor Authentication method — nothing to disable.";
        } else {
            $_SESSION["nnm_2fa_error"] = "A valid User ID is required.";
        }
        redir("module=security_pack&c=twoFactor&manage_user_id=" . $userId . "&manage_user_type=" . rawurlencode($userType), "addonmodules.php");
    }

    /**
     * 2026-08-22 — Requirements doc Section 3: administrator revoke-all
     * for a looked-up user's trusted browsers. Same shape as
     * disableUser() immediately above. Deliberately revoke-ALL only
     * (no per-device admin control) — see renderManageUser()'s docblock
     * for why.
     */
    private function revokeTrustedBrowsers()
    {
        $userId = (int) ($_POST["user_id"] ?? 0);
        $userType = UserIdentityType::normalize($_POST["user_type"] ?? null);
        if($userId > 0 && class_exists(TrustedBrowserService::class)) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            $count = TrustedBrowserService::revokeAll($userId, $userType, "admin#" . $adminId);
            $_SESSION["nnm_2fa_success"] = $count > 0
                ? "Revoked {$count} trusted browser(s) for this user."
                : "This user had no trusted browsers to revoke.";
        } else {
            $_SESSION["nnm_2fa_error"] = "A valid User ID is required.";
        }
        redir("module=security_pack&c=twoFactor&manage_user_id=" . $userId . "&manage_user_type=" . rawurlencode($userType), "addonmodules.php");
    }

    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderPolicy()'s data preparation — same $settings["twofactor_require"]
     * read, same TwoFactorAuthenticationService::defaultMethod() call,
     * same method-key/label list. save() (the actual POST handler this
     * form submits to) is untouched below.
     *
     * @return array{required:bool,defaultMethod:string,methodOptions:array<string,string>,token:string}
     */
    private function buildPolicyViewModel($settings, $token): array
    {
        return [
            "required" => !empty($settings["twofactor_require"]),
            "defaultMethod" => TwoFactorAuthenticationService::defaultMethod($settings),
            "methodOptions" => ["email" => "Email Verification", "whatsapp" => "DCTLAB WhatsApp", "totp" => "Time-Based Token"],
            "token" => $token,
        ];
    }

    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderBypasses()'s data preparation — same
     * TwoFactorBypassService::listActive(100) read, and the Method
     * column is still produced by the SAME
     * $this->bypassMethodLabel($row->method ?? null) call (that method
     * is untouched below — 3.1.16's "never display the raw stored method
     * value" fix is preserved exactly, including that it still runs in
     * PHP here, not duplicated in the template). bypass()/revoke() (the
     * actual POST handlers this form/row-actions submit to) are
     * untouched below.
     *
     * @return array{token:string,rows:array}
     */
    private function buildBypassesViewModel($token): array
    {
        $rows = [];
        foreach (TwoFactorBypassService::listActive(100) as $row) {
            $rows[] = [
                "id" => (int) $row->id,
                "userId" => (int) $row->user_id,
                "userType" => (string) $row->user_type,
                "scope" => (string) $row->scope,
                "methodLabelHtml" => $this->bypassMethodLabel($row->method ?? null),
                "expiresAt" => (string) $row->expires_at,
                "createdBy" => (string) $row->created_by,
                "reason" => (string) $row->reason,
            ];
        }
        return ["token" => $token, "rows" => $rows];
    }

    /**
     * 3.1.16 — "BYPASS DISPLAY": TwoFactorBypassService's own docblock
     * (see that class, `method` column) confirms a bypass is structurally
     * method-agnostic — "A bypass is NOT scoped by method... a granted
     * bypass applies regardless of the configured method... satisfies
     * the 2FA challenge no matter which method they have enrolled." The
     * stored `method` column is explicitly "informational only" (audit:
     * which method's verification happened to produce a same-IP
     * auto-bypass) and never affects enforcement — confirmed by reading
     * TwoFactorBypassService before changing anything here, per this
     * ticket's own instruction, and by TwoFactorAuthenticationService::
     * createAdminBypass() always tagging admin-created bypasses
     * "manual", never a specific method. Displaying the raw stored value
     * (e.g. "whatsapp") as if it were THE method the bypass applies to
     * was misleading — it looked method-scoped when it isn't. This never
     * touches a stored row (Section "Do not break existing bypass
     * records") — it only changes how the existing `method` column is
     * rendered: always leads with "Any 2FA Method", and — purely for
     * audit value — appends which method's verification originally
     * produced a same-IP auto-bypass, when that's known and isn't just
     * the generic "manual" tag admin-created bypasses always use.
     */
    private function bypassMethodLabel($rawMethod): string
    {
        $rawMethod = is_string($rawMethod) ? trim($rawMethod) : "";
        $label = "Any 2FA Method";
        if($rawMethod !== "" && $rawMethod !== "manual") {
            $label .= " <span class=\"text-muted small\">(granted via " . $this->e($rawMethod) . ")</span>";
        }
        return $label;
    }

    private function save()
    {
        $require = !empty($_POST["twofactor_require"]) ? "on" : "";
        $method = (string) ($_POST["twofactor_default_method"] ?? "email");
        $method = in_array($method, ["email", "whatsapp", "totp"], true) ? $method : "email";
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "twofactor_require"], ["setting" => "twofactor_require", "value" => $require]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "twofactor_default_method"], ["setting" => "twofactor_default_method", "value" => $method]);
        $_SESSION["nnm_2fa_success"] = "Saved.";
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    /**
     * 2026-08-27 — production bug fix ("Administrator Manual Bypass
     * still not working", confirmed live: the admin submitted this form
     * and no row ever appeared in the table, with no error shown
     * either). Root cause: createAdminBypass() previously returned void
     * and its own DB insert was wrapped in a try/catch that swallowed
     * any failure silently (e.g. the `method` column not yet existing on
     * this install's live table — see TwoFactorBypassService's own
     * docblock for exactly why that can happen given this project's
     * manual-FTP-upload delivery model) — meanwhile THIS method set
     * "Bypass created." unconditionally, regardless of whether anything
     * was actually written. An admin had no way to tell a real success
     * from a silent failure.
     *
     * Fix: createAdminBypass() now returns bool and (via
     * TwoFactorBypassService's own new self-heal) proactively fixes the
     * most likely cause of failure before attempting the write. This
     * method now reports the REAL outcome either way.
     */
    /**
     * 2026-08-27 — production bug fix ("Administrator Manual Bypass
     * auto-creation on login" investigation, Client/User identity
     * requirement): the "Administrator Manual Bypass" form's "WHMCS
     * User ID" field is a raw, freely-typed number with nothing
     * connecting it to WHMCS's own list of real Users — nothing stops
     * an admin from typing the CLIENT ID they can see elsewhere in the
     * admin UI (e.g. the Client Profile page's own "userid=" URL
     * parameter, WHMCS's own long-standing naming confusion, already
     * called out elsewhere in this codebase). A bypass created for a
     * Client ID that happens not to also be a real `tblusers.id` will
     * NEVER match at login time (login identity is resolved exclusively
     * from the real `tblusers.id`/`tbladmins.id`, never from
     * `tblclients.id`) — it just silently sits in the table looking
     * "created" while doing nothing, exactly the failure mode this
     * whole incident chain kept reporting.
     *
     * This does not stop someone from creating a bypass for the wrong
     * User (that's a normal admin mistake, not this bug) — it only
     * catches the specific, common Client/User mix-up: the submitted ID
     * doesn't exist as a User at all, but does exist as a Client. When
     * that happens, block the create and tell the admin exactly which
     * real User ID(s) are actually eligible, resolved via the SAME
     * `tblusers_clients` junction table the Users-tab overlay already
     * trusts (`resolveUserIdsForClient()`) — no new schema, no new
     * table, just refusing to accept an ID that can never work.
     */
    private static function looksLikeClientIdMistakenForUserId(int $userId, string $userType): ?array
    {
        if($userType !== UserIdentityType::CLIENT) {
            return null;
        }
        try {
            $isRealUser = \Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $userId)->exists();
        } catch (\Throwable $e) {
            // tblusers doesn't exist / query failed — fail open (don't
            // block a legitimate bypass creation over an inspection
            // error on an install where this table looks different).
            return null;
        }
        if($isRealUser) {
            return null;
        }
        try {
            $isRealClient = \Illuminate\Database\Capsule\Manager::table("tblclients")->where("id", $userId)->exists();
        } catch (\Throwable $e) {
            $isRealClient = false;
        }
        if(!$isRealClient) {
            // Not a real User AND not a real Client either — just an
            // invalid ID. createAdminBypass() will still write the row
            // (this class doesn't invent client-existence requirements
            // for User IDs in general — a User can exist with no linked
            // Client at all, see this incident's own acceptance tests),
            // so this is not this specific bug; let it proceed.
            return null;
        }
        return self::resolveUserIdsForClient($userId);
    }

    private function bypass()
    {
        $userType = UserIdentityType::normalize($_POST["user_type"] ?? null);
        $userId = (int) ($_POST["user_id"] ?? 0);
        $days = (int) ($_POST["days"] ?? 7);
        $reason = (string) ($_POST["reason"] ?? "");
        $mistakenClientId = $userId > 0 ? self::looksLikeClientIdMistakenForUserId($userId, $userType) : null;
        if($mistakenClientId !== null) {
            $_SESSION["nnm_2fa_error"] = "#" . $userId . " is a WHMCS Client ID, not a WHMCS User ID — a bypass created against it would never match at login. " . (count($mistakenClientId) > 0 ? "The real User ID(s) for this client are: " . implode(", ", $mistakenClientId) . "." : "No WHMCS User account is linked to this client yet, so no bypass can be created for it.");
            redir("module=security_pack&c=twoFactor", "addonmodules.php");
            return;
        }
        if($userId > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            $created = TwoFactorAuthenticationService::createAdminBypass($userId, $userType, $days, "admin#" . $adminId, $reason);
            if($created) {
                $_SESSION["nnm_2fa_success"] = "Bypass created.";
            } else {
                // 2026-08-27, third pass — surface the REAL captured
                // exception message (TwoFactorBypassService::getLastError())
                // instead of a generic string, since the generic version
                // gave no way to tell what's actually failing when this
                // was reported as still broken after the first self-heal
                // fix. Every attempt (success or failure) is also now
                // unconditionally written to WHMCS's own Activity Log by
                // TwoFactorBypassService itself — check Admin -> Utilities
                // -> Logs -> Activity Log for "[security_pack] Administrator
                // Manual Bypass" if this on-page message is ever missed.
                $lastError = TwoFactorBypassService::getLastError();
                $_SESSION["nnm_2fa_error"] = "Could not create the bypass" . ($lastError !== null && $lastError !== "" ? " — " . $lastError : " — an unknown database error occurred") . ". This attempt was also logged to Admin -> Utilities -> Logs -> Activity Log.";
            }
        } else {
            $_SESSION["nnm_2fa_error"] = "A valid User ID is required.";
        }
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    private function revoke()
    {
        $id = (int) ($_POST["id"] ?? 0);
        if($id > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            TwoFactorAuthenticationService::revokeBypass($id, "admin#" . $adminId);
        }
        $_SESSION["nnm_2fa_success"] = "Revoked.";
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    // -----------------------------------------------------------------
    // 3.1.6-3.1.15 — Admin Client Profile > Users tab integration.
    //
    // WHMCS's native Users tab "Two Factor Auth Method" column only ever
    // reflects WHMCS's OWN native Security-Module 2FA state — it has no
    // idea Security Pack's Email/DCTLAB WhatsApp/TOTP methods exist, so
    // an account with an ACTIVE Security Pack method shows "N/A" there.
    // There is no documented WHMCS hook to rewrite an existing native
    // admin table's cell content (AdminClientProfileTabFields only
    // APPENDS new field rows). Through 3.1.11 this was fixed with a JS
    // overlay that called a small AJAX endpoint on this controller
    // (ajaxUsersTwoFactorStatus(), now REMOVED — see below) for each
    // row's status. That endpoint 404'd on the reported install: the
    // Admin Client Profile page there is client-side-routed to a
    // friendly "/client/{id}/..." URL, and no derivation of the real
    // admin base path (relative fetch, then an absolute URL computed
    // server-side from $_SERVER["SCRIPT_NAME"]) reliably avoided that.
    //
    // 3.1.16 — "FINAL ADMIN USERS 2FA DISPLAY FIX": removes the AJAX
    // request from this display ENTIRELY. There is no round-trip to get
    // wrong: the AdminAreaFooterOutput hook (core/two_factor_admin_display.php)
    // now computes the {userId: {method, state}} mapping SERVER-SIDE, for
    // the real WHMCS Users belonging to the client currently being
    // viewed (resolved via $_REQUEST["userid"], the same client-id
    // parameter core/loginHistory.php already reads for the identical
    // "which client's tab is this" purpose), and injects it as a JSON
    // page global. The JS overlay (assets/js/two_factor_admin_users.js)
    // is now PURE DOM presentation — find the table, find the column,
    // find each row's User ID, look it up in the already-provided
    // mapping, write the cell. No fetch(), no endpoint URL, no token.
    //
    // Per Section "DATA SOURCE": this display's mapping is now built
    // directly from WHMCS's own native `tblusers.second_factor` column
    // (via labelFromSecondFactorModule(), unchanged since 3.1.8) —
    // NOT from TwoFactorAuthenticationService::status(). status()
    // answers "what has Security Pack's own unified layer activated",
    // which can legitimately differ from what this ONE native column
    // says; reading second_factor directly is what makes this specific
    // native display agree with what WHMCS's own Manage User modal
    // ("Two-Factor Authentication: ON") is itself keyed on, avoiding
    // the native/overlay disagreement this project's history has
    // repeatedly guarded against. Bypass state is a separate security
    // property (Section "BYPASS") and is never consulted here.
    // -----------------------------------------------------------------

    /**
     * Resolves the real WHMCS User IDs (`tblusers.id`) associated with a
     * given WHMCS Client (`tblclients.id`) via the `tblusers_clients`
     * junction table — the reverse direction of the identical, already-
     * established `userid`/`clientid` lookup this module relies on
     * elsewhere (see `Email2faService::resolveClientIdForUser()` and
     * `WhatsAppTwoFactorService`'s own copy — corroborated by WHMCS
     * Community developer discussion, not officially documented, but a
     * real table/columns this codebase already trusts). This is what
     * "real WHMCS Users rendered by the authorized admin page" (Section
     * "SECURITY") means for the Users tab: exactly the accounts WHMCS
     * itself lists there for this client, never an arbitrary/attacker-
     * supplied ID (Section "SECURITY": "Never trust arbitrary User IDs
     * from request parameters" — this method is the ONLY thing that
     * decides which User IDs are even eligible to appear in the
     * mapping; nothing here reads any request-supplied user id). Fails
     * closed to an empty list on any DB error or missing table.
     *
     * 3.1.20 — CONFIRMED SCHEMA FIX: this is the real, concrete root
     * cause of the "Two Factor Auth Method" column staying permanently
     * "N/A" even after 3.1.18/3.1.19 fixed the (real, but not the only)
     * client-ID-resolution and asset-URL bugs. A live `SHOW COLUMNS FROM
     * tblusers_clients` on the reporting install confirmed the real
     * column names are `auth_user_id` and `client_id` — NOT
     * `userid`/`clientid` as this method (and both sibling
     * resolveClientIdForUser() copies) assumed, based on undocumented
     * community discussion that turned out to not match this WHMCS
     * version's actual schema. The query below silently failed via the
     * try/catch on every single call, always returning an empty user-ID
     * list — which is exactly why the mapping the AdminAreaFooterOutput
     * hook injects was correctly-formed but always empty, confirmed live
     * via `view-source` (`var security_pack_2fa_users = {};`), even
     * though `tblusers.second_factor` was independently confirmed
     * (`dct_totp_2fa`) to be exactly right for this user. Now resolves
     * the real column names via hasColumn() at call time — trying the
     * confirmed-real `auth_user_id`/`client_id` first, falling back to
     * the originally-assumed `userid`/`clientid` only if those aren't
     * present — matching the identical fix applied to
     * Email2faService::resolveClientIdForUser() and
     * WhatsAppTwoFactorService's own copy.
     *
     * @return int[]
     */
    public static function resolveUserIdsForClient(int $clientId): array
    {
        if($clientId <= 0) {
            return [];
        }
        try {
            $schema = \Illuminate\Database\Capsule\Manager::schema();
            if(!$schema->hasTable("tblusers_clients")) {
                return [];
            }
            $userCol = $schema->hasColumn("tblusers_clients", "auth_user_id") ? "auth_user_id" : "userid";
            $clientCol = $schema->hasColumn("tblusers_clients", "client_id") ? "client_id" : "clientid";
            $ids = \Illuminate\Database\Capsule\Manager::table("tblusers_clients")
                ->where($clientCol, $clientId)
                ->pluck($userCol)
                ->all();
        } catch (\Throwable $e) {
            return [];
        }
        $result = [];
        foreach ($ids as $id) {
            $id = (int) $id;
            if($id > 0 && !in_array($id, $result, true)) {
                $result[] = $id;
            }
        }
        return $result;
    }

    /**
     * PURE decision logic (no DB access — unit tested directly). Builds
     * the final `{userId: {method, state}}` mapping the JS overlay
     * consumes, from an INJECTED per-user `second_factor` resolver
     * (same "inject the DB call as a callable so the decision logic is
     * unit-testable without a database" pattern this file has used
     * since 3.1.6 — see the removed `buildUsersStatusMap()`). Per
     * Section "DATA SOURCE": any user whose resolved value isn't one of
     * Security Pack's own three known security-module directory names
     * (`labelFromSecondFactorModule()` returns null — covers empty/null,
     * WHMCS's own built-in methods, and any unrecognized module) is
     * OMITTED from the returned map entirely, never included with a
     * guessed/empty label — so the JS overlay leaves that row's native
     * value exactly as WHMCS rendered it (Section "Unknown/empty values
     * must leave the native WHMCS value untouched"). A duplicate User ID
     * in `$userIds` is only ever resolved/emitted once (Section "TESTS":
     * "duplicate User IDs"); an ID `<= 0` is skipped (Section "TESTS":
     * "invalid User IDs").
     *
     * @param int[] $userIds
     */
    public static function buildSecondFactorMapping(array $userIds, callable $secondFactorResolver): array
    {
        $map = [];
        foreach ($userIds as $userId) {
            if($userId <= 0 || isset($map[(string) $userId])) {
                continue;
            }
            $raw = $secondFactorResolver($userId);
            $label = self::labelFromSecondFactorModule(is_string($raw) ? $raw : null);
            if($label === null) {
                continue;
            }
            $map[(string) $userId] = ["method" => $label, "state" => "active"];
        }
        return $map;
    }

    /**
     * 3.1.26 — "Require Two-Factor Authentication" policy badge (Policy
     * panel decision: admin Users-tab badge, not a client-area banner or
     * email reminder). Wraps buildSecondFactorMapping() UNCHANGED (kept
     * as its own tested function above, still called on its own by
     * anything that only wants the recognized-method mapping) and, only
     * when $requiredByPolicy is true, additionally marks every user in
     * $userIds who did NOT resolve to a recognized method as
     * `state: "required_not_enrolled"`. This is purely a display flag —
     * it does not enforce anything, gate login, or write to the
     * database; enabling the Policy panel setting "does not retroactively
     * lock out users who have not yet enrolled" (per the panel's own
     * documented behavior) — it only flags the gap here for an admin to
     * see and follow up on manually.
     *
     * Duplicate/invalid ($userId <= 0) IDs are skipped the same way
     * buildSecondFactorMapping() already skips them — this never
     * overwrites an entry buildSecondFactorMapping() already produced
     * for a recognized, active method.
     *
     * @param int[] $userIds
     */
    public static function buildSecondFactorMappingWithPolicy(array $userIds, callable $secondFactorResolver, bool $requiredByPolicy): array
    {
        $map = self::buildSecondFactorMapping($userIds, $secondFactorResolver);
        if(!$requiredByPolicy) {
            return $map;
        }
        foreach ($userIds as $userId) {
            if($userId <= 0 || isset($map[(string) $userId])) {
                continue;
            }
            $map[(string) $userId] = ["method" => "N/A", "state" => "required_not_enrolled"];
        }
        return $map;
    }

    /**
     * DB-backed orchestrator called directly by the AdminAreaFooterOutput
     * hook (core/two_factor_admin_display.php). Resolves the real WHMCS
     * User IDs for the given client (resolveUserIdsForClient()), batch-
     * fetches their `tblusers.second_factor` values in ONE query (never
     * one query per row — Section "PERFORMANCE"), and builds the final
     * mapping via buildSecondFactorMapping(). Fully fail-soft: any DB
     * error anywhere in this path returns `[]` — an empty mapping is
     * always safe, since the JS overlay simply leaves every native cell
     * untouched, identical to this hook never having run at all.
     */
    public static function buildUsersTwoFactorMappingForClient(int $clientId): array
    {
        try {
            $userIds = self::resolveUserIdsForClient($clientId);
            if(!$userIds) {
                return [];
            }
            $rows = \Illuminate\Database\Capsule\Manager::table("tblusers")
                ->whereIn("id", $userIds)
                ->get(["id", "second_factor"]);
            $bySecondFactor = [];
            foreach ($rows as $row) {
                $id = (int) (is_array($row) ? ($row["id"] ?? 0) : ($row->id ?? 0));
                $sf = is_array($row) ? ($row["second_factor"] ?? null) : ($row->second_factor ?? null);
                $bySecondFactor[$id] = is_string($sf) ? $sf : null;
            }
        } catch (\Throwable $e) {
            return [];
        }
        $requiredByPolicy = false;
        try {
            if(function_exists("security_pack_settings")) {
                $requiredByPolicy = TwoFactorAuthenticationService::isRequiredByPolicy(security_pack_settings());
            }
        } catch (\Throwable $e) {
            $requiredByPolicy = false;
        }
        return self::buildSecondFactorMappingWithPolicy($userIds, function ($id) use ($bySecondFactor) {
            return $bySecondFactor[$id] ?? null;
        }, $requiredByPolicy);
    }

    /**
     * PURE decision logic (no DB access, unit tested directly) — the
     * "REQUIRED MAPPING" from a WHMCS native security-module directory
     * name (as stored in `tblusers.second_factor`) to the exact display
     * label used everywhere else in this file. Returns null for any
     * value this module doesn't recognise — never guesses at an
     * unfamiliar module name, and never lets an unrecognized
     * `second_factor` value be displayed as a trusted method (Section
     * "IMPORTANT").
     *
     * Includes `dct_totp_native` (added in 3.1.24) even though that
     * module is entirely standalone and has zero code dependency on
     * Security Pack — this map is purely a DISPLAY label lookup, and
     * WHMCS core itself has no generic "ask the module for its friendly
     * name" mechanism for this admin Users column, so any third-party
     * security module's `second_factor` value renders as "N/A" here
     * unless something recognizes it explicitly. Native's own built-in
     * "totp" module is the one exception — WHMCS core labels that one
     * itself ("Time Based Tokens"), before this addon's JS overlay ever
     * runs, which is why it displayed correctly even before this fix
     * while `dct_totp_native` did not. Confirmed via a live side-by-side
     * comparison: an account enrolled under native showed "Time Based
     * Tokens" correctly, the same account re-enrolled under
     * `dct_totp_native` showed "N/A".
     */
    public static function labelFromSecondFactorModule(?string $moduleName): ?string
    {
        $map = [
            "dct_email_2fa" => "Email Two-Factor Authentication",
            "dct_whatsapp_2fa" => "DCTLAB WhatsApp Two-Factor Authentication",
            "dct_totp_2fa" => "Time-Based Token Two-Factor Authentication",
            "dct_totp_native" => "Time-Based Token (Enhanced) Two-Factor Authentication",
        ];
        if(!is_string($moduleName) || $moduleName === "") {
            return null;
        }
        return $map[$moduleName] ?? null;
    }
}
