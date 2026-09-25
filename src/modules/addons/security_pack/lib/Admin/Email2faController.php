<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\UserIdentityType;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.6 — Email Two-Factor Authentication (Authentication >
 * Email 2FA): enrolled-account overview + administrator manual bypass
 * management. The actual OTP engine lives entirely in Email2faService —
 * this controller never generates, stores, or displays an OTP itself
 * (Step 8: never expose OTP/hash/secret/challenge tokens here).
 *
 * ARCHITECTURE CORRECTION (2.6.1): OTP length/validity/attempts/resend/
 * bypass-duration settings used to be configured from a form on THIS
 * page. They are now configured natively by WHMCS itself, on Setup >
 * Security > Two-Factor Authentication, as part of activating the
 * "Email Verification" security module
 * (modules/security/dct_email_2fa/dct_email_2fa.php) — see that
 * module's dct_email_2fa_config() for the exact fields. This page no
 * longer duplicates that settings form; it only shows what WHMCS's own
 * screen does not: enrollment counts and administrator-granted bypasses
 * (a Security Pack feature with no native WHMCS equivalent).
 */
class Email2faController
{
    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        $postOnly = ["bypass", "revoke"];
        if(in_array($action, $postOnly, true)) {
            if($_SERVER["REQUEST_METHOD"] !== "POST") {
                redir("module=security_pack&c=twoFactor", "addonmodules.php");
            }
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_e2fa_error"] = "Your session token expired — please try again.";
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
        }
        // 3.1.25: Email 2FA and Two-Factor Authentication are now shown
        // together on one page (c=twoFactor) — see TwoFactorController::
        // render(). A bare c=email2fa visit (an old bookmark/link) lands
        // there instead of a separate, now-redundant page. bypass()/
        // revoke() above are untouched and still POST directly to
        // c=email2fa — only the GET "show me the page" path redirects.
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    private function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
    }

    private function render()
    {
        $this->renderContent(true);
    }

    /**
     * 3.1.25 — extracted so TwoFactorController::render() can embed this
     * page's content directly (per explicit request: "add [Email 2FA and
     * Two-Factor Authentication] in one page"). $standalone=true is this
     * controller's own c=email2fa route (currently unreachable via normal
     * navigation — index() always redirects a GET here to c=twoFactor —
     * kept only so this method still behaves correctly if ever called
     * directly); $standalone=false is the embedded call from
     * TwoFactorController.
     *
     * 3.1.27 — CORRECTED DUPLICATE-CONTENT BUG: 3.1.25 shipped calling
     * renderBypasses($token) in BOTH branches, on the stated rationale
     * that "an Email 2FA bypass here only satisfies the challenge for
     * someone enrolled in Email Verification specifically" — separate
     * from TwoFactorController's own unified bypass table above it. That
     * rationale was WRONG: this method queries the exact same
     * `dctlab_security_pack_email2fa_bypasses` table as
     * TwoFactorBypassService::listActive() (the table TwoFactorBypassService
     * itself documents as "the ONE authoritative 2FA bypass store" — it
     * was never split by method), with no method-scoping filter on
     * lookup — so the embedded page showed the literal same bypass rows
     * twice. Confirmed live: bypass #666037 appeared in both tables on
     * the merged page. Fix: the embedded branch no longer calls
     * renderBypasses() at all — it's 100% redundant with the unified
     * table TwoFactorController::render() already shows above this.
     * renderOverview() is KEPT in the embedded branch — unlike the
     * bypass table, it genuinely shows information the page above does
     * NOT: pending-verification counts and 24h failed-verification
     * counts, neither of which TwoFactorController::renderOverview()
     * tracks. The intro paragraph is rewritten to describe only what
     * this section actually still adds.
     */
    /**
     * PHASE 3.8: migrated to the templates/admin/ presentation layer.
     * CONTRACT PRESERVED EXACTLY — this stays `public function
     * renderContent(bool $standalone = true)` and continues to ECHO
     * directly rather than return a string (TwoFactorController::render()
     * calls it wrapped in try/catch, discarding any return value and
     * relying only on its echoed side effect — see that method). Both
     * branches ($standalone true/false) do exactly what they did before,
     * including which panels appear in which branch (3.1.27's dedup fix —
     * the embedded branch still never shows a bypass table, since
     * TwoFactorController::render() already shows the unified one). Only
     * HOW each branch's HTML is produced changed: via
     * TemplateRenderer::render() + templates/admin/email-2fa-*.tpl
     * instead of raw echo.
     */
    public function renderContent(bool $standalone = true)
    {
        $errorMessage = null;
        if(isset($_SESSION["nnm_e2fa_error"])) {
            $errorMessage = (string) $_SESSION["nnm_e2fa_error"];
            unset($_SESSION["nnm_e2fa_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_e2fa_success"])) {
            $successMessage = (string) $_SESSION["nnm_e2fa_success"];
            unset($_SESSION["nnm_e2fa_success"]);
        }

        $overview = $this->buildOverviewViewModel();

        if($standalone) {
            $token = security_pack_csrf_token();
            echo TemplateRenderer::render("email-2fa-standalone", [
                "errorMessage" => $errorMessage,
                "successMessage" => $successMessage,
                "overview" => $overview,
                "bypasses" => $this->buildBypassesViewModel($token),
                "userTypeOptions" => $this->userTypeOptions(),
            ]);
            return;
        }

        echo TemplateRenderer::render("email-2fa-embedded", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "overview" => $overview,
        ]);
    }

    /** @return array<string,string> type => label, same order as UserIdentityType::ALL */
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
     * renderOverview()'s data preparation — same three per-
     * UserIdentityType queries (active/pending counts), same 24h
     * failed-verification count, same fail-soft all-zero fallback,
     * same "only show the Contact stat box once a contact row exists"
     * rule (the template checks $overview["contact"] !== null).
     *
     * @return array{client:array{active:int,pending:int},admin:array{active:int,pending:int},contact:?array{active:int,pending:int},recentFailures:int}
     */
    private function buildOverviewViewModel(): array
    {
        try {
            $counts = [];
            // Sub-account foundation: loops over UserIdentityType::ALL,
            // not a hardcoded 2-value list — see TwoFactorController's
            // matching comment. No contact rows exist in any install
            // today.
            foreach (UserIdentityType::ALL as $type) {
                $counts[$type] = [
                    "active" => (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->where("user_type", $type)->where("status", "active")->count(),
                    "pending" => (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->where("user_type", $type)->where("status", "pending")->count(),
                ];
            }
            $recentFailures = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")->where("event_type", "email_2fa.verification.failed")->where("created_at", ">=", date("Y-m-d H:i:s", time() - 86400))->count();
        } catch (\Throwable $e) {
            $counts = [UserIdentityType::CLIENT => ["active" => 0, "pending" => 0], UserIdentityType::ADMIN => ["active" => 0, "pending" => 0], UserIdentityType::CONTACT => ["active" => 0, "pending" => 0]];
            $recentFailures = 0;
        }
        // Only shown once a contact-typed row actually exists — keeps
        // today's 3-box layout (client/admin/failures) unchanged for
        // every install with zero contacts.
        $hasContact = $counts[UserIdentityType::CONTACT]["active"] > 0 || $counts[UserIdentityType::CONTACT]["pending"] > 0;
        return [
            "client" => $counts[UserIdentityType::CLIENT],
            "admin" => $counts[UserIdentityType::ADMIN],
            "contact" => $hasContact ? $counts[UserIdentityType::CONTACT] : null,
            "recentFailures" => $recentFailures,
        ];
    }

    /**
     * Step 33/34: explicit administrator manual bypass — requires admin
     * auth (implicit, this is an authenticated admin controller),
     * authorization, CSRF, POST, and a confirmation dialog before
     * submit. Lookup is by exact numeric WHMCS User id (the same
     * identity Email2faService keys everything by) rather than by
     * fuzzy name/email match, to avoid ever silently bypassing the
     * wrong account.
     */
    /**
     * PHASE 3.8: presentation-only extraction of the former
     * renderBypasses()'s data preparation — same
     * dctlab_security_pack_email2fa_bypasses query (whereNull revoked_at,
     * expires_at >= now, ordered by expires_at ASC, limit 100), same
     * fail-soft empty-array-on-error fallback, same form/row action
     * targets (a=bypass, a=revoke — deliberately still routed to
     * c=email2fa, NOT c=twoFactor, exactly as before: these POST to
     * Email2faController::bypass()/revoke() directly, see this
     * controller's own docblock on why that's correct even though the
     * page is now shown embedded on c=twoFactor). bypass()/revoke()
     * themselves are untouched below.
     *
     * @return array{token:string,rows:array}
     */
    private function buildBypassesViewModel($token): array
    {
        try {
            $dbRows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa_bypasses")
                ->whereNull("revoked_at")->where("expires_at", ">=", date("Y-m-d H:i:s"))
                ->orderBy("expires_at", "ASC")->limit(100)->get();
        } catch (\Throwable $e) {
            $dbRows = [];
        }
        $rows = [];
        foreach ($dbRows as $row) {
            $rows[] = [
                "id" => (int) $row->id,
                "userId" => (int) $row->user_id,
                "userType" => (string) $row->user_type,
                "scope" => (string) $row->scope,
                "expiresAt" => (string) $row->expires_at,
                "createdBy" => (string) $row->created_by,
                "reason" => (string) $row->reason,
            ];
        }
        return ["token" => $token, "rows" => $rows];
    }

    /**
     * 2026-08-27 — same Client/User identity fix as
     * TwoFactorController::bypass() (see that method's own docblock for
     * the full incident): this is a SECOND admin form that can create
     * an admin_manual bypass, and was equally vulnerable to an admin
     * typing a Client ID into the "WHMCS User ID" field. Reuses
     * TwoFactorController's own resolution logic rather than
     * duplicating it.
     */
    private function bypass()
    {
        $userType = UserIdentityType::normalize($_POST["user_type"] ?? null);
        $userId = (int) ($_POST["user_id"] ?? 0);
        $days = (int) ($_POST["days"] ?? 7);
        $reason = (string) ($_POST["reason"] ?? "");
        if($userId > 0 && $userType === UserIdentityType::CLIENT && class_exists(TwoFactorController::class)) {
            try {
                $isRealUser = \Illuminate\Database\Capsule\Manager::table("tblusers")->where("id", $userId)->exists();
            } catch (\Throwable $e) {
                $isRealUser = true; // fail open on inspection error, same as TwoFactorController's guard
            }
            if(!$isRealUser) {
                try {
                    $isRealClient = \Illuminate\Database\Capsule\Manager::table("tblclients")->where("id", $userId)->exists();
                } catch (\Throwable $e) {
                    $isRealClient = false;
                }
                if($isRealClient) {
                    $realUserIds = TwoFactorController::resolveUserIdsForClient($userId);
                    $_SESSION["nnm_e2fa_error"] = "#" . $userId . " is a WHMCS Client ID, not a WHMCS User ID — a bypass created against it would never match at login. " . (count($realUserIds) > 0 ? "The real User ID(s) for this client are: " . implode(", ", $realUserIds) . "." : "No WHMCS User account is linked to this client yet, so no bypass can be created for it.");
                    redir("module=security_pack&c=twoFactor", "addonmodules.php");
                    return;
                }
            }
        }
        if($userId > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            Email2faService::createAdminBypass($userId, $userType, $days, "admin#" . $adminId, $reason);
            $_SESSION["nnm_e2fa_success"] = "Bypass created.";
        } else {
            $_SESSION["nnm_e2fa_error"] = "A valid User ID is required.";
        }
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }

    private function revoke()
    {
        $id = (int) ($_POST["id"] ?? 0);
        if($id > 0) {
            $adminId = (int) ($_SESSION["adminid"] ?? 0);
            Email2faService::revokeBypass($id, "admin#" . $adminId);
        }
        $_SESSION["nnm_e2fa_success"] = "Revoked.";
        redir("module=security_pack&c=twoFactor", "addonmodules.php");
    }
}
