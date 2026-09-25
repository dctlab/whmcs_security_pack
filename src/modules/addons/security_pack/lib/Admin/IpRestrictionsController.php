<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\IpRestrictionService;
use WHMCS\Module\Addon\Security_Pack\Security\IpUtil;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — IP Restrictions admin page.
 *
 * SAFE BY DEFAULT: adding rules here is the only way this feature does
 * anything — an upgraded install with zero rules behaves exactly as
 * before (see IpRestrictionService::evaluate(), which returns
 * allowed=true when no rules match).
 *
 * All state-changing actions go through the existing Phase 1 CSRF
 * token (security_pack_csrf_token()/security_pack_csrf_valid()) — no
 * second CSRF mechanism.
 *
 * PHASE 3.6A (2026-08-24): migrated to the templates/admin/ presentation
 * layer (same pattern as Dashboard/Alerts/Activity/Analytics/
 * Diagnostics/Settings). index()/save()/setEnabled()/delete() — the
 * action dispatch, the POST-only guard, the CSRF check, the target
 * normalization + validation (IpRestrictionService::normalizeTarget()),
 * the admin-lockout check (IpRestrictionService::wouldLockOutCurrentAdmin()),
 * the insert/update/delete queries, and every security_pack_record_event()
 * call — are copied verbatim, byte-for-byte. Only render() (formerly
 * three private methods that echoed HTML directly) now builds a
 * view-model and hands it to TemplateRenderer; no query, no validation
 * rule, and no redirect target changed.
 */
class IpRestrictionsController
{
    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        if(!in_array($action, ["index", "add_form"], true) && !security_pack_csrf_valid()) {
            $_SESSION["nnm_ipr_error"] = "Your session token expired — please try again.";
            redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
        }
        // Security Pack 2.3 (Step 12/14): every state-changing action
        // here is POST-only now (was GET+token for enable/disable/delete).
        $postOnlyActions = ["save", "enable", "disable", "delete"];
        if(in_array($action, $postOnlyActions, true) && $_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
        }

        switch ($action) {
            case "save":
                $this->save();
                return;
            case "enable":
                $this->setEnabled(true);
                return;
            case "disable":
                $this->setEnabled(false);
                return;
            case "delete":
                $this->delete();
                return;
        }

        $this->render();
    }

    private function render()
    {
        $token = security_pack_csrf_token();

        $errorMessage = null;
        if(isset($_SESSION["nnm_ipr_error"])) {
            $errorMessage = (string) $_SESSION["nnm_ipr_error"];
            unset($_SESSION["nnm_ipr_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_ipr_success"])) {
            $successMessage = (string) $_SESSION["nnm_ipr_success"];
            unset($_SESSION["nnm_ipr_success"]);
        }
        $lockoutWarning = null;
        if(isset($_SESSION["nnm_ipr_lockout_warning"])) {
            $lockoutWarning = $_SESSION["nnm_ipr_lockout_warning"];
            unset($_SESSION["nnm_ipr_lockout_warning"]);
        }

        // Same unmodified query/ordering the pre-migration renderList()
        // ran: specificity DESC, priority DESC, id DESC.
        $rules = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->orderBy("mask_bits", "DESC")->orderBy("priority", "DESC")->orderBy("id", "DESC")->get();

        $content = TemplateRenderer::render("ip-restrictions", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "lockoutWarning" => $lockoutWarning,
            "token" => $token,
            "stats" => $this->buildStats($rules),
            "rules" => $this->buildRuleRows($rules),
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "IP Restrictions",
            "pageDescription" => "Protect this installation using IP-based allow/block rules.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /**
     * Derived purely from the same $rules collection the unmodified query
     * above already fetches — no new query, no new business rule. The
     * original page already showed a total rule count ("N rule(s)"); this
     * only breaks that same number down by enabled/disabled and type.
     */
    private function buildStats($rules): array
    {
        $total = count($rules);
        $enabled = 0;
        $disabled = 0;
        $allow = 0;
        $block = 0;
        foreach ($rules as $rule) {
            if($rule->enabled) {
                $enabled++;
            } else {
                $disabled++;
            }
            if($rule->rule_type === "allow") {
                $allow++;
            } else {
                $block++;
            }
        }
        return ["total" => $total, "enabled" => $enabled, "disabled" => $disabled, "allow" => $allow, "block" => $block];
    }

    /** Same per-row fields the original renderList() computed inline (typeBadge/statusLabel logic unchanged, just returned as data instead of echoed). */
    private function buildRuleRows($rules): array
    {
        $rows = [];
        foreach ($rules as $rule) {
            $expired = (bool) ($rule->expires_at && strtotime($rule->expires_at) < time());
            $rows[] = [
                "id" => (int) $rule->id,
                "ruleType" => (string) $rule->rule_type,
                "target" => (string) $rule->target,
                "description" => (string) $rule->description,
                "enabled" => (bool) $rule->enabled,
                "expired" => $expired,
                "expiresDisplay" => $rule->expires_at ?: "Never",
                "priority" => (int) $rule->priority,
                "createdBy" => (string) $rule->created_by,
            ];
        }
        return $rows;
    }

    private function save()
    {
        $ruleType = ($_POST["rule_type"] ?? "block") === "allow" ? "allow" : "block";
        $targetRaw = trim((string) ($_POST["target"] ?? ""));
        $description = trim((string) ($_POST["description"] ?? ""));
        $expires = (string) ($_POST["expires"] ?? "never");
        $priority = (int) ($_POST["priority"] ?? 0);
        $confirmLockout = isset($_POST["confirm_lockout"]) && $_POST["confirm_lockout"] === "1";

        $normalized = IpRestrictionService::normalizeTarget($targetRaw);
        if(!$normalized) {
            $_SESSION["nnm_ipr_error"] = "\"" . $targetRaw . "\" is not a valid IP address or CIDR range.";
            redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
        }

        $expiresAt = null;
        if($expires !== "never" && ctype_digit($expires)) {
            $expiresAt = date("Y-m-d H:i:s", time() + ((int) $expires * 86400));
        }

        // Admin lockout protection (Step 16): server-side check, never
        // trusted to client-side JS alone.
        if($ruleType === "block" && !$confirmLockout) {
            $settings = security_pack_settings();
            $adminIp = function_exists("security_pack_detect_visitor_ip") ? security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto") : "";
            if($adminIp) {
                $existingRules = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")
                    ->where("enabled", 1)
                    ->where(function ($q) {
                        $q->whereNull("expires_at")->orWhere("expires_at", ">", date("Y-m-d H:i:s"));
                    })->get()->map(static fn ($r) => (array) $r)->all();
                if(IpRestrictionService::wouldLockOutCurrentAdmin($adminIp, $normalized["target"], $existingRules)) {
                    $_SESSION["nnm_ipr_lockout_warning"] = [
                        "target" => $normalized["target"], "admin_ip" => $adminIp, "rule_type" => $ruleType,
                        "description" => $description, "expires" => $expires, "priority" => $priority,
                    ];
                    redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
                }
            }
        }

        $adminUsername = $_SESSION["adminid"] ?? "admin";
        if(class_exists("\\WHMCS\\Authentication\\CurrentUser")) {
            try {
                $admin = (new \WHMCS\Authentication\CurrentUser())->administrator();
                if($admin && !empty($admin->username)) {
                    $adminUsername = $admin->username;
                }
            } catch (\Throwable $e) {
            }
        }

        $id = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->insertGetId([
            "rule_type" => $ruleType,
            "target" => $normalized["target"],
            "mask_bits" => $normalized["mask_bits"],
            "description" => $description ?: null,
            "enabled" => 1,
            "priority" => $priority,
            "expires_at" => $expiresAt,
            "created_by" => (string) $adminUsername,
            "created_at" => date("Y-m-d H:i:s"),
            "updated_at" => date("Y-m-d H:i:s"),
        ]);

        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("ip_rule.created", "IP restriction rule created: " . strtoupper($ruleType) . " " . $normalized["target"], ["id" => $id, "rule_type" => $ruleType, "target" => $normalized["target"], "expires_at" => $expiresAt], $ruleType === "block" ? "warning" : "info");
        }

        $_SESSION["nnm_ipr_success"] = "Rule saved.";
        redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
    }

    private function setEnabled($enabled)
    {
        $id = (int) ($_REQUEST["id"] ?? 0);
        if($id > 0) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->where("id", $id)->update(["enabled" => $enabled ? 1 : 0, "updated_at" => date("Y-m-d H:i:s")]);
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event($enabled ? "ip_rule.enabled" : "ip_rule.disabled", "IP restriction rule #" . $id . " " . ($enabled ? "enabled" : "disabled") . ".", ["id" => $id]);
            }
        }
        redir("module=security_pack&c=ipRestrictions", "addonmodules.php");
    }

    private function delete()
    {
        $id = (int) ($_REQUEST["id"] ?? 0);
        if($id > 0) {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->where("id", $id)->delete();
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("ip_rule.deleted", "IP restriction rule #" . $id . " deleted.", ["id" => $id]);
            }
        }
        redir("module=security_pack&c=ipRestrictions&deleted=1", "addonmodules.php");
    }
}
