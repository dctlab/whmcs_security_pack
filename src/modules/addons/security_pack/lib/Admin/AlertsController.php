<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\SecurityAlertService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — Alerts (Activity > Alerts).
 *
 * PHASE 3.3 (2026-08-24): migrated to the templates/admin/ presentation
 * layer, same pattern validated on Dashboard (Phase 3.2) — this
 * controller now prepares a data array and hands it to TemplateRenderer
 * instead of echoing HTML directly. Functionally UNCHANGED: same
 * SecurityAlertService::gather() call, same CSRF/POST/permission
 * handling on save(), same dctlab_security_pack setting key
 * ("alerts_email_enabled"), same security_pack_record_event() call. Not
 * a second event/notification system — see this class's own original
 * docblock note, preserved below.
 *
 * A curated, read-only summary derived from existing signals (see
 * SecurityAlertService) — not a second event/notification system. The
 * only state-changing action here is the digest-email opt-in toggle,
 * which reuses WHMCS's own sendAdminMessage()/email-template mechanism
 * (see core/security_intelligence.php) rather than adding a new
 * notification channel.
 */
class AlertsController
{
    private function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
    }

    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        if($action === "save") {
            if($_SERVER["REQUEST_METHOD"] !== "POST") {
                redir("module=security_pack&c=alerts", "addonmodules.php");
            }
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_alert_error"] = "Your session token expired — please try again.";
                redir("module=security_pack&c=alerts", "addonmodules.php");
            }
            $this->save();
            return;
        }
        $this->render();
    }

    private function render()
    {
        $token = security_pack_csrf_token();
        $settings = security_pack_settings();
        $emailEnabled = !empty($settings["alerts_email_enabled"]) && $settings["alerts_email_enabled"] !== "0";

        $errorMessage = null;
        if(isset($_SESSION["nnm_alert_error"])) {
            $errorMessage = (string) $_SESSION["nnm_alert_error"];
            unset($_SESSION["nnm_alert_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_alert_success"])) {
            $successMessage = (string) $_SESSION["nnm_alert_success"];
            unset($_SESSION["nnm_alert_success"]);
        }

        try {
            $alerts = SecurityAlertService::gather($settings);
        } catch (\Throwable $e) {
            $alerts = [];
        }

        $content = TemplateRenderer::render("alerts", [
            "token" => $token,
            "emailEnabled" => $emailEnabled,
            "successMessage" => $successMessage,
            "errorMessage" => $errorMessage,
            "alerts" => $alerts,
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Alerts",
            "pageDescription" => "A curated summary of meaningful security conditions — repeated failures, IP/country/CSP spikes, a Security Score drop, or unacknowledged high-severity anomalies.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    private function save()
    {
        $enabled = isset($_POST["alerts_email_enabled"]) && $_POST["alerts_email_enabled"] ? "1" : "0";
        if($enabled === "1") {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "alerts_email_enabled"], ["setting" => "alerts_email_enabled", "value" => "1"]);
        } else {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->where("setting", "alerts_email_enabled")->delete();
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("alert.configuration.changed", "Security alert digest email setting changed.", ["enabled" => $enabled === "1"]);
        }
        $_SESSION["nnm_alert_success"] = "Saved.";
        redir("module=security_pack&c=alerts", "addonmodules.php");
    }
}
