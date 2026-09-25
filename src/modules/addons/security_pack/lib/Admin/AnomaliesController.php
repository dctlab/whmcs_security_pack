<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\SecurityAnomalyService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — Anomalies (Activity > Anomalies).
 *
 * Runs SecurityAnomalyService::gather() (deterministic, rule-based — see
 * that class for why this is not "AI") against the EXISTING Security
 * Events table, syncs fresh findings into dctlab_security_pack_anomalies
 * (for the acknowledge/dismiss lifecycle — a finding that keeps
 * reoccurring stays a single row with an updated timestamp, not a new
 * row every page load), and renders them with full evidence/reasoning.
 *
 * Dismissing an anomaly suppresses that SPECIFIC recurring shape
 * (dedupe_key) for a defined cool-down window, not "this rule,
 * permanently, forever" — see suppressDays().
 *
 * PHASE 3.6B (2026-08-24): migrated to the templates/admin/ presentation
 * layer. index()/sync()/setStatus() — the POST-only+CSRF guard, the
 * detection sync/upsert/suppression-window logic, the
 * security_pack_record_event() calls, and every query — are copied
 * verbatim, byte-for-byte. Only render() (which echoed HTML directly)
 * was rebuilt to produce a view-model for TemplateRenderer; no query, no
 * business rule, and no redirect target changed.
 */
class AnomaliesController
{
    private const SUPPRESS_DAYS = 7;

    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        $postOnlyActions = ["acknowledge", "dismiss"];
        if(in_array($action, $postOnlyActions, true)) {
            if($_SERVER["REQUEST_METHOD"] !== "POST") {
                redir("module=security_pack&c=anomalies", "addonmodules.php");
            }
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_anomaly_error"] = "Your session token expired — please try again.";
                redir("module=security_pack&c=anomalies", "addonmodules.php");
            }
        }

        switch ($action) {
            case "acknowledge":
                $this->setStatus("acknowledged");
                return;
            case "dismiss":
                $this->setStatus("dismissed");
                return;
        }

        $this->sync();
        $this->render();
    }

    /**
     * Runs detection and upserts findings into dctlab_security_pack_anomalies
     * by dedupe_key. Never overwrites an acknowledged/dismissed row's
     * status — only a currently-suppressed (dismissed + still within its
     * cool-down) dedupe_key is skipped entirely; everything else either
     * updates the existing row's reason/evidence/timestamp or inserts a
     * fresh open row.
     */
    private function sync()
    {
        if(!\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_anomalies")) {
            return;
        }
        $settings = security_pack_settings();
        try {
            $findings = SecurityAnomalyService::gather($settings);
        } catch (\Throwable $e) {
            return;
        }
        $now = date("Y-m-d H:i:s");
        foreach ($findings as $finding) {
            try {
                $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->where("dedupe_key", $finding["dedupe_key"])->first();
                if($existing) {
                    if($existing->status === "dismissed" && $existing->suppressed_until && strtotime($existing->suppressed_until) > time()) {
                        continue; // still suppressed — do not resurrect
                    }
                    if($existing->status === "dismissed") {
                        // Suppression window elapsed — this shape is
                        // still occurring, so it comes back as a fresh
                        // open finding (never permanently suppressed).
                        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->where("id", $existing->id)->update([
                            "status" => "open", "severity" => $finding["severity"], "confidence" => $finding["confidence"],
                            "reason" => $finding["reason"], "evidence" => json_encode($finding["evidence"]),
                            "ip" => $finding["ip"], "suppressed_until" => null, "updated_at" => $now,
                        ]);
                    } else {
                        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->where("id", $existing->id)->update([
                            "severity" => $finding["severity"], "confidence" => $finding["confidence"],
                            "reason" => $finding["reason"], "evidence" => json_encode($finding["evidence"]), "updated_at" => $now,
                        ]);
                    }
                } else {
                    \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->insert([
                        "rule" => $finding["rule"], "dedupe_key" => $finding["dedupe_key"], "severity" => $finding["severity"],
                        "confidence" => $finding["confidence"], "reason" => $finding["reason"], "evidence" => json_encode($finding["evidence"]),
                        "ip" => $finding["ip"], "status" => "open", "created_at" => $now, "updated_at" => $now,
                    ]);
                    if(function_exists("security_pack_record_event") && in_array($finding["severity"], ["high", "critical"], true)) {
                        security_pack_record_event("anomaly.detected", "Anomaly detected: " . $finding["reason"], ["rule" => $finding["rule"]], $finding["severity"] === "critical" ? "critical" : "warning");
                    }
                }
            } catch (\Throwable $e) {
            }
        }
    }

    private function render()
    {
        $token = security_pack_csrf_token();

        $errorMessage = null;
        if(isset($_SESSION["nnm_anomaly_error"])) {
            $errorMessage = (string) $_SESSION["nnm_anomaly_error"];
            unset($_SESSION["nnm_anomaly_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_anomaly_success"])) {
            $successMessage = (string) $_SESSION["nnm_anomaly_success"];
            unset($_SESSION["nnm_anomaly_success"]);
        }

        $statusFilter = in_array($_GET["status"] ?? "open", ["open", "acknowledged", "dismissed", "all"], true) ? $_GET["status"] : "open";

        $unavailable = false;
        $rows = [];
        try {
            $query = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies");
            if($statusFilter !== "all") {
                $query->where("status", $statusFilter);
            }
            $dbRows = $query->orderBy("updated_at", "DESC")->limit(200)->get();
        } catch (\Throwable $e) {
            $unavailable = true;
            $dbRows = [];
        }

        if(!$unavailable) {
            foreach ($dbRows as $row) {
                $sevClass = ["critical" => "panel-danger", "high" => "panel-danger", "warning" => "panel-warning", "info" => "panel-default"][$row->severity] ?? "panel-default";
                $evidenceOut = [];
                $evidence = json_decode((string) $row->evidence, true);
                if(is_array($evidence) && $evidence) {
                    foreach ($evidence as $k => $v) {
                        $evidenceOut[$k] = is_scalar($v) ? $v : json_encode($v);
                    }
                }
                $rows[] = [
                    "id" => (int) $row->id,
                    "severity" => (string) $row->severity,
                    "panelClass" => $sevClass,
                    "rule" => (string) $row->rule,
                    "confidence" => (string) $row->confidence,
                    "status" => (string) $row->status,
                    "reason" => (string) $row->reason,
                    "evidence" => $evidenceOut,
                    "createdAt" => (string) $row->created_at,
                    "updatedAt" => (string) $row->updated_at,
                ];
            }
        }

        $content = TemplateRenderer::render("anomalies", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "token" => $token,
            "statusFilter" => $statusFilter,
            "unavailable" => $unavailable,
            "rows" => $rows,
            "suppressDays" => self::SUPPRESS_DAYS,
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Anomalies",
            "pageDescription" => "Deterministic, rule-based findings against your existing Security Events.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    private function setStatus(string $status)
    {
        $id = (int) ($_POST["id"] ?? 0);
        if($id > 0) {
            $update = ["status" => $status, "updated_at" => date("Y-m-d H:i:s")];
            if($status === "dismissed") {
                // Suppress THIS specific recurring shape for a fixed
                // window — never permanent. If the same pattern is still
                // happening after the window, sync() will re-open it as
                // a fresh finding.
                $update["suppressed_until"] = date("Y-m-d H:i:s", time() + (self::SUPPRESS_DAYS * 86400));
            }
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->where("id", $id)->update($update);
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("anomaly." . $status, "Admin " . ($status === "dismissed" ? "dismissed" : "acknowledged") . " anomaly #" . $id . ".", ["id" => $id]);
            }
        }
        $_SESSION["nnm_anomaly_success"] = "Updated.";
        redir("module=security_pack&c=anomalies", "addonmodules.php");
    }
}
