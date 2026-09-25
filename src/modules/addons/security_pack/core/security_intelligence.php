<?php

declare(strict_types=1);

// Security Pack 2.5 — Security Intelligence wiring: failed-login event
// capture (needed by SecurityAnomalyService's brute-force rules — 2.4.0
// only ever recorded SUCCESSFUL logins), the daily Security Score
// snapshot (needed for score-drop trend/alerting), and the optional
// daily alert digest email. All three reuse EXISTING infrastructure:
// security_pack_record_event() for the event, the EXISTING DailyCronJob
// hook already used elsewhere in this module for the cron work, and
// WHMCS's own sendAdminMessage()/email-template mechanism (already used
// by the Phase 1 admin login notification) for delivery — no second
// event system, no second cron mechanism, no new notification channel.

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

add_hook("UserLoginFailed", 1, function ($vars) {
    if(function_exists("security_pack_record_event")) {
        // Never log the attempted password — $vars intentionally
        // contributes nothing except the fact that a failure happened;
        // identity ties to IP (auto-captured by security_pack_record_event)
        // rather than the submitted username, which could itself be
        // attacker-supplied garbage.
        security_pack_record_event("login.client.failed", "Client login attempt failed.", [], "warning");
    }
});

add_hook("AdminLoginFailed", 1, function ($vars) {
    if(function_exists("security_pack_record_event")) {
        security_pack_record_event("login.admin.failed", "Admin login attempt failed.", [], "warning");
    }
});

add_hook("DailyCronJob", 1, function ($vars) {
    // Security Score daily snapshot — one row/day, existence-guarded
    // (updateOrInsert on the unique snapshot_date), so re-running cron
    // twice in a day never creates duplicate rows or skews the trend.
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\SecurityScoreService")) {
        return;
    }
    try {
        $settings = security_pack_settings();
        $facts = \WHMCS\Module\Addon\Security_Pack\Security\SecurityScoreService::gatherFacts();
        $result = \WHMCS\Module\Addon\Security_Pack\Security\SecurityScoreService::compute($settings, $facts);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_score_snapshots")->updateOrInsert(
            ["snapshot_date" => date("Y-m-d")],
            ["snapshot_date" => date("Y-m-d"), "score" => $result["score"], "max" => $result["max"], "created_at" => date("Y-m-d H:i:s")]
        );
        // Bounded — keep at most ~1 year of daily snapshots.
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_score_snapshots")
            ->where("snapshot_date", "<", date("Y-m-d", time() - (370 * 86400)))
            ->delete();
    } catch (\Throwable $e) {
    }
});

add_hook("DailyCronJob", 1, function ($vars) {
    // Optional daily digest email for open HIGH/CRITICAL alerts — off by
    // default. Reuses sendAdminMessage(), the exact same WHMCS core
    // function the Phase 1 admin login notification already uses; the
    // email template is seeded non-destructively in security_pack.php,
    // same pattern as the existing login-notification templates.
    $settings = security_pack_settings();
    if(empty($settings["alerts_email_enabled"]) || $settings["alerts_email_enabled"] === "0") {
        return;
    }
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\SecurityAlertService")) {
        return;
    }
    try {
        $alerts = \WHMCS\Module\Addon\Security_Pack\Security\SecurityAlertService::gather($settings);
        $notable = array_values(array_filter($alerts, static fn ($a) => in_array($a["severity"], ["high", "critical"], true)));
        if(!$notable) {
            return;
        }
        $summaryLines = [];
        foreach (array_slice($notable, 0, 10) as $alert) {
            $summaryLines[] = "[" . strtoupper($alert["severity"]) . "] " . $alert["title"] . " — " . $alert["reason"];
        }
        if(function_exists("sendAdminMessage")) {
            sendAdminMessage("Security Pack - Security Alert Digest", [
                "security_pack_alert_count" => (string) count($notable),
                "security_pack_alert_summary" => implode("\n", $summaryLines),
            ], "system", 0, 0);
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("alert.digest.sent", "Daily security alert digest sent (" . count($notable) . " open high/critical alert(s)).", ["count" => count($notable)]);
        }
    } catch (\Throwable $e) {
    }
});
