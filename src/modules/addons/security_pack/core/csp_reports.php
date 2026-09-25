<?php

declare(strict_types=1);

// Security Pack 2.5 — CSP Reports retention/cleanup wiring. The actual
// collection endpoint is csp-report.php (a standalone, unauthenticated
// entry point — see that file's header comment for why it can't be a
// hook). This file only wires the EXISTING DailyCronJob hook (already
// used by RateLimiter::prune()/security_pack_prune_events() in
// core/loginHistory.php) to also purge CSP telemetry — no second cron
// mechanism.

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

add_hook("DailyCronJob", 1, function ($vars) {
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\CspReportService")) {
        return;
    }
    $settings = security_pack_settings();
    $retentionDays = isset($settings["csp_report_retention_days"]) ? max(1, (int) $settings["csp_report_retention_days"]) : 30;
    $maxRows = isset($settings["csp_report_max_rows"]) ? max(100, (int) $settings["csp_report_max_rows"]) : 5000;
    \WHMCS\Module\Addon\Security_Pack\Security\CspReportService::purge($retentionDays, $maxRows);
});
