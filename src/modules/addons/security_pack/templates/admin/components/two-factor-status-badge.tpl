<?php
/**
 * Phase 5 UI polish — badge for TwoFactorController's own report-status
 * vocabulary (buildReportRows() / TwoFactorAuthenticationService::
 * reportStatusLabel()): "Enabled" | "Disabled" | "Not Configured". Kept
 * as ITS OWN component rather than reusing components/status-badge.tpl
 * (a 2-state on/off toggle) or components/check-badge.tpl
 * (DiagnosticsController's own 4-state PASS/WARNING/FAIL/INFO
 * vocabulary) — same "don't collapse a backend distinction the UI
 * actually has" principle check-badge.tpl already established.
 * "Disabled" and "Not Configured" are semantically different (one was
 * on and turned off; the other was never set up) and get visibly
 * different badge classes here — never merged into the same look.
 *
 * Maps ONLY the existing string values buildReportRows() already
 * produces; introduces no new backend status. An unrecognized value
 * falls back to a neutral badge showing that exact string uppercased,
 * the same "don't crash on an unrecognized value" convention
 * check-badge.tpl already uses for its own fallback.
 *
 * Expected variables:
 *   string $status  "Enabled" | "Disabled" | "Not Configured"
 */
$status = $status ?? "Not Configured";
$map = [
    "Enabled" => ["class" => "sp-badge-on", "label" => "ENABLED"],
    "Disabled" => ["class" => "sp-badge-warn", "label" => "DISABLED"],
    "Not Configured" => ["class" => "sp-badge-off", "label" => "NOT CONFIGURED"],
];
$resolved = $map[$status] ?? ["class" => "sp-badge-off", "label" => strtoupper($status)];
?><span class="sp-badge <?php echo security_pack_e($resolved["class"]); ?>"><?php echo security_pack_e($resolved["label"]); ?></span>
