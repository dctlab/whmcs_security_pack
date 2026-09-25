<?php
/**
 * DiagnosticsController's own 4-state result vocabulary — PASS/WARNING/
 * FAIL/INFO — preserved exactly as the original private badge() method
 * produced it (same Bootstrap label-* classes, same fallback to "info"
 * for an unrecognized status). Deliberately its own component rather
 * than reusing components/status-badge.tpl, which is a 2-state on/off
 * toggle indicator with different semantics — collapsing 4 distinct
 * diagnostic outcomes into on/off would lose information the backend
 * actually distinguishes (Phase 3.4 spec: "do not reduce everything to
 * green = good, red = bad if the backend distinguishes multiple states").
 *
 * Expected variables:
 *   string $status  "pass"|"warning"|"fail"|"info" (unrecognized values fall back to "info", matching the original)
 */
$status = $status ?? "info";
$map = [
    "pass" => ["label" => "PASS", "class" => "label-success"],
    "warning" => ["label" => "WARNING", "class" => "label-warning"],
    "fail" => ["label" => "FAIL", "class" => "label-danger"],
    "info" => ["label" => "INFO", "class" => "label-default"],
];
$resolved = $map[$status] ?? $map["info"];
?><span class="label <?php echo security_pack_e($resolved["class"]); ?>"><?php echo security_pack_e($resolved["label"]); ?></span>
