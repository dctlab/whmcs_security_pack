<?php
/**
 * One entry from SecurityAlertService::gather() — reuses the same
 * .sp-recommendation visual pattern already validated on the Dashboard
 * (colored left border, priority pill, message, optional action link)
 * rather than introducing a parallel "alert card" style. Deliberately
 * NOT a straight reuse of components/recommendation.tpl though: that
 * component's severity->label map is written for RECOMMENDATION urgency
 * ("HIGH PRIORITY"/"MEDIUM"/"LOW"/"OK"), while AlertsController's
 * original markup showed the alert's own literal severity word
 * uppercased (CRITICAL/HIGH/WARNING/INFO — SecurityAlertService's real
 * severity vocabulary, confirmed via its gather() implementation).
 * Relabeling an alert's actual severity as a recommendation-style
 * urgency tier would be a real behavior/meaning change, not just a
 * restyle, so this stays its own thin component.
 *
 * Expected variables:
 *   string $severity  "critical"|"high"|"warning"|"info" (SecurityAlertService's vocabulary — unknown values fall back to the neutral/grey style, matching the original label-default fallback)
 *   string $title
 *   string $reason
 *   string $href (optional)
 */
$severity = $severity ?? "info";
$title = $title ?? "";
$reason = $reason ?? "";
$href = $href ?? "";
// "critical" and "high" shared the same red Bootstrap label-danger class
// in the original markup — preserved here via the same CSS color variant.
$colorClass = in_array($severity, ["critical", "high"], true)
    ? "sp-recommendation-critical"
    : ($severity === "warning" ? "sp-recommendation-warning" : ($severity === "info" ? "sp-recommendation-info" : ""));
?>
<div class="sp-recommendation <?php echo security_pack_e($colorClass); ?>">
    <span class="sp-recommendation-priority"><?php echo security_pack_e(strtoupper($severity)); ?></span>
    <span class="sp-recommendation-message">
        <?php if($title !== ""): ?><strong><?php echo security_pack_e($title); ?></strong><?php endif; ?>
        <?php if($reason !== ""): ?><?php echo $title !== "" ? " — " : ""; ?><?php echo security_pack_e($reason); ?><?php endif; ?>
    </span>
    <?php if($href !== ""): ?>
        <a class="sp-recommendation-action" href="<?php echo security_pack_e($href); ?>">Review &raquo;</a>
    <?php endif; ?>
</div>
