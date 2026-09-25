<?php
/**
 * Expected variables:
 *   string $label
 *   int|string|null $value   pass null (not 0) when the statistic is genuinely unavailable
 *   string $href (optional)
 *   string $hint (optional, added Phase 3.6B) — small muted line under the label (e.g. CSP Reports'
 *       "all-time occurrence count across all groups"). Omitted entirely when "" (the default), so
 *       every pre-3.6B call site (Dashboard, IP Restrictions) renders byte-identical output unchanged.
 */
$label = $label ?? "";
$value = $value ?? null;
$href = $href ?? "";
$hint = $hint ?? "";
$display = $value === null ? "Not enough data" : (string) $value;
$isUnavailable = $value === null;
?>
<<?php echo $href !== "" ? "a href=\"" . security_pack_e($href) . "\"" : "div"; ?> class="sp-stat<?php echo $isUnavailable ? " sp-stat-empty" : ""; ?>">
    <span class="sp-stat-value"><?php echo security_pack_e($display); ?></span>
    <span class="sp-stat-label"><?php echo security_pack_e($label); ?></span>
    <?php if($hint !== ""): ?><span class="sp-stat-hint"><?php echo security_pack_e($hint); ?></span><?php endif; ?>
</<?php echo $href !== "" ? "a" : "div"; ?>>
