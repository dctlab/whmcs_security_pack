<?php
/**
 * Phase 5 UI polish — a security-method summary card for the TwoFactor
 * "Security Overview" section only. Deliberately a SEPARATE component
 * from components/stat-card.tpl (which several OTHER pages — Dashboard,
 * IP Restrictions, Email 2FA's own Overview panel — already rely on
 * rendering byte-identically) rather than modifying that shared
 * component.
 *
 * Takes the EXACT SAME view-model shape TwoFactorController::
 * buildOverviewViewModel() already produces (label/value/hint), PLUS the
 * clientCount/adminCount/subAccountCount integers that method now also
 * supplies (Phase 3.8C) — no new query, these are the same integers the
 * pre-existing "hint" string was already formatted from. The
 * "Active"/"Not Active" indicator is a pure display-time derivation of
 * the already-supplied $value (> 0 or not), computed here in the
 * template, not a new backend status.
 *
 * PHASE 3.8B (further UX polish, per live-review feedback): dropped the
 * standalone large numeric $value and the separate status-dot row — both
 * duplicated information the ACTIVE/NOT ACTIVE badge and the $hint string
 * already conveyed, and together they made each card read as a cramped,
 * run-together line rather than a clear box. $value is still
 * computed/used to derive $isActive — no backend value is lost, only its
 * redundant separate on-page display.
 *
 * PHASE 3.8C (per request — "proper metric cards, use Bootstrap"):
 * rebuilt on Bootstrap 3's own .panel/.panel-default/.panel-info instead
 * of a custom flexbox box, and the counts now render as separate labeled
 * lines ("1 client" / "0 administrators") using the new structured
 * clientCount/adminCount/subAccountCount fields, instead of parsing the
 * single pre-formatted "hint" string. Falls back to rendering "hint" as
 * a single line if clientCount/adminCount are ever absent (e.g. this
 * template used with an older caller) so nothing breaks either way.
 *
 * Expected variables:
 *   string $label
 *   int $value
 *   string $hint (optional, fallback — see above)
 *   int $clientCount (optional; renders the split count lines when present)
 *   int $adminCount (optional; renders the split count lines when present)
 *   int $subAccountCount (optional; only shown when > 0, same rule as
 *       the controller's own $breakdown string)
 */
$label = $label ?? "";
$value = (int) ($value ?? 0);
$hint = $hint ?? "";
$clientCount = isset($clientCount) ? (int) $clientCount : null;
$adminCount = isset($adminCount) ? (int) $adminCount : null;
$subAccountCount = isset($subAccountCount) ? (int) $subAccountCount : null;
$isActive = $value > 0;
$panelClass = $isActive ? "panel-info" : "panel-default";
?>
<div class="panel <?php echo $panelClass; ?> sp-method-card">
    <div class="panel-body">
        <span class="sp-method-card-label"><?php echo security_pack_e($label); ?></span>
        <span class="sp-badge <?php echo $isActive ? "sp-badge-on" : "sp-badge-off"; ?>"><?php echo $isActive ? "ACTIVE" : "NOT ACTIVE"; ?></span>
        <?php if($clientCount !== null && $adminCount !== null): ?>
            <div class="sp-method-card-counts">
                <span class="sp-method-card-count"><?php echo (int) $clientCount; ?> <?php echo $clientCount === 1 ? "client" : "clients"; ?></span>
                <span class="sp-method-card-count"><?php echo (int) $adminCount; ?> <?php echo $adminCount === 1 ? "administrator" : "administrators"; ?></span>
                <?php if($subAccountCount !== null && $subAccountCount > 0): ?>
                    <span class="sp-method-card-count"><?php echo (int) $subAccountCount; ?> <?php echo $subAccountCount === 1 ? "sub-account" : "sub-accounts"; ?></span>
                <?php endif; ?>
            </div>
        <?php elseif($hint !== ""): ?>
            <span class="sp-method-card-hint"><?php echo security_pack_e($hint); ?></span>
        <?php endif; ?>
    </div>
</div>
