<?php
/**
 * Phase 5 UI polish — one method's status card inside "Manage a User's
 * Two-Factor Authentication" (TwoFactorController::
 * buildManageUserViewModel()'s $providerRows). Maps ONLY that method's
 * existing 3-state vocabulary — "Active" | "Pending verification" |
 * "Not enrolled" — no new backend state, and a distinct badge class per
 * state (never merging "pending" into either "active" or "not
 * enrolled").
 *
 * Expected variables:
 *   string $label
 *   string $state
 */
$label = $label ?? "";
$state = $state ?? "Not enrolled";
$map = [
    "Active" => "sp-badge-on",
    "Pending verification" => "sp-badge-warn",
    "Not enrolled" => "sp-badge-off",
];
$badgeClass = $map[$state] ?? "sp-badge-off";
?>
<div class="sp-method-lookup-card">
    <span class="sp-method-lookup-label"><?php echo security_pack_e($label); ?></span>
    <span class="sp-badge <?php echo security_pack_e($badgeClass); ?>"><?php echo security_pack_e(strtoupper($state)); ?></span>
</div>
