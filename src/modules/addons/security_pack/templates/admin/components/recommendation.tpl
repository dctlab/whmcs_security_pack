<?php
/**
 * Expected variables:
 *   string $severity  "critical"|"warning"|"info"|"pass"
 *   string $message
 *   string $action (optional link label), string $href (optional link target)
 */
$severity = $severity ?? "info";
$message = $message ?? "";
$action = $action ?? "";
$href = $href ?? "";
$priorityLabel = ["critical" => "HIGH PRIORITY", "warning" => "MEDIUM", "info" => "LOW", "pass" => "OK"][$severity] ?? strtoupper($severity);
?>
<div class="sp-recommendation sp-recommendation-<?php echo security_pack_e($severity); ?>">
    <span class="sp-recommendation-priority"><?php echo security_pack_e($priorityLabel); ?></span>
    <span class="sp-recommendation-message"><?php echo security_pack_e($message); ?></span>
    <?php if($action !== "" && $href !== ""): ?>
        <a class="sp-recommendation-action" href="<?php echo security_pack_e($href); ?>"><?php echo security_pack_e($action); ?> &raquo;</a>
    <?php endif; ?>
</div>
