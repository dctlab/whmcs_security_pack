<?php
/**
 * Expected variables:
 *   bool $on
 *   string $onLabel (default "Enabled"), string $offLabel (default "Disabled")
 */
$on = !empty($on);
$onLabel = $onLabel ?? "Enabled";
$offLabel = $offLabel ?? "Disabled";
?><span class="sp-badge sp-badge-<?php echo $on ? "on" : "off"; ?>"><?php echo $on ? security_pack_e($onLabel) : security_pack_e($offLabel); ?></span>
