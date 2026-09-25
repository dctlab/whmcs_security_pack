<?php
/**
 * One numeric setting (auto_delete_days, email_2fa_length,
 * email_2fa_minutes, geo_cache_days, lc_cookie_days) — same
 * name="settings[$name]" contract SettingsController::save() expects.
 *
 * Expected variables:
 *   string $name
 *   string $label
 *   int|string $value      already resolved by the controller (same intval()/default fallback as the original)
 *   string $tooltip (optional)
 *   int|null $min (optional)
 *   int|null $max (optional)
 *   string $suffix (optional) — e.g. "Days" / "Minutes"
 */
$name = $name ?? "";
$label = $label ?? "";
$value = $value ?? "";
$tooltip = $tooltip ?? "";
$min = $min ?? null;
$max = $max ?? null;
$suffix = $suffix ?? "";
?>
<tr>
    <td class="fieldlabel" width="50%">
        <?php echo security_pack_e($label); ?>
        <?php if($tooltip !== ""): ?> <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="<?php echo security_pack_e($tooltip); ?>"></i><?php endif; ?>
    </td>
    <td>
        <input name="settings[<?php echo security_pack_e($name); ?>]" value="<?php echo security_pack_e($value); ?>" class="form-control input-100" type="number" style="display:inline-block;width:auto;" <?php echo $min !== null ? 'min="' . security_pack_e($min) . '"' : ""; ?> <?php echo $max !== null ? 'max="' . security_pack_e($max) . '"' : ""; ?>>
        <?php if($suffix !== ""): ?><small> <?php echo security_pack_e($suffix); ?></small><?php endif; ?>
    </td>
</tr>
