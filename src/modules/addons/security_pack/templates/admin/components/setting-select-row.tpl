<?php
/**
 * One dropdown setting (login_notification, admin_login_notification) —
 * same name="settings[$name]" contract, same option VALUES as the
 * original (string comparison against "0"/"1"/"2" in the controller).
 *
 * Expected variables:
 *   string $name
 *   string $label
 *   string $tooltip (optional)
 *   array $options   [value => label, ...] in display order
 *   string $value    currently selected value
 */
$name = $name ?? "";
$label = $label ?? "";
$tooltip = $tooltip ?? "";
$options = $options ?? [];
$value = $value ?? "";
?>
<tr>
    <td class="fieldlabel" width="50%">
        <?php echo security_pack_e($label); ?>
        <?php if($tooltip !== ""): ?> <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="<?php echo security_pack_e($tooltip); ?>"></i><?php endif; ?>
    </td>
    <td>
        <select name="settings[<?php echo security_pack_e($name); ?>]" class="form-control">
            <?php foreach ($options as $optValue => $optLabel): ?>
                <option value="<?php echo security_pack_e($optValue); ?>" <?php echo ((string) $value === (string) $optValue) ? 'selected="selected"' : ""; ?>><?php echo security_pack_e($optLabel); ?></option>
            <?php endforeach; ?>
        </select>
    </td>
</tr>
