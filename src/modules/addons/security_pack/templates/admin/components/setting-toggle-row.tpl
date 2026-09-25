<?php
/**
 * One boolean setting, rendered as the SAME on/off switch control the
 * original Settings page used (.nnm_switch/.nnm_slider — see settings.tpl's
 * own <style>, carried over verbatim). Submits as name="settings[$name]"
 * value="on" when checked, absent when unchecked — the exact semantics
 * SettingsController::save() already expects (isset() check, no 0/1
 * string comparison) — this component does not change that contract.
 *
 * Expected variables:
 *   string $name      the settings[] key — must be one of SettingsController::OWNED_KEYS
 *   string $label
 *   bool   $checked
 *   string $tooltip (optional)
 *   string $description (optional) — small muted text under the label (used by Security Headers)
 *   array|null $badge (optional) — ["label","class"] e.g. ["Advanced","label-default"] / ["Caution","label-danger"] — same risk-flagging the original already used for CSP/HSTS, not a new warning mechanism
 *   string $extraClass (optional) — extra class on the checkbox itself (e.g. "country_restriction_changes")
 *   bool   $indent (optional) — renders "&#8627;" before the label (used for the nested HSTS-confirmation row)
 */
$name = $name ?? "";
$label = $label ?? "";
$checked = $checked ?? false;
$tooltip = $tooltip ?? "";
$description = $description ?? "";
$badge = $badge ?? null;
$extraClass = $extraClass ?? "";
$indent = $indent ?? false;
?>
<tr>
    <td class="fieldlabel" width="50%">
        <?php if($indent): ?>&nbsp;&nbsp;&#8627; <?php endif; ?>
        <?php echo security_pack_e($label); ?>
        <?php if($badge !== null): ?> <span class="label <?php echo security_pack_e($badge["class"]); ?>"><?php echo security_pack_e($badge["label"]); ?></span><?php endif; ?>
        <?php if($tooltip !== ""): ?> <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="<?php echo security_pack_e($tooltip); ?>"></i><?php endif; ?>
        <?php if($description !== ""): ?><br><small class="text-muted"><?php echo security_pack_e($description); ?></small><?php endif; ?>
    </td>
    <td>
        <label class="nnm_switch">
            <input type="checkbox" class="<?php echo security_pack_e($extraClass); ?>" value="on" <?php echo $checked ? 'checked="checked"' : ""; ?> name="settings[<?php echo security_pack_e($name); ?>]">
            <span class="nnm_slider round"></span>
        </label>
    </td>
</tr>
