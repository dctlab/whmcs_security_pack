<?php
/**
 * Outer card for one Settings section (Login History, Login Notification,
 * Advanced Security Options, Email 2FA, Content Protection, Country
 * Restriction, GeoIP Language & Currency, Security Headers) — genuinely
 * reused 8 times on this one page, unlike most other single-use panels
 * elsewhere in this module.
 *
 * Expected variables:
 *   string $title
 *   string $tooltip (optional) — rendered as the same fa-question-circle tooltip icon the original used
 *   array|null $masterToggle (optional) — ["name","checked","panelClass"] — when set, renders a toggle switch
 *       in the card header that shows/hides $content via the SAME nnm_show_hide_panel/data-panel JS
 *       mechanism the original controller used (see settings.tpl's own <script>, carried over verbatim —
 *       this component does not reimplement that behavior, only renders the markup it hooks into)
 *   string $content  pre-rendered inner HTML (a <table> of setting rows, or fully custom markup)
 *   string $panelClass (optional) — the nnm_config_panel's own class, so the master toggle above can target it
 */
$title = $title ?? "";
$tooltip = $tooltip ?? "";
$masterToggle = $masterToggle ?? null;
$content = $content ?? "";
$panelClass = $panelClass ?? "";
$isDisabled = $masterToggle !== null && empty($masterToggle["checked"]);
?>
<div class="sp-card">
    <h3 class="sp-card-title" style="display:flex;align-items:center;justify-content:space-between;">
        <span>
            <?php echo security_pack_e($title); ?>
            <?php if($tooltip !== ""): ?><i class="far fa-question-circle" data-toggle="tooltip" data-original-title="<?php echo security_pack_e($tooltip); ?>"></i><?php endif; ?>
        </span>
        <?php if($masterToggle !== null): ?>
            <label class="nnm_switch">
                <input type="checkbox" data-panel="<?php echo security_pack_e($panelClass); ?>" class="nnm_show_hide_panel" value="on" <?php echo !empty($masterToggle["checked"]) ? 'checked="checked"' : ""; ?> name="settings[<?php echo security_pack_e($masterToggle["name"]); ?>]">
                <span class="nnm_slider round"></span>
            </label>
        <?php endif; ?>
    </h3>
    <div class="nnm_config_panel <?php echo security_pack_e($panelClass); ?> <?php echo $isDisabled ? "disabled" : ""; ?>">
        <?php echo $content; ?>
    </div>
</div>
