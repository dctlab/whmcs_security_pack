{*
 * DCTLAB Security Pack — "Login Notification" / "Disable Forgot Password
 * Reset" / "Session IP Security Limits" panel.
 *
 * RECONSTRUCTED 2026-08-27: this file was found missing on a live
 * production install (Smarty "No template default content" error on the
 * native client-area Security Settings page), even though the code that
 * writes/removes its {include} tag (core/user_security.php) and the
 * three form-handling actions it posts to (ClientController::
 * change_reset_password() / login_notification_alert() / limit_ip_range(),
 * all unmodified) were still fully present and working. It is rebuilt
 * here from that surviving evidence, not guessed from scratch:
 *
 *   - The exact variable names/shapes are dictated by
 *     core/user_security.php's own return array (nnmlang, login_notification,
 *     login_notification_allowed, ip_limits, security_pack_ip_limits,
 *     security_pack_disable_password, nnm_security_pack_successful,
 *     nnm_security_pack_error, remote_ip, disabled_reset_password,
 *     security_pack_csrf).
 *   - The exact POST targets/field names are dictated by
 *     lib/Client/ClientController.php's still-unmodified action methods:
 *     change_reset_password() and login_notification_alert() are
 *     CSRF-checked AJAX endpoints expecting a "status" field and
 *     returning plain "1"/"0"; limit_ip_range() is a CSRF-checked,
 *     POST-only, redirect-back action expecting ip_start_rang/
 *     ip_end_rang to add a range, or remove_ips (the row id) to delete
 *     one — POST-only per the PHASE4-01 fix in SECURITY-AUDIT-PHASE-4.md,
 *     which explicitly documents this file previously rendering the
 *     remove action as a GET link; that finding's fix is followed here
 *     (a POST form, never a link, for the remove action).
 *   - Every label string reuses the SURVIVING lang/english.php keys that
 *     were clearly authored for this exact template (disable_reset_password_title/desc,
 *     ip_login_limit*, login_notification*, invalid_ips, invalid_start_ip,
 *     saved, reset_password_disabled, are_you_sure, delete, yes, no) —
 *     no new copy was invented.
 *   - $ip_limit->start_ip / $ip_limit->end_ip / $remote_ip are rendered
 *     with |escape, matching PHASE4-05's defense-in-depth fix, which
 *     named this exact file and these exact values.
 *   - The CSRF field name (security_pack_token) matches
 *     security_pack_csrf_valid() in hooks.php, unmodified.
 *
 * This is injected as a FRAGMENT into an arbitrary theme's own
 * user-security.tpl/clientareasecurity.tpl by core/user_security.php —
 * it cannot assume this module's own admin CSS assets are loaded, so
 * styling here is self-contained (a small inline <style> block, plus
 * plain Bootstrap 3 classes already present in WHMCS's own default
 * client-area themes).
 *}
<div class="sp-native-settings-fragment" style="margin-top:20px;">
    <style>
        .sp-native-settings-fragment .sp-nsf-panel { border: 1px solid #e3e3e3; border-radius: 4px; padding: 15px; margin-bottom: 15px; background: #fff; }
        .sp-native-settings-fragment .sp-nsf-panel h4 { margin-top: 0; }
        .sp-native-settings-fragment .sp-nsf-desc { color: #737373; margin-bottom: 10px; }
        .sp-native-settings-fragment .sp-nsf-alert { padding: 10px 15px; border-radius: 4px; margin-bottom: 15px; }
        .sp-native-settings-fragment .sp-nsf-alert-success { background: #dff0d8; color: #3c763d; border: 1px solid #d6e9c6; }
        .sp-native-settings-fragment .sp-nsf-alert-danger { background: #f2dede; color: #a94442; border: 1px solid #ebccd1; }
        .sp-native-settings-fragment table.sp-nsf-table { width: 100%; margin-bottom: 10px; }
        .sp-native-settings-fragment table.sp-nsf-table th, .sp-native-settings-fragment table.sp-nsf-table td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: left; }
    </style>

    {if $nnm_security_pack_successful}
        <div class="sp-nsf-alert sp-nsf-alert-success">{$nnm_security_pack_successful|escape}</div>
    {/if}
    {if $nnm_security_pack_error}
        <div class="sp-nsf-alert sp-nsf-alert-danger">{$nnm_security_pack_error|escape}</div>
    {/if}

    {if $login_notification_allowed}
    <div class="sp-nsf-panel">
        <h4>{$nnmlang.login_notification}</h4>
        <p class="sp-nsf-desc">{$nnmlang.login_notification_details}</p>
        <div class="btn-group" role="group" data-sp-toggle="login_notification_alert" data-sp-current="{if $login_notification->allowed}1{else}0{/if}">
            <button type="button" class="btn btn-sm {if $login_notification->allowed}btn-primary{else}btn-default{/if}" data-sp-value="1">{$nnmlang.yes}</button>
            <button type="button" class="btn btn-sm {if !$login_notification->allowed}btn-primary{else}btn-default{/if}" data-sp-value="0">{$nnmlang.no}</button>
        </div>
        <span class="sp-nsf-toggle-status text-muted" style="margin-left:10px;"></span>
    </div>
    {/if}

    {if $security_pack_disable_password}
    <div class="sp-nsf-panel">
        <h4>{$nnmlang.disable_reset_password_title}</h4>
        <p class="sp-nsf-desc">{$nnmlang.disable_reset_password_desc}</p>
        <div class="btn-group" role="group" data-sp-toggle="change_reset_password" data-sp-current="{if $disabled_reset_password}1{else}0{/if}">
            <button type="button" class="btn btn-sm {if $disabled_reset_password}btn-primary{else}btn-default{/if}" data-sp-value="1">{$nnmlang.yes}</button>
            <button type="button" class="btn btn-sm {if !$disabled_reset_password}btn-primary{else}btn-default{/if}" data-sp-value="0">{$nnmlang.no}</button>
        </div>
        <span class="sp-nsf-toggle-status text-muted" style="margin-left:10px;"></span>
    </div>
    {/if}

    {if $security_pack_ip_limits}
    <div class="sp-nsf-panel">
        <h4>{$nnmlang.ip_login_limit}</h4>
        <p class="sp-nsf-desc">{$nnmlang.ip_login_limit_desc}</p>
        <p>{$nnmlang.ip_login_limit_current_ip} <strong>{$remote_ip|escape}</strong></p>

        {if $ip_limits|@count}
        <table class="sp-nsf-table">
            <thead>
                <tr>
                    <th>{$nnmlang.ip_login_limit_start_ip}</th>
                    <th>{$nnmlang.ip_login_limit_end_ip}</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                {foreach from=$ip_limits item=ip_limit}
                <tr>
                    <td>{$ip_limit->start_ip|escape}</td>
                    <td>{$ip_limit->end_ip|escape}</td>
                    <td>
                        <form method="post" action="index.php?m=security_pack&page=limit_ip_range" onsubmit="return confirm('{$nnmlang.are_you_sure|escape:'javascript'}');" style="margin:0;">
                            <input type="hidden" name="security_pack_token" value="{$security_pack_csrf}">
                            <input type="hidden" name="remove_ips" value="{$ip_limit->id|intval}">
                            <button type="submit" class="btn btn-xs btn-danger">{$nnmlang.delete}</button>
                        </form>
                    </td>
                </tr>
                {/foreach}
            </tbody>
        </table>
        {/if}

        <form method="post" action="index.php?m=security_pack&page=limit_ip_range" class="form-inline">
            <input type="hidden" name="security_pack_token" value="{$security_pack_csrf}">
            <div class="form-group" style="margin-right:8px;">
                <label style="margin-right:4px;">{$nnmlang.ip_login_limit_start_ip}</label>
                <input type="text" class="form-control input-sm" name="ip_start_rang" placeholder="{$nnmlang.ip_login_limit_start_ip}" required>
            </div>
            <div class="form-group" style="margin-right:8px;">
                <label style="margin-right:4px;">{$nnmlang.ip_login_limit_end_ip}</label>
                <input type="text" class="form-control input-sm" name="ip_end_rang" placeholder="{$nnmlang.ip_login_limit_end_ip}" required>
            </div>
            <button type="submit" class="btn btn-sm btn-primary">{$nnmlang.ip_login_limit_add}</button>
        </form>
    </div>
    {/if}
</div>

{if $login_notification_allowed || $security_pack_disable_password}
<script>
(function () {
    "use strict";
    var toggleGroups = document.querySelectorAll(".sp-native-settings-fragment [data-sp-toggle]");
    for (var i = 0; i < toggleGroups.length; i++) {
        (function (group) {
            var action = group.getAttribute("data-sp-toggle");
            var statusEl = group.parentNode.querySelector(".sp-nsf-toggle-status");
            var buttons = group.querySelectorAll("button[data-sp-value]");
            for (var j = 0; j < buttons.length; j++) {
                buttons[j].addEventListener("click", function (evt) {
                    var btn = evt.currentTarget;
                    var value = btn.getAttribute("data-sp-value");
                    if (group.getAttribute("data-sp-current") === value) {
                        return;
                    }
                    var body = "status=" + encodeURIComponent(value) + "&security_pack_token=" + encodeURIComponent("{$security_pack_csrf}");
                    if (statusEl) { statusEl.textContent = "…"; }
                    fetch("index.php?m=security_pack&page=" + action, {
                        method: "POST",
                        credentials: "same-origin",
                        headers: { "Content-Type": "application/x-www-form-urlencoded" },
                        body: body
                    }).then(function (resp) { return resp.text(); }).then(function (text) {
                        if (text.trim() === "1") {
                            group.setAttribute("data-sp-current", value);
                            for (var k = 0; k < buttons.length; k++) {
                                var isActive = buttons[k].getAttribute("data-sp-value") === value;
                                buttons[k].classList.toggle("btn-primary", isActive);
                                buttons[k].classList.toggle("btn-default", !isActive);
                            }
                            if (statusEl) { statusEl.textContent = ""; }
                        } else if (statusEl) {
                            statusEl.textContent = "Could not save — please refresh and try again.";
                        }
                    }).catch(function () {
                        if (statusEl) { statusEl.textContent = "Could not save — please refresh and try again."; }
                    });
                });
            }
        })(toggleGroups[i]);
    }
})();
</script>
{/if}
