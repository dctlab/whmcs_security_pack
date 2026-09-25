<style>
{literal}
    .sp-csc-card{border:1px solid #e3e3e3;border-radius:4px;padding:16px;margin-bottom:16px;background:#fff;}
    .sp-csc-status{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:600;margin-bottom:4px;}
    .sp-csc-dot{width:12px;height:12px;border-radius:50%;display:inline-block;}
    .sp-csc-dot.strong{background:#41c173;}
    .sp-csc-dot.good{background:#f0ad4e;}
    .sp-csc-dot.weak{background:#d9534f;}
    .sp-csc-dot.unknown{background:#999;}
    .sp-csc-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #f0f0f0;}
    .sp-csc-row:last-child{border-bottom:none;}
    .sp-csc-check{color:#41c173;font-weight:bold;margin-right:6px;}
    .sp-csc-warn{color:#f0ad4e;font-weight:bold;margin-right:6px;}
    .sp-csc-notactive{color:#aaa;font-weight:bold;margin-right:6px;}
    .sp-csc-activity-item{padding:8px 0;border-bottom:1px solid #f0f0f0;font-size:13px;}
    .sp-csc-activity-item:last-child{border-bottom:none;}
    .sp-csc-muted{color:#888;font-size:12px;}
    .sp-csc-h3{font-size:18px;margin:0 0 12px 0;}
    .sp-csc-info{background:#f0f6ff;border:1px solid #d6e6ff;border-radius:4px;padding:8px 12px;font-size:13px;color:#3a5a8c;margin-top:8px;}
{/literal}
</style>

<div class="sp-csc-card">
    {if $strength_label == ($nnmlang.security_center_strength_strong|default:'Strong')}
        {assign var="sp_dot_class" value="strong"}
    {elseif $strength_label == ($nnmlang.security_center_strength_good|default:'Good')}
        {assign var="sp_dot_class" value="good"}
    {elseif $strength_label == ($nnmlang.security_center_strength_weak|default:'Needs Attention')}
        {assign var="sp_dot_class" value="weak"}
    {else}
        {assign var="sp_dot_class" value="unknown"}
    {/if}
    <div class="sp-csc-status"><span class="sp-csc-dot {$sp_dot_class}"></span> {$nnmlang.security_center_your_security|default:'Your Security'}: {$strength_label}</div>
    <p class="sp-csc-muted">{$nnmlang.security_center_status_note|default:'Based on the security features available on your account. This is not the same as your provider\'s internal security configuration.'}</p>
    {if count($strength_recommendations)}
        <div style="margin-top:10px;">
            {foreach from=$strength_recommendations item=rec}
                <div><span class="sp-csc-warn">&#9888;</span> {$rec}</div>
            {/foreach}
        </div>
    {/if}
</div>

<div class="sp-csc-card">
    <h3 class="sp-csc-h3">{$nnmlang.security_center_authentication|default:'Authentication'}</h3>
    {* 2.7.9: every "Manage" button in this box previously linked to a
       guessed, nonexistent path ({$WEB_ROOT}/user-security or
       {$WEB_ROOT}/security) — neither is a real WHMCS client-area URL,
       so every button 404'd. Fixed to the confirmed-valid classic
       (non-friendly) URL {$WEB_ROOT}/clientarea.php?action=security,
       which WHMCS documents as the client-area URL for its native
       Security Settings page (Password Reset / Login Notification /
       Session sign-in history all live on this ONE page) and which
       always works regardless of whether Friendly URLs are enabled —
       unlike the Smarty routePath() function, which has a documented
       "unknown function" failure mode in some rendering contexts, this
       plain query-string URL has no such risk.

       3.1.3 CORRECTION: user-supplied screenshots (direct evidence,
       same trust level as 2.7.8's confirmed getChild("Account")
       reference) proved {$WEB_ROOT}/clientarea.php?action=security
       does NOT render a Two-Factor Authentication section at all on
       this WHMCS version — it shows only Login Notification / Disable
       Forgot Password Reset / a Sessions list. The screen that
       actually hosts WHMCS's native "Two-Factor Authentication" tab
       (where a client picks/manages Email, DCTLAB WhatsApp, or
       Time-Based Token — the SAME native UI the 3.0.0 design
       deliberately chose not to duplicate) is the FRIENDLY URL
       {$WEB_ROOT}/user/security ("Security Settings", tabbed
       "Linked Accounts" / "Two-Factor Authentication"), confirmed
       working by the same screenshots. Every row below whose feature
       lives on THAT tab (WHMCS's own native 2FA row, and the three
       Security Pack method rows) now links there instead. Login
       Notification / Password Reset / Session IP Security Limits are
       UNCHANGED — action=security is still their correct, confirmed
       destination. No provider-specific deep-link/anchor into
       /user/security's Two-Factor Authentication tab was found or
       confirmed anywhere (WHMCS ships no documented query
       parameter/hash for it) — per the "do not fabricate a URL" rule,
       all three methods and WHMCS's own 2FA row share this ONE
       destination rather than guessing three different ones; this
       matches WHMCS's own native UI, which already lets a client pick
       among installed methods from that single screen. This is pure
       navigation — the link never activates/deactivates/switches a
       method, never appears with a query string, and carries no
       user/client identifier (the destination resolves the
       authenticated session itself, exactly like WHMCS's own
       clientarea.php?action=security link already did). *}
    {if $login_notification_allowed}
        <div class="sp-csc-row">
            <span>{if $login_notification_on}<span class="sp-csc-check">&#10003;</span>{else}<span class="sp-csc-warn">&#9888;</span>{/if} {$nnmlang.login_notification|default:'Login Notifications'}</span>
            <a href="{$WEB_ROOT}/clientarea.php?action=security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $two_factor_status !== null}
        <div class="sp-csc-row">
            <span>{if $two_factor_status}<span class="sp-csc-check">&#10003;</span>{else}<span class="sp-csc-warn">&#9888;</span>{/if} {$nnmlang.security_center_2fa|default:'Two-Factor Authentication'}</span>
            <a href="{$WEB_ROOT}/user/security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $email2fa_available || $whatsapp2fa_available || $totp2fa_available}
        {* Post-3.1.0 mutual-exclusion fix: Email/DCTLAB WhatsApp/Time-Based
           Token are three separate native WHMCS Two-Factor Authentication
           methods (Setup > Security > Two-Factor Authentication), but only
           ONE may be the active primary method at a time — enforced
           server-side (TwoFactorAuthenticationService::activateExclusive()/
           enforceSingleActiveMethod()), not just in this display. This
           panel remains status display only, never a separate control
           surface — every row still manages from the SAME native screen. *}
        <p class="sp-csc-muted">{$nnmlang.security_center_2fa_intro|default:'Two-factor authentication adds an extra layer of security to your account.'} <strong>{$nnmlang.security_center_2fa_exclusive|default:'Only one method can be active at a time.'}</strong></p>
    {/if}
    {if $email2fa_available}
        {* Architecture correction (2.6.1): Email 2FA is now a native WHMCS
           Two-Factor Authentication method (Setup > Security > Two-Factor
           Authentication), so it is enabled/disabled from the SAME native
           "Manage" screen as WHMCS's own 2FA row above — this panel is
           status display only, never a separate control surface. *}
        <div class="sp-csc-row">
            <span>
                {if $email2fa_status == 'active'}<span class="sp-csc-check">&#10003;</span> {$nnmlang.email2fa_enabled|default:'Email Two-Factor Authentication'} ({$email2fa_masked_email})
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_active|default:'Active'}</span>
                    {if $email2fa_bypass_active}<br><span class="sp-csc-muted">{$nnmlang.email2fa_trusted_ip|default:'Trusted sign-in on this device until'} {$email2fa_bypass_expires}</span>{/if}
                {elseif $email2fa_status == 'pending'}<span class="sp-csc-warn">&#9888;</span> {$nnmlang.email2fa_pending|default:'Email Two-Factor Authentication — verification not yet completed'}
                {else}<span class="sp-csc-notactive">&#9675;</span> {$nnmlang.email2fa_disabled|default:'Email Two-Factor Authentication'}
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_not_active|default:'Not active'}</span>
                {/if}
            </span>
            <a href="{$WEB_ROOT}/user/security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $whatsapp2fa_available}
        <div class="sp-csc-row">
            <span>
                {if $whatsapp2fa_status == 'active'}<span class="sp-csc-check">&#10003;</span> {$nnmlang.whatsapp2fa_enabled|default:'DCTLAB WhatsApp Two-Factor Authentication'}
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_active|default:'Active'}</span>
                {elseif $whatsapp2fa_status == 'pending'}<span class="sp-csc-warn">&#9888;</span> {$nnmlang.whatsapp2fa_pending|default:'WhatsApp Two-Factor Authentication — verification not yet completed'}
                {else}<span class="sp-csc-notactive">&#9675;</span> {$nnmlang.whatsapp2fa_disabled|default:'DCTLAB WhatsApp Two-Factor Authentication'}
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_not_active|default:'Not active'}</span>
                {/if}
            </span>
            <a href="{$WEB_ROOT}/user/security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $totp2fa_available}
        <div class="sp-csc-row">
            <span>
                {if $totp2fa_status == 'active'}<span class="sp-csc-check">&#10003;</span> {$nnmlang.totp2fa_enabled|default:'Time-Based Token Two-Factor Authentication'}
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_active|default:'Active'}</span>
                {elseif $totp2fa_status == 'pending'}<span class="sp-csc-warn">&#9888;</span> {$nnmlang.totp2fa_pending|default:'Time-Based Token Two-Factor Authentication — verification not yet completed'}
                {else}<span class="sp-csc-notactive">&#9675;</span> {$nnmlang.totp2fa_disabled|default:'Time-Based Token Two-Factor Authentication'}
                    <br><span class="sp-csc-muted">{$nnmlang.security_center_not_active|default:'Not active'}</span>
                {/if}
            </span>
            <a href="{$WEB_ROOT}/user/security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $email2fa_available || $whatsapp2fa_available || $totp2fa_available}
        <div class="sp-csc-info">&#8505; {$nnmlang.security_center_2fa_exclusive_note|default:'Only one two-factor authentication method can be active at a time. Activate a different method to switch — your previous enrollment is kept, not deleted.'}</div>
    {/if}
    {if $recovery_codes_remaining > 0}
        <div class="sp-csc-row">
            <span><span class="sp-csc-check">&#10003;</span> {$nnmlang.recovery_codes_remaining|default:'2FA Recovery Codes remaining'}: {$recovery_codes_remaining}</span>
        </div>
    {/if}
    {if $password_reset_protection_available}
        <div class="sp-csc-row">
            <span>{if $password_reset_disabled}<span class="sp-csc-check">&#10003;</span> {$nnmlang.disable_reset_password_title|default:'Password Reset Disabled'}{else}{$nnmlang.security_center_password_reset_enabled|default:'Password reset is available (you can disable it in Security Settings)'}{/if}</span>
            <a href="{$WEB_ROOT}/clientarea.php?action=security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if $ip_limits_available}
        <div class="sp-csc-row">
            <span><span class="sp-csc-check">&#10003;</span> {$nnmlang.ip_login_limit|default:'Session IP Security Limits'} {if $ip_limit_count > 0}({$ip_limit_count}){/if}</span>
            <a href="{$WEB_ROOT}/clientarea.php?action=security" class="btn btn-default btn-sm">{$nnmlang.security_center_manage|default:'Manage'}</a>
        </div>
    {/if}
    {if !$login_notification_allowed && $two_factor_status === null && !$email2fa_available && !$password_reset_protection_available && !$ip_limits_available}
        <p class="sp-csc-muted">{$nnmlang.security_center_no_features|default:'No optional account security features are currently enabled by your provider.'}</p>
    {/if}
</div>

<div class="sp-csc-card">
    <h3 class="sp-csc-h3">{$nnmlang.security_center_current_session|default:'Current Session'}</h3>
    <div class="sp-csc-row">
        <span>{$current_session.browser} &middot; {$current_session.os}</span>
        <span class="label label-success">{$nnmlang.security_center_current|default:'Current'}</span>
    </div>
    <p class="sp-csc-muted">{$current_session.ip}{if $current_session.country} &middot; {$current_session.country}{/if}</p>
    <p class="sp-csc-muted">{$nnmlang.security_center_sessions_note|default:'For security reasons, a full list of other active sessions and the ability to remotely sign them out is not available at this time — only your current session\'s information is shown. If you believe your account has been accessed without your permission, change your password immediately and contact support.'}</p>
</div>

{if isset($trusted_browsers)}
    <div class="sp-csc-card">
        <h3 class="sp-csc-h3">{$nnmlang.security_center_trusted_browsers|default:'Trusted Browsers'}</h3>
        <p class="sp-csc-muted">{$nnmlang.security_center_trusted_browsers_note|default:'Browsers you chose to remember after verifying with a two-factor code skip that verification for 30 days. Revoke any you don\'t recognize.'}</p>
        {if count($trusted_browsers)}
            {foreach from=$trusted_browsers item=tb}
                <div class="sp-csc-row">
                    <span>
                        {$tb.device_label|default:'Unknown device'|truncate:60}{if $tb.is_this_browser} <span class="label label-success">{$nnmlang.security_center_current|default:'Current'}</span>{/if}<br>
                        <span class="sp-csc-muted">{$nnmlang.security_center_trusted_since|default:'Trusted since'} {$tb.created_at} &middot; {$nnmlang.security_center_trusted_expires|default:'expires'} {$tb.expires_at}{if $tb.last_used_at} &middot; {$nnmlang.security_center_trusted_last_used|default:'last used'} {$tb.last_used_at}{/if}</span>
                    </span>
                    <form action="index.php?m=security_pack&page=revoke_trusted_browser" method="post" style="margin:0;">
                        <input type="hidden" name="security_pack_token" value="{$security_pack_csrf}">
                        <input type="hidden" name="id" value="{$tb.id}">
                        <button type="submit" class="btn btn-default btn-sm">{$nnmlang.security_center_revoke|default:'Revoke'}</button>
                    </form>
                </div>
            {/foreach}
            <form action="index.php?m=security_pack&page=revoke_trusted_browser" method="post" style="margin-top:10px;">
                <input type="hidden" name="security_pack_token" value="{$security_pack_csrf}">
                <input type="hidden" name="revoke_all" value="1">
                <button type="submit" class="btn btn-default btn-sm">{$nnmlang.security_center_revoke_all|default:'Revoke All'}</button>
            </form>
        {else}
            <p class="sp-csc-muted">{$nnmlang.security_center_no_trusted_browsers|default:'No trusted browsers on this account.'}</p>
        {/if}
    </div>
{/if}

{if $recent_activity_available}
    <div class="sp-csc-card">
        <h3 class="sp-csc-h3">{$nnmlang.security_center_recent_activity|default:'Recent Activity'}</h3>
        {if count($recent_activity)}
            {foreach from=$recent_activity item=item}
                <div class="sp-csc-activity-item">
                    <strong>{$item.browser} &middot; {$item.os}</strong><br>
                    <span class="sp-csc-muted">{$item.ip_address} &middot; {$item.date_time}</span>
                </div>
            {/foreach}
            <p style="margin-top:10px;"><a href="index.php?m=security_pack&page=login_history">{$nnmlang.security_center_view_all_activity|default:'View full login history'} &raquo;</a></p>
        {else}
            <p class="sp-csc-muted">{$nnmlang.security_center_no_activity|default:'No recent activity recorded yet.'}</p>
        {/if}
    </div>
{/if}
