{*
 * DCTLAB Security Pack — Client Area "Login History" page.
 *
 * RECONSTRUCTED 2026-08-27: this file was found MISSING entirely on a
 * live production install — reported as
 * "index.php?m=security_pack&page=login_history not working". The code
 * that builds and returns it (ClientController::login_history(),
 * lib/Client/ClientController.php, unmodified) was still fully present
 * and working, and its own docblock/TemplateRenderer.php's header
 * comment both already documented this exact file
 * ("templates/logs.tpl") as an expected client-area Smarty template —
 * it just didn't exist on disk, so WHMCS had nothing to render for this
 * page (the classic "Smarty template not found" failure — the same
 * failure mode templates/settings.tpl's own RECONSTRUCTED docblock
 * describes hitting previously). Rebuilt here from that surviving
 * evidence, not guessed from scratch:
 *
 *   - The exact variable names/shapes are dictated by
 *     ClientController::login_history()'s own return array:
 *       "vars" => ["logs" => $logs, "nnmlang" => $lang]
 *     where each $logs row is exactly
 *       ["ip_address" => ..., "os" => ..., "browser" => ..., "date_time" => ...]
 *     (see that method — nothing here invents a field it doesn't
 *     already provide).
 *   - Every label string reuses the SURVIVING lang/english.php keys that
 *     were clearly authored for this exact page (login_history,
 *     ip_address, os, browser, date_time) — no new copy was invented for
 *     those; an empty-state message and column-independent strings use
 *     Smarty's |default fallback the same way templates/security_center.tpl
 *     already does for its own not-yet-defined lang keys, so a future
 *     translation can override them without a code change.
 *   - This is a full client-area PAGE (pagetitle/breadcrumb/requirelogin
 *     are already set by the controller; WHMCS's own theme renders the
 *     surrounding header/nav/footer/breadcrumb automatically), not a
 *     fragment spliced into another page — same pattern as
 *     templates/security_center.tpl, not templates/settings.tpl.
 *   - All log values are rendered with |escape — this table displays a
 *     client's own browser User-Agent string and IP, both attacker-
 *     influenced input, so they're never trusted as safe HTML.
 *}
<style>
{literal}
    .sp-lh-card{border:1px solid #e3e3e3;border-radius:4px;padding:16px;margin-bottom:16px;background:#fff;}
    .sp-lh-table{width:100%;border-collapse:collapse;}
    .sp-lh-table th,.sp-lh-table td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;font-size:13px;}
    .sp-lh-table th{color:#555;font-weight:600;}
    .sp-lh-table tr:last-child td{border-bottom:none;}
    .sp-lh-empty{color:#888;font-size:13px;padding:8px 0;}
{/literal}
</style>

<div class="sp-lh-card">
    {if $logs|@count}
    <div style="overflow-x:auto;">
        <table class="sp-lh-table">
            <thead>
                <tr>
                    <th>{$nnmlang.ip_address|default:'IP Address'}</th>
                    <th>{$nnmlang.os|default:'OS'}</th>
                    <th>{$nnmlang.browser|default:'Browser'}</th>
                    <th>{$nnmlang.date_time|default:'Date Time'}</th>
                </tr>
            </thead>
            <tbody>
                {foreach from=$logs item=log}
                <tr>
                    <td>{$log.ip_address|escape}</td>
                    <td>{$log.os|escape}</td>
                    <td>{$log.browser|escape}</td>
                    <td>{$log.date_time|escape}</td>
                </tr>
                {/foreach}
            </tbody>
        </table>
    </div>
    {else}
    <p class="sp-lh-empty">{$nnmlang.login_history_empty|default:'No login history recorded yet.'}</p>
    {/if}
</div>
