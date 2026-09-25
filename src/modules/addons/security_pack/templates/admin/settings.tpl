<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Expected variables (all prepared by SettingsController::index(); this
 * template only renders what it's given):
 *   string|null $errorMessage
 *   string $token
 *   array $loginHistory, $loginNotification, $advancedSecurity, $systemActivityLog, $email2fa, $contentProtection  — ["title","tooltip"?,"panelClass"?,"masterToggle"?,"rows" => [{"type":"toggle"|"number"|"select", ...}]]
 *   array $countryRestriction  ["checked","whitelist"] — no "providerOptions" any more (2026-08-27: GEO Providers field removed, MaxMind-only now)
 *   array $geoLangCurrency     ["langCurrency","lcBanner","geoCacheDays","lcCookieDays"]
 *   array $securityHeaders     ["safeHeaders" => [{"name","label","description","checked"}], "csp","hsts","hstsConfirmHttps" => {"checked"}]
 *
 * ONE form for this entire page (POST ?module=security_pack&c=settings&a=save),
 * matching the original — this page never had separate per-section forms,
 * so nothing was split apart here (Phase 3.5 spec's "multi-form rule").
 * The "Manage Country Restrictions »" / "Manage GeoIP Language & Currency »"
 * links are, and always were, plain navigation to their own dedicated
 * pages/controllers — not additional forms on this page.
 */
$errorMessage = $errorMessage ?? null;
$token = $token ?? "";
$loginHistory = $loginHistory ?? ["title" => "", "rows" => []];
$loginNotification = $loginNotification ?? ["title" => "", "rows" => []];
$advancedSecurity = $advancedSecurity ?? ["title" => "", "rows" => []];
$systemActivityLog = $systemActivityLog ?? ["title" => "", "rows" => []];
$email2fa = $email2fa ?? ["title" => "", "rows" => []];
$contentProtection = $contentProtection ?? ["title" => "", "rows" => []];
$countryRestriction = $countryRestriction ?? ["checked" => false, "whitelist" => ""];
$geoLangCurrency = $geoLangCurrency ?? ["langCurrency" => false, "lcBanner" => false, "geoCacheDays" => "7", "lcCookieDays" => "365"];
$securityHeaders = $securityHeaders ?? ["safeHeaders" => [], "csp" => ["checked" => false], "hsts" => ["checked" => false], "hstsConfirmHttps" => ["checked" => false]];

/**
 * Renders one section's "rows" array (toggle/number/select) into a
 * <table>, the same generic loop used by every simple section on this
 * page — kept as a small local helper (not a component) since it's only
 * ever called from within this one template, composing components that
 * ARE shared (setting-toggle-row/setting-number-row/setting-select-row).
 */
$renderRows = function (array $rows): string {
    $html = '<table class="table" width="100%" border="0" cellspacing="2" cellpadding="3"><tbody>';
    foreach ($rows as $row) {
        $type = $row["type"] ?? "toggle";
        if($type === "toggle") {
            $html .= TemplateRenderer::component("setting-toggle-row", $row);
        } elseif($type === "number") {
            $html .= TemplateRenderer::component("setting-number-row", $row);
        } elseif($type === "select") {
            $html .= TemplateRenderer::component("setting-select-row", $row);
        }
    }
    $html .= "</tbody></table>";
    return $html;
};
?>
<style>
    .nnm_switch { position: relative; display: inline-block; width: 47px; height: 25px; margin-bottom: 0px; }
    .nnm_switch input { opacity: 0; width: 0; height: 0; }
    .nnm_slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; -webkit-transition: .4s; transition: .4s; }
    .nnm_slider:before { position: absolute; content: ""; height: 19px; width: 20px; left: 4px; bottom: 3px; background-color: white; -webkit-transition: .4s; transition: .4s; }
    input:checked + .nnm_slider { background-color: #41c173; }
    input:focus + .nnm_slider { box-shadow: 0 0 1px #2196F3; }
    input:checked + .nnm_slider:before { -webkit-transform: translateX(19px); -ms-transform: translateX(19px); transform: translateX(19px); }
    .nnm_slider.round { border-radius: 34px; }
    .nnm_slider.round:before { border-radius: 50%; }
    .nnm_config_panel.disabled { position: relative; }
    .nnm_config_panel.disabled::after { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(0, 0, 0, 0.4); pointer-events: none; display: block; z-index: 10000; }
    .nnm_config_panel { padding: 0px; }
    table.form { margin: 0px; border: none; padding-top: 8px; border-spacing: 5px; }
    .table .fieldlabel { padding-top: 13px; }
    .form-control.selectize-control, .selectize-control .selectize-input, .selectize-control.multi .selectize-input.has-items { height: auto; }
    .sp-settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 16px; }
</style>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>

<form action="?module=security_pack&amp;c=settings&amp;a=save" method="post">

    <div class="sp-settings-grid">
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $loginHistory["title"], "tooltip" => $loginHistory["tooltip"] ?? "",
            "masterToggle" => $loginHistory["masterToggle"] ?? null, "panelClass" => $loginHistory["panelClass"] ?? "",
            "content" => $renderRows($loginHistory["rows"]),
        ]); ?>
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $loginNotification["title"], "tooltip" => $loginNotification["tooltip"] ?? "",
            "content" => $renderRows($loginNotification["rows"]),
        ]); ?>
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $advancedSecurity["title"],
            "content" => $renderRows($advancedSecurity["rows"]),
        ]); ?>
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $systemActivityLog["title"], "tooltip" => $systemActivityLog["tooltip"] ?? "",
            "content" => $renderRows($systemActivityLog["rows"]),
        ]); ?>
    </div>

    <div class="sp-settings-grid">
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $email2fa["title"], "tooltip" => $email2fa["tooltip"] ?? "",
            "content" => $renderRows($email2fa["rows"]),
        ]); ?>
        <?php echo TemplateRenderer::component("setting-panel", [
            "title" => $contentProtection["title"],
            "content" => $renderRows($contentProtection["rows"]),
        ]); ?>
        <?php
        // Country Restriction: the enable toggle, Whitelist IP textarea,
        // then a separate link-out panel to the dedicated Mode/
        // country-list/unknown-policy page (Security Pack 2.8).
        //
        // 2026-08-27: the GEO Providers multi-select (freeipapi.com/
        // geojs.io/ipapi.co) that used to sit here is gone — Country
        // Restriction now resolves exclusively against the MaxMind
        // database uploaded on the GeoIP Language & Currency page (see
        // GeoIpManager's docblock). A short note links there instead.
        $crRows = $renderRows([
            ["type" => "toggle", "name" => "country_restriction", "label" => "Country Restriction", "tooltip" => "Enable country restriction feature.", "checked" => $countryRestriction["checked"], "extraClass" => "country_restriction_changes"],
        ]);
        $crRows .= '<table class="table" width="100%" border="0" cellspacing="2" cellpadding="3"><tbody>';
        $crRows .= '<tr><td class="fieldlabel" width="300">Whitelist IP <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="One IP per line"></i></td><td class="fieldarea"><textarea name="settings[whitelist]" class="form-control" rows="2">' . security_pack_e($countryRestriction["whitelist"]) . '</textarea></td></tr>';
        $crRows .= '</tbody></table>';
        $crRows .= '<p class="sp-footer-links" style="margin-top:8px;">Country lookups use the MaxMind database uploaded on the GeoIP Language &amp; Currency page below.</p>';
        $crRows .= '<div style="padding:12px 0 0;"><p class="sp-footer-links">Mode, the country list, and the unknown-country policy are managed on a dedicated page.</p><a class="btn btn-default btn-sm" href="?module=security_pack&amp;c=countryRestriction">Manage Country Restrictions &raquo;</a></div>';
        echo TemplateRenderer::component("setting-panel", ["title" => "Country Restriction", "content" => $crRows]);
        ?>
    </div>

    <div class="sp-settings-grid" style="grid-template-columns:2fr 1fr;">
        <?php
        $glcRows = $renderRows([
            ["type" => "toggle", "name" => "lang_currency", "label" => "Enable", "checked" => $geoLangCurrency["langCurrency"]],
            ["type" => "toggle", "name" => "lc_banner", "label" => "Show notice banner", "checked" => $geoLangCurrency["lcBanner"]],
            ["type" => "number", "name" => "geo_cache_days", "label" => "Cache lookups for (days)", "tooltip" => "How long a resolved IP-to-country result (MaxMind or curl provider) is cached before being looked up again.", "value" => $geoLangCurrency["geoCacheDays"], "min" => 1, "max" => 365],
            ["type" => "number", "name" => "lc_cookie_days", "label" => "Remember visitor's manual choice for (days)", "value" => $geoLangCurrency["lcCookieDays"], "min" => 1, "max" => 3650],
        ]);
        echo TemplateRenderer::component("setting-panel", ["title" => "GeoIP Language &amp; Currency", "tooltip" => "Auto-detect visitor country and switch client area language/currency to match.", "content" => $glcRows]);
        ?>
        <div class="sp-card">
            <p>The GeoIP database (MaxMind upload), test-a-lookup tool, default fallback language/currency, and per-country rules are all managed on a dedicated page.</p>
            <a class="btn btn-default" href="?module=security_pack&amp;c=langCurrency">Manage GeoIP Language &amp; Currency &raquo;</a>
        </div>
    </div>

    <div class="sp-card" style="margin-bottom:16px;">
        <h3 class="sp-card-title">Security Headers <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="HTTP response headers that provide defense-in-depth against certain browser-side attacks. See Security Diagnostics for current status."></i></h3>
        <table class="table" width="100%"><tbody>
        <?php foreach ($securityHeaders["safeHeaders"] as $header): ?>
            <?php echo TemplateRenderer::component("setting-toggle-row", ["name" => $header["name"], "label" => $header["label"], "description" => $header["description"], "checked" => $header["checked"]]); ?>
        <?php endforeach; ?>
        <?php echo TemplateRenderer::component("setting-toggle-row", [
            "name" => "sh_csp", "label" => "Content-Security-Policy",
            "badge" => ["label" => "Advanced", "class" => "label-default"],
            "description" => "OFF by default — an incorrectly scoped CSP can silently break payment gateway iframes, JavaScript widgets, or this module's own AJAX calls. Only enable if you've reviewed what your site actually loads.",
            "checked" => $securityHeaders["csp"]["checked"],
        ]); ?>
        <?php echo TemplateRenderer::component("setting-toggle-row", [
            "name" => "sh_hsts", "label" => "Strict-Transport-Security (HSTS)",
            "badge" => ["label" => "Caution", "class" => "label-danger"],
            "description" => "OFF by default. Only enable if EVERY page of this site (admin, client area, and every subdomain you might use) is already served exclusively over HTTPS — HSTS instructs browsers to refuse plain HTTP entirely for a period of time, which will break the site for visitors if that's not actually true yet.",
            "checked" => $securityHeaders["hsts"]["checked"],
        ]); ?>
        <?php echo TemplateRenderer::component("setting-toggle-row", [
            "name" => "sh_hsts_confirm_https", "label" => "I confirm this entire site is served over HTTPS only",
            "indent" => true, "checked" => $securityHeaders["hstsConfirmHttps"]["checked"],
        ]); ?>
        </tbody></table>
    </div>

    <input type="hidden" name="save" value="1">
    <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
    <div class="btn-container" style="display:flex;gap:8px;flex-wrap:wrap;">
        <input id="save_change_texts" type="submit" value="Save Changes" class="btn btn-primary">
    </div>
</form>
<div class="alert alert-warning" style="margin-top:16px;"><i class="far fa-question-circle"></i> <small>Note: Some features in the client area, such as client login notifications or the option to disable free emails, will be skipped if you are logged in as an admin in the browser.</small></div>
<script>
    $(document).ready(function () {
        $('.nnm_show_hide_panel').change(function () {
            if (this.checked) {
                $('.' + $(this).data('panel')).removeClass('disabled');
            } else {
                $('.' + $(this).data('panel')).addClass('disabled');
            }
        });
    });
</script>
