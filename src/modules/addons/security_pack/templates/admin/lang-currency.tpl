<?php
/**
 * Phase 3.6C — GeoIP Language & Currency page (formerly
 * LangCurrencyController::render()/renderDatabaseStatus()/
 * renderTestLookup()/renderDefaultFallback()/renderCountryRules()/
 * renderAdvancedSettings(), which echoed this markup directly).
 *
 * The MaxMind .mmdb upload form keeps its exact original contract
 * (method="post" enctype="multipart/form-data", field name "mmdb_file",
 * required, accept=".mmdb") — file uploads are never touched beyond
 * presentation, per the standing "preserve exact form contract" rule.
 *
 * Expected variables:
 *   bool $showSavedBanner   isset($_REQUEST["saved"]) — a generic query-string banner, not a session message
 *   string|null $errorMessage
 *   string|null $successMessage
 *   string $token
 *   array $dbStatus   ["loaded"=>false] or ["loaded"=>true,"type","nodeCount","built","path","cachedLookups"]
 *   array $languages  list of language strings (WHMCS\Language\ClientLanguage::getLanguages(), or ["english"] fallback)
 *   array $currencies list of currency code strings (tblcurrencies, unchanged ordering)
 *   array $countries  [code => name, ...] from WHMCS\Utility\Country
 *   string $fallbackLanguage
 *   string $fallbackCurrency
 *   array $overrides  [{"id","countryCode","name","language","currency","enabled"}, ...]
 *   array $advanced   ["ipSource","seoBotBypass","applyLoggedIn","debug"]
 */
$showSavedBanner = $showSavedBanner ?? false;
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$token = $token ?? "";
$dbStatus = $dbStatus ?? ["loaded" => false];
$languages = $languages ?? ["english"];
$currencies = $currencies ?? [];
$countries = $countries ?? [];
$fallbackLanguage = $fallbackLanguage ?? "";
$fallbackCurrency = $fallbackCurrency ?? "";
$overrides = $overrides ?? [];
$advanced = $advanced ?? ["ipSource" => "auto", "seoBotBypass" => true, "applyLoggedIn" => false, "debug" => false];
$ipOptions = ["auto" => "Auto-detect", "cloudflare" => "Cloudflare (CF-Connecting-IP)", "xff" => "X-Forwarded-For", "xrealip" => "X-Real-IP", "remoteaddr" => "REMOTE_ADDR only"];
?>

<?php if($showSavedBanner): ?>
<div class="alert alert-success">Saved successfully.</div>
<?php endif; ?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">GeoIP Database Status</h3>
    <?php if(!empty($dbStatus["loaded"])): ?>
        <span class="label label-success">Loaded</span>
        Type: <strong><?php echo security_pack_e($dbStatus["type"]); ?></strong> &nbsp;
        Nodes: <?php echo security_pack_e($dbStatus["nodeCount"]); ?> &nbsp;
        Built: <?php echo security_pack_e($dbStatus["built"]); ?><br><br>
        <small class="text-muted">Path: <?php echo security_pack_e($dbStatus["path"]); ?> &nbsp;|&nbsp; Cached lookups: <?php echo security_pack_e($dbStatus["cachedLookups"]); ?></small>
    <?php else: ?>
        <span class="label label-default">Not loaded</span> No GeoLite2-Country.mmdb uploaded yet — falling back to the free curl-based GEO providers configured under the main Settings tab.
    <?php endif; ?>
    <br><br>
    <form method="post" enctype="multipart/form-data" action="?module=security_pack&amp;c=langCurrency&amp;a=upload_mmdb" class="form-inline">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <input type="file" name="mmdb_file" accept=".mmdb" class="form-control" required>
        <button type="submit" class="btn btn-primary">Upload / Replace Database</button>
    </form>
    <br>
    <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=clear_cache" style="display:inline;" onsubmit="return confirm('Clear all cached GeoIP lookups?')">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <button type="submit" class="btn btn-default">Clear Lookup Cache</button>
    </form>
    <p class="text-muted small" style="margin-top:10px;">Get a free GeoLite2-Country.mmdb from MaxMind (sign up for a free license key at <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener">maxmind.com/en/geolite2/signup</a>), then upload it here. See README.md for a cron command to keep it updated automatically.</p>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Test a Lookup</h3>
    <div class="form-inline">
        <input type="text" id="nnm_lc_test_ip" class="form-control" placeholder="e.g. 81.2.69.142">
        <button type="button" id="nnm_lc_test_btn" class="btn btn-default">Test</button>
    </div>
    <div id="nnm_lc_test_result" style="margin-top:10px;"></div>
</div>
<script>
jQuery(function ($) {
    $('#nnm_lc_test_btn').on('click', function () {
        var ip = $('#nnm_lc_test_ip').val();
        $('#nnm_lc_test_result').text('Looking up...');
        $.get('addonmodules.php', {module: 'security_pack', c: 'langCurrency', a: 'test_lookup', ip: ip, token: '<?php echo security_pack_e($token); ?>'}, function (resp) {
            $('#nnm_lc_test_result').html(resp);
        });
    });
});
</script>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Default Fallback (all other countries)</h3>
    <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=save_defaults" class="form-inline">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <div style="display:inline-block;margin-right:15px;">
            <label>Language</label><br>
            <select name="fallback_language" class="form-control">
                <?php foreach ($languages as $lang): ?>
                    <option value="<?php echo security_pack_e($lang); ?>" <?php echo $fallbackLanguage === $lang ? "selected" : ""; ?>><?php echo security_pack_e(ucfirst($lang)); ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="display:inline-block;margin-right:15px;">
            <label>Currency</label><br>
            <select name="fallback_currency" class="form-control">
                <?php foreach ($currencies as $code): ?>
                    <option value="<?php echo security_pack_e($code); ?>" <?php echo $fallbackCurrency === $code ? "selected" : ""; ?>><?php echo security_pack_e($code); ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <button type="submit" class="btn btn-primary" style="vertical-align:bottom;">Save Defaults</button>
    </form>
    <p class="text-muted small" style="margin-top:10px;">Applied to visitors whose country doesn't match any rule below.</p>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Country Rules</h3>
    <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=override_save">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <div class="row">
            <div class="col-sm-4">
                <select name="country_code" class="form-control" required>
                    <option value="">Country...</option>
                    <?php foreach ($countries as $code => $name): ?>
                        <option value="<?php echo security_pack_e($code); ?>"><?php echo security_pack_e($name); ?> (<?php echo security_pack_e($code); ?>)</option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-sm-4">
                <select name="language" class="form-control">
                    <option value="">Language...</option>
                    <?php foreach ($languages as $lang): ?>
                        <option value="<?php echo security_pack_e($lang); ?>"><?php echo security_pack_e(ucfirst($lang)); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-sm-4">
                <select name="currency" class="form-control">
                    <option value="">Currency...</option>
                    <?php foreach ($currencies as $code): ?>
                        <option value="<?php echo security_pack_e($code); ?>"><?php echo security_pack_e($code); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
        <br><button type="submit" class="btn btn-primary">Add / Update Rule</button>
    </form>
    <br>
    <div class="table-responsive">
        <table class="table">
            <thead><tr><th>Country</th><th>Language</th><th>Currency</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php if(!count($overrides)): ?>
                <tr><td colspan="5" class="text-center text-muted">No rules yet — the built-in 248-country currency defaults apply.</td></tr>
            <?php else: ?>
                <?php foreach ($overrides as $row): ?>
                    <?php
                    $toggleAction = $row["enabled"] ? "override_disable" : "override_enable";
                    $toggleLabel = $row["enabled"] ? "Disable" : "Enable";
                    ?>
                    <tr>
                        <td><?php echo security_pack_e($row["name"]); ?> (<?php echo security_pack_e($row["countryCode"]); ?>)</td>
                        <td><?php echo security_pack_e($row["language"]); ?></td>
                        <td><?php echo security_pack_e($row["currency"]); ?></td>
                        <td><?php echo $row["enabled"] ? '<span class="label label-success">Active</span>' : '<span class="label label-default">Disabled</span>'; ?></td>
                        <td>
                            <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=<?php echo $toggleAction; ?>" style="display:inline;margin:0;">
                                <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>"><input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                                <button type="submit" class="btn btn-default btn-sm"><?php echo security_pack_e($toggleLabel); ?></button>
                            </form>
                            <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=override_delete" style="display:inline;margin:0;" onsubmit="return confirm('Delete this rule?')">
                                <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>"><input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Advanced Settings</h3>
    <form method="post" action="?module=security_pack&amp;c=langCurrency&amp;a=save_advanced">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">

        <div class="form-group">
            <label>Visitor IP Source</label>
            <select name="ip_source" class="form-control" style="max-width:320px;display:inline-block;">
                <?php foreach ($ipOptions as $value => $label): ?>
                    <option value="<?php echo security_pack_e($value); ?>" <?php echo $advanced["ipSource"] === $value ? "selected" : ""; ?>><?php echo security_pack_e($label); ?></option>
                <?php endforeach; ?>
            </select>
            <p class="text-muted small">auto = try Cloudflare / X-Forwarded-For / X-Real-IP, then fall back to REMOTE_ADDR. Choose a specific header only if you know your server/CDN setup requires it.</p>
        </div>

        <div class="checkbox">
            <label><input type="checkbox" name="seo_bot_bypass" value="1" <?php echo $advanced["seoBotBypass"] ? "checked" : ""; ?>> SEO Bot Bypass</label>
            <p class="text-muted small">Search engine crawlers always see the site default language/currency, preventing duplicate-content issues.</p>
        </div>

        <div class="checkbox">
            <label><input type="checkbox" name="lc_apply_logged_in" value="1" <?php echo $advanced["applyLoggedIn"] ? "checked" : ""; ?>> Apply to Logged-in Clients</label>
            <p class="text-muted small">If off (recommended), detection only runs for guests/new visitors. If on, it also runs for logged-in clients who have not manually switched language/currency.</p>
        </div>

        <div class="checkbox">
            <label><input type="checkbox" name="lc_debug" value="1" <?php echo $advanced["debug"] ? "checked" : ""; ?>> Debug Logging</label>
            <p class="text-muted small">Write GeoIP lookup errors and skip-reasons to the WHMCS Activity Log. Leave off in normal production use.</p>
        </div>

        <button type="submit" class="btn btn-primary">Save Advanced Settings</button>
    </form>
</div>
