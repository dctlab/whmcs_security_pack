<?php
/**
 * Phase 3.6A — Country Restriction page (formerly
 * CountryRestrictionController::render()/renderStatus()/renderTestLookup()/
 * renderRules()/renderRecentActivity(), which echoed this markup
 * directly).
 *
 * This page only ever supported ONE mode concept — "Mode" is a two-value
 * radio (block selected countries / allow only selected countries), not a
 * separate on/off "allow mode" toggle — and only ONE form (Rules: Mode +
 * Countries + Unknown-country Behavior, POST to a=save). The enable
 * toggle and the GEO Providers/Whitelist IP fields are NOT on this page —
 * they live on the Settings tab (SettingsController's Country Restriction
 * panel) and always have; this page only ever displayed their current
 * value read-only ("Status: Enabled/Disabled ... Disable on the Settings
 * tab »"), matching CountryRestrictionController::render()'s pre-Phase-3.6A
 * behavior exactly. Test Lookup's AJAX handler (a=test_lookup) is
 * intentionally left as a bare-fragment endpoint outside this template
 * (see CountryRestrictionController::testLookup()) — it isn't a full page
 * render, so migrating it here would change what it returns.
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   string $token
 *   bool $enabled
 *   string $mode              "block"|"allow"
 *   string $unknownPolicy     "allow"|"block"
 *   array $providerRows       [{"name","available"}, ...] — from GeoIpManager::diagnostics(), unchanged
 *   bool $anyProviderAvailable
 *   bool $mmdbLoaded
 *   array $countries          [code => name, ...] from WHMCS\Utility\Country::getCountryNameArray(), unchanged ordering
 *   array $selectedCountries  list of currently-selected 2-letter codes
 *   array $recentEvents       raw stdClass rows (created_at, ip, country_code, message) from dctlab_security_pack_events, or [] on query failure — unchanged fail-open behavior
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$token = $token ?? "";
$enabled = !empty($enabled);
$mode = $mode ?? "block";
$unknownPolicy = $unknownPolicy ?? "allow";
$providerRows = $providerRows ?? [];
$anyProviderAvailable = $anyProviderAvailable ?? false;
$mmdbLoaded = $mmdbLoaded ?? false;
$countries = $countries ?? [];
$selectedCountries = $selectedCountries ?? [];
$recentEvents = $recentEvents ?? [];
?>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Country Restriction — Status</h3>
    <table class="table"><tbody>
        <tr>
            <td width="260">Status</td>
            <td>
                <?php echo $enabled ? '<span class="label label-success">Enabled</span>' : '<span class="label label-default">Disabled</span>'; ?>
                <a href="?module=security_pack&amp;c=settings"><?php echo $enabled ? "Disable" : "Enable"; ?> on the Settings tab &raquo;</a>
            </td>
        </tr>
        <tr>
            <td>GeoIP Provider(s)</td>
            <td>
                <?php if(!count($providerRows)): ?>
                    <span class="text-muted">none configured</span>
                <?php else: ?>
                    <?php foreach ($providerRows as $i => $row): ?>
                        <?php echo $i > 0 ? "&nbsp; &nbsp;" : ""; ?><?php echo security_pack_e($row["name"]); ?>: <?php echo !empty($row["available"]) ? '<span class="label label-success">available</span>' : '<span class="label label-default">unavailable</span>'; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </td>
        </tr>
        <tr>
            <td>MaxMind Database</td>
            <td>
                <?php echo $mmdbLoaded ? '<span class="label label-success">Available</span>' : '<span class="label label-default">Not uploaded</span>'; ?>
                <a href="?module=security_pack&amp;c=langCurrency">Manage on the GeoIP Language &amp; Currency page &raquo;</a>
            </td>
        </tr>
        <tr>
            <td>Mode</td>
            <td><?php echo $mode === "allow" ? "Allow only selected countries" : "Block selected countries"; ?></td>
        </tr>
        <tr>
            <td>Unknown-country Policy</td>
            <td>
                <?php echo $unknownPolicy === "block" ? "Block" : "Allow"; ?>
                <small class="text-muted">(applied when the GeoIP database/providers cannot determine a visitor's country)</small>
            </td>
        </tr>
    </tbody></table>
    <?php if($enabled && !$anyProviderAvailable): ?>
        <div class="alert alert-warning">No GeoIP provider is currently available (no MaxMind database uploaded and no curl provider configured) — Country Restriction cannot determine any visitor's country right now, so the configured Unknown-country Policy (<strong><?php echo $unknownPolicy === "block" ? "Block" : "Allow"; ?></strong>) applies to every visitor.</div>
    <?php endif; ?>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Test Lookup</h3>
    <div class="form-inline">
        <input type="text" id="nnm_cr_test_ip" class="form-control" placeholder="e.g. 8.8.8.8">
        <button type="button" id="nnm_cr_test_btn" class="btn btn-default">Test</button>
    </div>
    <div id="nnm_cr_test_result" style="margin-top:10px;"></div>
</div>
<script>
jQuery(function ($) {
    $('#nnm_cr_test_btn').on('click', function () {
        var ip = $('#nnm_cr_test_ip').val();
        $('#nnm_cr_test_result').text('Looking up...');
        $.get('addonmodules.php', {module: 'security_pack', c: 'countryRestriction', a: 'test_lookup', ip: ip, token: '<?php echo security_pack_e($token); ?>'}, function (resp) {
            $('#nnm_cr_test_result').html(resp);
        });
    });
});
</script>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Rules</h3>
    <form method="post" action="?module=security_pack&amp;c=countryRestriction&amp;a=save">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">

        <div class="form-group">
            <label>Mode</label><br>
            <label class="radio-inline"><input type="radio" name="mode" value="block" <?php echo $mode === "block" ? "checked" : ""; ?>> Block selected countries</label>
            <label class="radio-inline"><input type="radio" name="mode" value="allow" <?php echo $mode === "allow" ? "checked" : ""; ?>> Allow only selected countries</label>
        </div>

        <div class="form-group">
            <label>Countries</label><br>
            <select name="countries[]" class="form-control selectize-multi-select countrypicker" multiple="multiple" style="max-width:600px;">
                <?php foreach ($countries as $code => $name): ?>
                    <option value="<?php echo security_pack_e($code); ?>" <?php echo in_array($code, $selectedCountries, true) ? 'selected="selected"' : ""; ?>><?php echo security_pack_e($name); ?> (<?php echo security_pack_e($code); ?>)</option>
                <?php endforeach; ?>
            </select>
            <p class="text-muted small">Leave empty to disable enforcement without turning the feature off (a safe no-op in either mode).</p>
        </div>

        <div class="form-group">
            <label>Unknown-country Behavior</label><br>
            <label class="radio-inline"><input type="radio" name="unknown_policy" value="allow" <?php echo $unknownPolicy === "allow" ? "checked" : ""; ?>> Allow <span class="label label-default">Recommended</span></label>
            <label class="radio-inline"><input type="radio" name="unknown_policy" value="block" <?php echo $unknownPolicy === "block" ? "checked" : ""; ?>> Block</label>
            <p class="text-muted small">Applied when GeoIP cannot determine a visitor's country (database unavailable, provider failure/timeout). Allow (fail open) is recommended so a GeoIP outage never locks out every visitor — choose Block only if your security policy explicitly requires fail-closed country enforcement.</p>
        </div>

        <button type="submit" class="btn btn-primary">Save Changes</button>
    </form>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Recently Blocked</h3>
    <?php if(!count($recentEvents)): ?>
        <p class="text-muted">No visitors have been blocked by Country Restriction yet.</p>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-condensed">
                <thead><tr><th>Time</th><th>IP</th><th>Country</th><th>Message</th></tr></thead>
                <tbody>
                <?php foreach ($recentEvents as $event): ?>
                    <tr>
                        <td><?php echo security_pack_e($event->created_at); ?></td>
                        <td style="word-break:break-all;"><?php echo security_pack_e($event->ip); ?></td>
                        <td><?php echo security_pack_e($event->country_code ?: "unknown"); ?></td>
                        <td style="word-wrap:break-word;overflow-wrap:break-word;"><?php echo security_pack_e($event->message); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
    <p class="text-muted small">Full history: <a href="?module=security_pack&amp;c=activity&amp;type=country_restriction.blocked">Security Activity &raquo;</a></p>
</div>
