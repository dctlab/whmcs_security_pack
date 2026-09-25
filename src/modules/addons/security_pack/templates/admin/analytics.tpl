<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Expected variables (all prepared by AnalyticsController::index() — the
 * date-range resolution, every aggregate SQL query, and the trend
 * series/max calculation are all still in the controller, byte-for-byte
 * unchanged from the pre-Phase-3 version; this template only formats
 * what it's given):
 *   array $rangeLinks   [["key","label","active","href"], ...] — same 4 ranges (today/7d/30d/90d) as before
 *   array $metrics      [["label","value"], ...] — same metric set/order/values as the original renderMetrics()
 *   array $trend        ["series" => [date => count, ...], "max" => int, "rangeStart" => string, "rangeEnd" => string]
 *   array $topSources   ["ips" => [...], "countries" => [...], "eventTypes" => [...], "cspSources" => [...]] — same 4 topBy()/CSP queries as before, each already LIMIT 10
 */
$rangeLinks = $rangeLinks ?? [];
$metrics = $metrics ?? [];
$trend = $trend ?? ["series" => [], "max" => 1, "rangeStart" => "", "rangeEnd" => ""];
$topSources = $topSources ?? ["ips" => [], "countries" => [], "eventTypes" => [], "cspSources" => []];
?>
<div class="sp-card" style="margin-bottom:16px;">
    <div class="btn-group" role="group">
        <?php foreach ($rangeLinks as $link): ?>
            <a class="btn btn-sm <?php echo $link["active"] ? "btn-primary" : "btn-default"; ?>" href="<?php echo security_pack_e($link["href"]); ?>"><?php echo security_pack_e($link["label"]); ?></a>
        <?php endforeach; ?>
    </div>
</div>

<?php if($metrics): ?>
<div class="sp-stats-row" style="margin-bottom:16px;">
    <?php foreach ($metrics as $metric): ?>
        <?php echo TemplateRenderer::component("stat-card", [
            "label" => $metric["label"],
            "value" => number_format((int) $metric["value"]),
            "href" => "",
        ]); ?>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Security Events / Day</h3>
    <?php if(!$trend["series"]): ?>
        <?php echo TemplateRenderer::component("empty-state", ["message" => "No analytics data is available for this period."]); ?>
    <?php else: ?>
        <div style="display:flex;align-items:flex-end;gap:2px;height:80px;overflow-x:auto;">
            <?php foreach ($trend["series"] as $day => $count): ?>
                <?php $barHeight = (int) round(($count / max(1, $trend["max"])) * 76) + 2; ?>
                <div title="<?php echo security_pack_e($day . ": " . $count); ?>" style="flex:1;background:#5bc0de;height:<?php echo $barHeight; ?>px;min-width:2px;"></div>
            <?php endforeach; ?>
        </div>
        <p class="sp-footer-links" style="margin-top:6px;"><?php echo security_pack_e($trend["rangeStart"]); ?> &rarr; <?php echo security_pack_e($trend["rangeEnd"]); ?> (hover a bar for its date/count)</p>
    <?php endif; ?>
</div>

<div class="sp-posture-grid" style="margin-bottom:16px;grid-template-columns:repeat(auto-fill, minmax(260px, 1fr));">
    <?php echo TemplateRenderer::component("top-list-card", ["title" => "Top IPs", "items" => $topSources["ips"]]); ?>
    <?php echo TemplateRenderer::component("top-list-card", ["title" => "Top Countries", "items" => $topSources["countries"]]); ?>
    <?php echo TemplateRenderer::component("top-list-card", ["title" => "Top Event Types", "items" => $topSources["eventTypes"]]); ?>
</div>

<div class="sp-posture-grid" style="grid-template-columns:repeat(auto-fill, minmax(260px, 1fr));">
    <?php echo TemplateRenderer::component("top-list-card", ["title" => "Top CSP Sources", "items" => $topSources["cspSources"]]); ?>
</div>
