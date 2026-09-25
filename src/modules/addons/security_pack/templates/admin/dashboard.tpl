<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Expected variables (all prepared by DashboardController::index() — this
 * template only renders, never queries or computes):
 *   int $score, int $max, array $categories, array $recommendations
 *   array $stats            [["label" => "Open Alerts", "value" => int|null, "href" => string], ...]
 *   array $postureCards      [["label" => "...", "on" => bool, "href" => "..."], ...]
 */
$score = $score ?? 0;
$max = $max ?? 0;
$categories = $categories ?? [];
$recommendations = $recommendations ?? [];
$stats = $stats ?? [];
$postureCards = $postureCards ?? [];
?>
<?php echo TemplateRenderer::component("security-score", ["score" => $score, "max" => $max, "categories" => $categories]); ?>

<?php if($stats): ?>
<div class="sp-stats-row">
    <?php foreach ($stats as $stat) {
        echo TemplateRenderer::component("stat-card", $stat);
    } ?>
</div>
<?php endif; ?>

<div class="sp-card">
    <h3 class="sp-card-title">Security Recommendations</h3>
    <?php
    $shown = 0;
    foreach ($recommendations as $rec) {
        if(($rec["severity"] ?? "") === "pass" && $shown >= 3) {
            // Don't bury actionable warnings/info under a wall of PASS entries.
            continue;
        }
        echo TemplateRenderer::component("recommendation", $rec);
        $shown++;
    }
    if(!$shown) {
        echo TemplateRenderer::component("empty-state", ["message" => "Nothing to show."]);
    }
    ?>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Security Posture</h3>
    <div class="sp-posture-grid">
        <?php foreach ($postureCards as $card): ?>
        <a href="<?php echo security_pack_e($card["href"]); ?>" class="sp-posture-item">
            <span class="sp-posture-label"><?php echo security_pack_e($card["label"]); ?></span>
            <?php echo TemplateRenderer::component("status-badge", ["on" => $card["on"]]); ?>
        </a>
        <?php endforeach; ?>
    </div>
</div>

<p class="sp-footer-links">
    Full event history: <a href="?module=security_pack&amp;c=activity">Security Activity Center &raquo;</a>
    &nbsp;|&nbsp;
    System health: <a href="?module=security_pack&amp;c=diagnostics">Security Diagnostics &raquo;</a>
</p>
