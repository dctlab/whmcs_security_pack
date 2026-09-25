<?php
/**
 * Expected variables:
 *   int $score, int $max
 *   array $categories  ["Category Name" => ["earned" => int, "max" => int], ...]
 */
$score = (int) ($score ?? 0);
$max = (int) ($max ?? 0) ?: 1;
$categories = $categories ?? [];
$pct = (int) round(($score / $max) * 100);
$state = $pct >= 80 ? "good" : ($pct >= 50 ? "warn" : "bad");
$stateLabel = $pct >= 80 ? "Protected" : ($pct >= 50 ? "Needs Attention" : "At Risk");
?>
<div class="sp-card sp-score">
    <div class="sp-score-wrap">
        <div class="sp-score-circle sp-score-<?php echo $state; ?>">
            <span class="sp-score-num"><?php echo (int) $score; ?></span>
            <span class="sp-score-den">/ <?php echo (int) $max; ?></span>
        </div>
        <div class="sp-score-summary">
            <h3 class="sp-score-state"><?php echo security_pack_e($stateLabel); ?></h3>
            <p class="sp-score-note">Security Score is calculated from your current DCTLAB Security Pack configuration — it updates automatically as you change settings.</p>
        </div>
    </div>
    <?php if($categories): ?>
    <table class="sp-score-breakdown">
        <tbody>
        <?php foreach ($categories as $name => $cat):
            $catMax = (int) ($cat["max"] ?? 0);
            $catEarned = (int) ($cat["earned"] ?? 0);
            $catPct = $catMax > 0 ? (int) round(($catEarned / $catMax) * 100) : 0;
        ?>
            <tr>
                <td class="sp-score-cat-name"><?php echo security_pack_e($name); ?></td>
                <td class="sp-score-cat-bar"><div class="sp-cat-bar"><span style="width:<?php echo $catPct; ?>%;"></span></div></td>
                <td class="sp-score-cat-val"><?php echo $catEarned; ?>/<?php echo $catMax; ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>
