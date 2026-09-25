<?php
/**
 * A titled card containing a simple key/count table — the same shape
 * AnalyticsController's original renderTopColumn() produced four times
 * (Top IPs, Top Countries, Top Event Types, Top CSP Sources). Created as
 * a shared component because it's genuinely reused within this one page
 * four times, not because it's speculatively reusable elsewhere.
 *
 * Expected variables:
 *   string $title
 *   array $items          [key => count, ...] — already LIMIT-bounded and ordered by the controller's query; this template does not sort/slice
 *   string $emptyMessage  (optional, defaults to "No data.")
 */
$title = $title ?? "";
$items = $items ?? [];
$emptyMessage = $emptyMessage ?? "No data.";
?>
<div class="sp-card">
    <h3 class="sp-card-title"><?php echo security_pack_e($title); ?></h3>
    <?php if(!$items): ?>
        <p class="sp-empty"><?php echo security_pack_e($emptyMessage); ?></p>
    <?php else: ?>
        <table class="table table-condensed">
            <tbody>
            <?php foreach ($items as $key => $count): ?>
                <tr>
                    <td style="word-break:break-word;"><?php echo security_pack_e($key); ?></td>
                    <td class="text-right"><?php echo security_pack_e(number_format((int) $count)); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
