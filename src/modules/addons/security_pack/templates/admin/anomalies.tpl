<?php
/**
 * Phase 3.6B — Anomalies page (formerly AnomaliesController::render(),
 * which echoed this markup directly).
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   string $token
 *   string $statusFilter   one of "open"|"acknowledged"|"dismissed"|"all"
 *   bool $unavailable      true when the anomalies table query itself failed (matches the original's catch block)
 *   array $rows            [{"id","severity","panelClass","rule","confidence","status","reason","evidence"=>[key=>displayValue,...],"createdAt","updatedAt"}, ...]
 *   int $suppressDays      AnomaliesController::SUPPRESS_DAYS, used only in the Dismiss confirm() text
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$token = $token ?? "";
$statusFilter = $statusFilter ?? "open";
$unavailable = $unavailable ?? false;
$rows = $rows ?? [];
$suppressDays = $suppressDays ?? 7;
?>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<p class="text-muted">Anomalies are detected by fixed, deterministic threshold rules against your existing Security Events — not by a machine-learning or AI system. Every finding below states exactly why it was flagged.</p>

<div class="btn-group" style="margin-bottom:12px;" role="group">
    <?php foreach (["open" => "Open", "acknowledged" => "Acknowledged", "dismissed" => "Dismissed", "all" => "All"] as $key => $label): ?>
        <?php $active = $statusFilter === $key ? "btn-primary" : "btn-default"; ?>
        <a class="btn <?php echo $active; ?> btn-sm" href="?module=security_pack&amp;c=anomalies&amp;status=<?php echo security_pack_e($key); ?>"><?php echo security_pack_e($label); ?></a>
    <?php endforeach; ?>
</div>

<?php if($unavailable): ?>
    <div class="alert alert-warning">Anomalies table is not available yet — save the module settings once to run migrations.</div>
<?php elseif(!count($rows)): ?>
    <p class="text-muted">No <?php echo security_pack_e($statusFilter === "all" ? "" : $statusFilter); ?> anomalies.</p>
<?php else: ?>
    <?php foreach ($rows as $row): ?>
        <div class="panel <?php echo security_pack_e($row["panelClass"]); ?>">
            <div class="panel-heading">
                <strong><?php echo strtoupper(security_pack_e($row["severity"])); ?></strong> &middot; <?php echo security_pack_e($row["rule"]); ?> &middot; <span class="text-muted">confidence: <?php echo security_pack_e($row["confidence"]); ?></span>
                <span class="pull-right label label-default"><?php echo security_pack_e($row["status"]); ?></span>
            </div>
            <div class="panel-body">
                <p><strong>Reason:</strong> <?php echo security_pack_e($row["reason"]); ?></p>
                <?php if(!empty($row["evidence"])): ?>
                    <p><strong>Evidence:</strong></p>
                    <ul>
                        <?php foreach ($row["evidence"] as $k => $v): ?>
                            <li><?php echo security_pack_e($k); ?>: <?php echo security_pack_e($v); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
                <p class="text-muted small">First flagged <?php echo security_pack_e($row["createdAt"]); ?> &middot; last observed <?php echo security_pack_e($row["updatedAt"]); ?></p>
                <?php if($row["status"] === "open"): ?>
                    <form method="post" action="?module=security_pack&amp;c=anomalies&amp;a=acknowledge" style="display:inline;">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>"><input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-default btn-sm">Acknowledge</button>
                    </form>
                    <form method="post" action="?module=security_pack&amp;c=anomalies&amp;a=dismiss" style="display:inline;" onsubmit="return confirm('Dismiss this anomaly? It will be suppressed for <?php echo (int) $suppressDays; ?> days if the same pattern recurs, then re-flagged if it is still happening.')">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>"><input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-danger btn-sm">Dismiss</button>
                    </form>
                <?php elseif($row["status"] === "acknowledged"): ?>
                    <form method="post" action="?module=security_pack&amp;c=anomalies&amp;a=dismiss" style="display:inline;">
                        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>"><input type="hidden" name="id" value="<?php echo (int) $row["id"]; ?>">
                        <button type="submit" class="btn btn-danger btn-sm">Dismiss</button>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    <?php endforeach; ?>
<?php endif; ?>
