<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Phase 3.6A — IP Restrictions page (formerly
 * IpRestrictionsController::render()/renderAddForm()/renderList()/
 * renderLockoutWarning(), which echoed this markup directly).
 *
 * Every field name, form action, POST/CSRF/enable-disable/delete
 * behavior, and validation message is unchanged — this template only
 * formats the same view-model the controller already builds from its
 * unmodified query/business logic.
 *
 * The native `confirm()` dialog on Delete (see components/rule-actions.tpl)
 * was kept verbatim rather than replaced with a custom modal — it's real,
 * already-tested interactive behavior this environment can't verify live,
 * and it already satisfies the "confirmation before a destructive action"
 * requirement without inventing new JS.
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   array|null $lockoutWarning   ["target","admin_ip","rule_type","description","expires","priority"] — same session payload as before
 *   string $token
 *   array $stats   ["total","enabled","disabled","allow","block"] — counts DERIVED from the same already-loaded $rules collection the original query fetched; no new query, no new business rule. Shown because the original page already displayed a rule count ("N rule(s)") — this only breaks that same count down further.
 *   array $rules   [{"id","ruleType","target","description","enabled","expired","expiresDisplay","priority","createdBy"}, ...] — one entry per row, straight from the unmodified dctlab_security_pack_ip_rules query
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$lockoutWarning = $lockoutWarning ?? null;
$token = $token ?? "";
$stats = $stats ?? ["total" => 0, "enabled" => 0, "disabled" => 0, "allow" => 0, "block" => 0];
$rules = $rules ?? [];
$baseHref = "?module=security_pack&amp;c=ipRestrictions&amp;a=";
?>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<?php if($lockoutWarning !== null): ?>
<div class="panel panel-danger">
    <div class="panel-heading"><strong>⚠ This rule would block YOUR current IP</strong></div>
    <div class="panel-body">
        <p>Saving a <strong>BLOCK</strong> rule for <code><?php echo security_pack_e($lockoutWarning["target"] ?? ""); ?></code> would also block your own detected IP address (<code><?php echo security_pack_e($lockoutWarning["admin_ip"] ?? ""); ?></code>), which could lock you out of the admin area.</p>
        <form method="post" action="?module=security_pack&amp;c=ipRestrictions&amp;a=save">
            <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
            <?php foreach (["rule_type", "target", "description", "expires", "priority"] as $field): ?>
                <input type="hidden" name="<?php echo $field; ?>" value="<?php echo security_pack_e($lockoutWarning[$field] ?? ""); ?>">
            <?php endforeach; ?>
            <input type="hidden" name="confirm_lockout" value="1">
            <button type="submit" class="btn btn-danger">I understand — block it anyway</button>
            <a href="?module=security_pack&amp;c=ipRestrictions" class="btn btn-default">Cancel</a>
        </form>
    </div>
</div>
<?php endif; ?>

<div class="sp-stats-row" style="margin-bottom:16px;">
    <?php echo TemplateRenderer::component("stat-card", ["label" => "Total Rules", "value" => $stats["total"]]); ?>
    <?php echo TemplateRenderer::component("stat-card", ["label" => "Enabled", "value" => $stats["enabled"]]); ?>
    <?php echo TemplateRenderer::component("stat-card", ["label" => "Disabled", "value" => $stats["disabled"]]); ?>
    <?php echo TemplateRenderer::component("stat-card", ["label" => "Block Rules", "value" => $stats["block"]]); ?>
    <?php echo TemplateRenderer::component("stat-card", ["label" => "Allow Rules", "value" => $stats["allow"]]); ?>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Add IP Restriction Rule</h3>
    <form method="post" action="?module=security_pack&amp;c=ipRestrictions&amp;a=save" class="form-inline">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <select name="rule_type" class="form-control">
            <option value="block">Block</option>
            <option value="allow">Allow</option>
        </select>
        <input type="text" name="target" class="form-control" placeholder="IP or CIDR, e.g. 203.0.113.25 or 203.0.113.0/24" required style="min-width:260px;">
        <input type="text" name="description" class="form-control" placeholder="Description (optional)" style="min-width:200px;">
        <select name="expires" class="form-control">
            <option value="never">Never expires</option>
            <option value="1">Expires in 24 hours</option>
            <option value="7">Expires in 7 days</option>
            <option value="30">Expires in 30 days</option>
        </select>
        <input type="number" name="priority" class="form-control" placeholder="Priority" value="0" style="width:90px;">
        <button type="submit" class="btn btn-primary">Add Rule</button>
    </form>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">IP Restriction Rules <span style="font-weight:400;color:var(--sp-text-muted);"><?php echo (int) $stats["total"]; ?> rule<?php echo $stats["total"] === 1 ? "" : "s"; ?></span></h3>
    <?php if(!count($rules)): ?>
        <?php echo TemplateRenderer::component("empty-state", ["message" => "No rules configured — every visitor is currently unaffected by IP Restrictions."]); ?>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-condensed">
                <thead><tr><th>Type</th><th>IP / CIDR</th><th>Description</th><th>Status</th><th>Expires</th><th>Priority</th><th>Created By</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($rules as $rule): ?>
                    <?php
                    $typeBadge = $rule["ruleType"] === "block" ? '<span class="label label-danger">BLOCK</span>' : '<span class="label label-success">ALLOW</span>';
                    $statusLabel = !$rule["enabled"] ? '<span class="label label-default">Disabled</span>' : ($rule["expired"] ? '<span class="label label-warning">Expired</span>' : '<span class="label label-success">Active</span>');
                    ?>
                    <tr>
                        <td><?php echo $typeBadge; ?></td>
                        <td style="word-break:break-all;"><code><?php echo security_pack_e($rule["target"]); ?></code></td>
                        <td style="word-break:break-word;"><?php echo security_pack_e($rule["description"]); ?></td>
                        <td><?php echo $statusLabel; ?></td>
                        <td><?php echo security_pack_e($rule["expiresDisplay"]); ?></td>
                        <td><?php echo (int) $rule["priority"]; ?></td>
                        <td><?php echo security_pack_e($rule["createdBy"]); ?></td>
                        <td><?php echo TemplateRenderer::component("rule-actions", [
                            "token" => $token, "id" => $rule["id"], "enabled" => $rule["enabled"],
                            "target" => $rule["target"], "baseHref" => $baseHref,
                        ]); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
    <p class="text-muted small" style="margin-top:12px;">IP Restrictions are evaluated by <code>IpRestrictionService::evaluate()</code>. With zero rules configured, nothing is blocked — this feature is off by default on every install, including upgrades. Precedence: a more specific match (exact IP over CIDR, narrower CIDR over broader) always wins; ties break on Priority, then on the most recently saved rule.</p>
</div>
