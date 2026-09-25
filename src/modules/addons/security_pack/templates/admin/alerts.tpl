<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Expected variables (all prepared by AlertsController::index() — this
 * template only renders, never queries, saves, or computes):
 *   string $token             CSRF token for the delivery-settings form
 *   bool   $emailEnabled
 *   string|null $successMessage
 *   string|null $errorMessage
 *   array  $alerts            [["severity","title","reason","href"], ...] — straight from SecurityAlertService::gather(), untouched
 */
$token = $token ?? "";
$emailEnabled = $emailEnabled ?? false;
$successMessage = $successMessage ?? null;
$errorMessage = $errorMessage ?? null;
$alerts = $alerts ?? [];
?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<div class="sp-card">
    <h3 class="sp-card-title">Delivery</h3>
    <form method="post" action="?module=security_pack&amp;c=alerts&amp;a=save">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <label>
            <input type="checkbox" name="alerts_email_enabled" value="1" <?php echo $emailEnabled ? "checked" : ""; ?>>
            Send a daily email digest to admins when HIGH or CRITICAL alerts are open
        </label>
        &nbsp;
        <button type="submit" class="btn btn-primary btn-sm">Save</button>
    </form>
    <p class="sp-footer-links" style="margin-top:8px;">Delivered once per day via the existing WHMCS admin-message system (Security Pack - Security Alert Digest email template) — no external messaging provider is used. Off by default; only meaningful (HIGH/CRITICAL) alerts are ever included, never every ordinary event.</p>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Current Alerts <span style="font-weight:400;color:var(--sp-text-muted);"><?php echo (int) count($alerts); ?></span></h3>
    <?php if(!$alerts): ?>
        <?php echo TemplateRenderer::component("empty-state", ["message" => "No open alerts. This view only surfaces meaningful conditions (repeated failures, IP/country/CSP spikes, a Security Score drop, or an unacknowledged high-severity anomaly) — not every ordinary security event."]); ?>
    <?php else: ?>
        <?php foreach ($alerts as $alert): ?>
            <?php echo TemplateRenderer::component("alert-item", [
                "severity" => $alert["severity"] ?? "info",
                "title" => $alert["title"] ?? "",
                "reason" => $alert["reason"] ?? "",
                "href" => $alert["href"] ?? "",
            ]); ?>
        <?php endforeach; ?>
    <?php endif; ?>
</div>
