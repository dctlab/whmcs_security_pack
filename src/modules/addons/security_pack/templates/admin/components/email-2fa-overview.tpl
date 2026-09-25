<?php
/**
 * Shared by templates/admin/email-2fa-embedded.tpl and
 * templates/admin/email-2fa-standalone.tpl — the "Overview" panel is
 * identical in both branches of Email2faController::renderContent()
 * (client/admin active counts, optional contact box, 24h failed
 * verifications). See Email2faController::buildOverviewViewModel().
 *
 * Expected variables:
 *   array $overview  {client:{active,pending}, admin:{active,pending}, contact:?{active,pending}, recentFailures:int}
 */
$overview = $overview ?? ["client" => ["active" => 0, "pending" => 0], "admin" => ["active" => 0, "pending" => 0], "contact" => null, "recentFailures" => 0];
?>
<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Overview</h3>
    <div class="sp-stats-row">
        <?php echo security_pack_render_component("stat-card", [
            "label" => "Client / User Accounts Active",
            "value" => $overview["client"]["active"],
            "hint" => $overview["client"]["pending"] > 0 ? $overview["client"]["pending"] . " pending verification" : "",
        ]); ?>
        <?php echo security_pack_render_component("stat-card", [
            "label" => "Administrator Accounts Active",
            "value" => $overview["admin"]["active"],
            "hint" => $overview["admin"]["pending"] > 0 ? $overview["admin"]["pending"] . " pending verification" : "",
        ]); ?>
        <?php if($overview["contact"] !== null): ?>
        <?php echo security_pack_render_component("stat-card", [
            "label" => "Sub-Account / Contact Active",
            "value" => $overview["contact"]["active"],
            "hint" => $overview["contact"]["pending"] > 0 ? $overview["contact"]["pending"] . " pending verification" : "",
        ]); ?>
        <?php endif; ?>
        <?php echo security_pack_render_component("stat-card", [
            "label" => "Failed Verifications (24h)",
            "value" => $overview["recentFailures"],
        ]); ?>
    </div>
</div>
