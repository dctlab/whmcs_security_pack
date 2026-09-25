<?php
use WHMCS\Module\Addon\Security_Pack\Admin\TemplateRenderer;

/**
 * Expected variables (all prepared by DiagnosticsController::index() —
 * runChecks() itself, the Trusted Proxies/retention settings read, the
 * admin-email lookup, and the recent-events query are all UNCHANGED from
 * the pre-Phase-3 controller; this template only renders what it's given):
 *   string|null $successMessage
 *   string|null $errorMessage
 *   string $token                CSRF token, shared by all 3 forms on this page
 *   array $checks                [["name","status","detail"], ...] — runChecks()'s own result, untouched
 *   string $trustedProxies       current settings value (raw, un-normalized — same as before)
 *   string $eventRetentionDays   current settings value (defaults "90", same as before)
 *   int $currentAdminId
 *   string $currentAdminEmail
 *   iterable $recentEvents       last 25 rows from dctlab_security_pack_events, same query as before
 *   array|null $testEmailPreview  ["subject"=>string,"bodyHtml"=>string]|null — set only right
 *                                  after a successful client-type "Send Test Email" render (see
 *                                  DiagnosticsController::testEmail()); the exact rendered bytes
 *                                  WHMCS's own template pipeline produced, so header/footer/logo
 *                                  can be visually confirmed, not just trusted from "sent: true".
 *   array $mailPipelineIntrospection  read-only reflection dump of sendMessage()/
 *                                     sendAdminMessage()'s real source plus
 *                                     \WHMCS\Mail\Emailer/\WHMCS\User\User's real public
 *                                     method list — see DiagnosticsController::
 *                                     introspectMailPipeline(). Added 2026-08-26 to replace
 *                                     guessing about undocumented core mail internals with
 *                                     verified fact read directly from this install.
 */
$successMessage = $successMessage ?? null;
$errorMessage = $errorMessage ?? null;
$token = $token ?? "";
$checks = $checks ?? [];
$trustedProxies = $trustedProxies ?? "";
$eventRetentionDays = $eventRetentionDays ?? "90";
$currentAdminId = $currentAdminId ?? 0;
$currentAdminEmail = $currentAdminEmail ?? "";
$recentEvents = $recentEvents ?? [];
$testEmailPreview = $testEmailPreview ?? null;
$mailPipelineIntrospection = $mailPipelineIntrospection ?? [];
?>
<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">System Checks</h3>
    <?php if(!$checks): ?>
        <?php echo TemplateRenderer::component("empty-state", ["message" => "Diagnostic information is currently unavailable."]); ?>
    <?php else: ?>
        <table class="table">
            <tbody>
            <?php foreach ($checks as $check): ?>
                <tr>
                    <td width="90"><?php echo TemplateRenderer::component("check-badge", ["status" => $check["status"] ?? "info"]); ?></td>
                    <td>
                        <strong><?php echo security_pack_e($check["name"] ?? ""); ?></strong><br>
                        <small class="text-muted" style="word-wrap:break-word;overflow-wrap:break-word;"><?php echo security_pack_e($check["detail"] ?? ""); ?></small>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Network / Trusted Proxies</h3>
    <form method="post" action="?module=security_pack&amp;c=diagnostics&amp;a=save">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <div class="form-group">
            <label>Trusted Proxies <i class="far fa-question-circle" data-toggle="tooltip" data-original-title="One IP or CIDR per line (e.g. a CDN/load balancer's own IP range). When set, CF-Connecting-IP / X-Forwarded-For / X-Real-IP headers are only trusted when the direct connection comes from one of these — otherwise any visitor could spoof their own IP/country. Leave blank to keep pre-2.0 behaviour (all such headers trusted unconditionally)."></i></label>
            <textarea name="trusted_proxies" class="form-control" rows="3" placeholder="e.g.&#10;173.245.48.0/20&#10;10.0.0.5"><?php echo security_pack_e($trustedProxies); ?></textarea>
        </div>
        <div class="form-group">
            <label>Security Event Retention (days)</label>
            <input type="number" min="1" max="3650" class="form-control" style="max-width:150px;display:inline-block;" name="event_retention_days" value="<?php echo security_pack_e($eventRetentionDays); ?>">
        </div>
        <button type="submit" class="btn btn-primary">Save</button>
    </form>
</div>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Email 2FA — Test Delivery</h3>
    <p class="sp-footer-links">Sends a harmless test message through the same WHMCS mail pipeline (sendAdminMessage()/sendMessage()) used to deliver real Email 2FA one-time codes. <strong>Note:</strong> this pipeline applies your Global BCC setting (General Settings &gt; Mail &gt; BCC Messages) just like any other WHMCS email — including to real one-time codes, not just this test. Use this to confirm delivery independent of a live login/activation attempt.</p>

    <form method="post" action="?module=security_pack&amp;c=diagnostics&amp;a=testEmail" class="form-inline" style="margin-bottom:10px;">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <input type="hidden" name="test_user_type" value="admin">
        <input type="hidden" name="test_user_id" value="<?php echo security_pack_e($currentAdminId); ?>">
        <button type="submit" class="btn btn-default">Send Test Email to My Admin Account<?php echo $currentAdminEmail !== "" ? " (" . security_pack_e($currentAdminEmail) . ")" : ""; ?></button>
    </form>

    <form method="post" action="?module=security_pack&amp;c=diagnostics&amp;a=testEmail" class="form-inline">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <input type="hidden" name="test_user_type" value="client">
        <div class="form-group">
            <label>Test Client-Side Delivery — WHMCS User ID: </label>
            <input type="number" min="1" name="test_user_id" class="form-control" style="width:120px;display:inline-block;" required>
        </div>
        <button type="submit" class="btn btn-default">Send Test Email</button>
        <p class="sp-footer-links">Uses the same client-account resolution real client OTP sends use (via <code>tblusers_clients</code>, falling back to a matching <code>tblclients.email</code>) — enter the WHMCS User (login) ID whose delivery path you want to verify, e.g. your own.</p>
    </form>

    <?php if($testEmailPreview !== null): ?>
    <div style="margin-top:16px;border-top:1px solid #e5e5e5;padding-top:16px;">
        <h4>Rendered HTML Preview <small class="text-muted">(the exact bytes WHMCS's template pipeline just produced for the send above)</small></h4>
        <p class="sp-footer-links">This is rendered in an isolated frame below exactly as generated — use it to visually confirm your configured header, footer, logo, and styling actually appear, rather than relying on how your email client happens to display the message (clients often strip or alter styling).</p>
        <div class="form-group">
            <label>Subject</label>
            <input type="text" class="form-control" readonly value="<?php echo security_pack_e($testEmailPreview["subject"] ?? ""); ?>">
        </div>
        <div class="form-group">
            <label>Body (rendered)</label>
            <iframe sandbox="" style="width:100%;min-height:420px;border:1px solid #ccc;background:#fff;" srcdoc="<?php echo security_pack_e($testEmailPreview["bodyHtml"] ?? ""); ?>"></iframe>
        </div>
        <details>
            <summary>View raw HTML source</summary>
            <pre style="max-height:300px;overflow:auto;white-space:pre-wrap;word-wrap:break-word;"><?php echo security_pack_e($testEmailPreview["bodyHtml"] ?? ""); ?></pre>
        </details>
    </div>
    <?php endif; ?>

    <div style="margin-top:16px;border-top:1px solid #e5e5e5;padding-top:16px;">
        <details>
            <summary><strong>Mail Pipeline Introspection</strong> <small class="text-muted">(read-only — the real, currently-loaded source of WHMCS's own sendMessage()/sendAdminMessage(), and the real method list of \WHMCS\Mail\Emailer / \WHMCS\User\User on this install)</small></summary>
            <p class="sp-footer-links" style="margin-top:10px;">Added to answer, with fact instead of guesswork, why manually-built messages (this addon's own client-type OTP send path) don't render WHMCS's Global Header/Footer/branding the way sendMessage()/sendAdminMessage() do elsewhere in this codebase (Login Notification). Nothing here is executed or changed — it's a read-only reflection of code already loaded in this request.</p>

            <?php if(!empty($mailPipelineIntrospection["error"])): ?>
                <div class="alert alert-warning"><?php echo security_pack_e($mailPipelineIntrospection["error"]); ?></div>
            <?php endif; ?>

            <?php foreach (["sendMessage", "sendAdminMessage"] as $fnName): ?>
                <?php $fnInfo = $mailPipelineIntrospection[$fnName] ?? null; ?>
                <h5><code><?php echo security_pack_e($fnName); ?>()</code></h5>
                <?php if(!$fnInfo || empty($fnInfo["available"])): ?>
                    <p class="sp-footer-links">Not available in this execution context<?php echo (!empty($fnInfo["source"])) ? " — " . security_pack_e($fnInfo["source"]) : "."; ?></p>
                <?php else: ?>
                    <p class="sp-footer-links">Defined at <code><?php echo security_pack_e($fnInfo["file"]); ?></code>, lines <?php echo security_pack_e($fnInfo["startLine"]); ?>–<?php echo security_pack_e($fnInfo["endLine"]); ?>.</p>
                    <pre style="max-height:400px;overflow:auto;white-space:pre-wrap;word-wrap:break-word;"><?php echo security_pack_e($fnInfo["source"]); ?></pre>
                <?php endif; ?>
            <?php endforeach; ?>

            <?php foreach (["emailerMethods" => "\\WHMCS\\Mail\\Emailer", "userMethods" => "\\WHMCS\\User\\User"] as $methodsKey => $className): ?>
                <?php $methods = $mailPipelineIntrospection[$methodsKey] ?? null; ?>
                <h5><code><?php echo security_pack_e($className); ?></code> — public methods</h5>
                <?php if($methods === null): ?>
                    <p class="sp-footer-links">Class not loaded in this execution context.</p>
                <?php elseif(!count($methods)): ?>
                    <p class="sp-footer-links">Class loaded, but no public methods were found.</p>
                <?php else: ?>
                    <ul style="font-family:monospace;font-size:12px;">
                        <?php foreach ($methods as $method): ?>
                            <li style="margin-bottom:8px;">
                                <?php echo security_pack_e($method["signature"]); ?>
                                <?php if(!empty($method["doc"])): ?>
                                    <br><span style="color:#888;white-space:pre-wrap;"><?php echo security_pack_e($method["doc"]); ?></span>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endforeach; ?>
        </details>
    </div>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Recent Security Events <small class="text-muted">(last 25 — <a href="?module=security_pack&amp;c=activity">open full Security Activity Center</a>)</small></h3>
    <?php if(!count($recentEvents)): ?>
        <?php echo TemplateRenderer::component("empty-state", ["message" => "No events recorded yet."]); ?>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-condensed">
                <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Message</th><th>IP</th><th>Country</th></tr></thead>
                <tbody>
                <?php foreach ($recentEvents as $event): ?>
                    <?php
                    $sevBadge = $event->severity === "critical"
                        ? '<span class="label label-danger">critical</span>'
                        : ($event->severity === "warning" ? '<span class="label label-warning">warning</span>' : '<span class="label label-default">info</span>');
                    ?>
                    <tr>
                        <td><?php echo security_pack_e($event->created_at); ?></td>
                        <td><?php echo security_pack_e($event->event_type); ?></td>
                        <td><?php echo $sevBadge; ?></td>
                        <td style="word-wrap:break-word;overflow-wrap:break-word;"><?php echo security_pack_e($event->message); ?></td>
                        <td style="word-break:break-all;"><?php echo security_pack_e($event->ip); ?></td>
                        <td><?php echo security_pack_e($event->country_code); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
