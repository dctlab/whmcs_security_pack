<?php
/**
 * Phase 3.6B — CSP Policy Analysis sub-page (formerly
 * CspReportsController::policy(), which echoed this markup directly and
 * had three distinct early-exit shapes depending on data availability —
 * all three are preserved via $status below, not flattened into one).
 *
 * Expected variables:
 *   string|null $errorMessage   note: the original only ever checked
 *       $_SESSION["nnm_csp_error"] here, never the success message — that
 *       asymmetry (vs. the main list page, which shows both) is preserved.
 *   string $status   "unavailable" (query/table failed — matches the original's
 *       catch block), "empty" (query ran, zero grouped origins), or "ok"
 *   array $originRows   only meaningful when $status === "ok":
 *       [{"origin","classification","badgeClass","directivesList","count"}, ...]
 *   array $suggested   only meaningful when $status === "ok": list of origin
 *       strings whose classification isn't "Observed" — same
 *       CspReportService::classifySource() rule as before
 */
$errorMessage = $errorMessage ?? null;
$status = $status ?? "unavailable";
$originRows = $originRows ?? [];
$suggested = $suggested ?? [];
?>
<p><a href="?module=security_pack&amp;c=cspReports">&laquo; Back to CSP Reports</a></p>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">CSP Policy Analysis</h3>
    <p class="text-muted">This analysis is <strong>observational only</strong> — it never classifies a source as "safe" and never modifies the enforced policy. Review every entry before adding it anywhere.</p>

    <?php if($status === "unavailable"): ?>
        <p class="text-muted">No data available yet.</p>
    <?php elseif($status === "empty"): ?>
        <p class="text-muted">No CSP violations recorded yet.</p>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-condensed">
                <thead><tr><th>Source</th><th>Classification</th><th>Directives</th><th>Occurrences</th></tr></thead>
                <tbody>
                <?php foreach ($originRows as $row): ?>
                    <tr>
                        <td><code><?php echo security_pack_e($row["origin"]); ?></code></td>
                        <td><span class="label <?php echo security_pack_e($row["badgeClass"]); ?>"><?php echo security_pack_e($row["classification"]); ?></span></td>
                        <td><?php echo security_pack_e($row["directivesList"]); ?></td>
                        <td><?php echo number_format($row["count"]); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php if($status === "ok"): ?>
<div class="sp-card">
    <h3 class="sp-card-title">Suggested Additions — Review Before Enabling</h3>
    <?php if(!count($suggested)): ?>
        <p class="text-muted">No unrecognized or third-party sources observed.</p>
    <?php else: ?>
        <p>These sources are triggering CSP violations and are not part of any policy this module manages. Nothing has been added automatically — a suggested <code>script-src</code>/<code>style-src</code> style addition is shown for reference only:</p>
        <pre><?php foreach ($suggested as $origin): ?><?php echo security_pack_e($origin); ?>
<?php endforeach; ?></pre>
        <p class="text-muted small">This module does not manage or emit an enforcing Content-Security-Policy header — these additions, if you choose to use them, apply to whatever policy you manage elsewhere (your own header configuration, CDN, or reverse proxy).</p>
    <?php endif; ?>
</div>
<?php endif; ?>
