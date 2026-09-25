<?php
/**
 * Phase 3.6B — CSP Reports list/detail page (formerly
 * CspReportsController::render()/renderSettingsPanel()/renderStats()/
 * readFilters()/renderFilters()/renderList()/renderDetail(), which
 * echoed this markup directly).
 *
 * Every value on this page originated as untrusted browser input
 * collected by the public csp-report.php endpoint (directive names,
 * blocked URIs, source files, user agents, referrers) — nothing here is
 * rendered without security_pack_e(), matching the original's
 * "never treat CSP report content as safe" discipline exactly.
 *
 * Expected variables:
 *   string|null $errorMessage
 *   string|null $successMessage
 *   string $token
 *   array $settings   ["collection"=>bool,"retentionDays"=>int,"maxRows"=>int]
 *   array $stats      ["totalViolations","uniqueViolations","last24h","affectedResources"] — same 4 COUNT/SUM queries as before, unchanged
 *   array|null $detail  null when no ?view= id was requested; else ["notFound"=>bool,"fields"=>[label=>value,...]]
 *   array $filters    ["directive","domain","source","disposition","from","to","p"] — current filter values, for re-populating the form
 *   array $list       ["unavailable"=>bool,"total","totalPages","page","rows"=>[{"id","directive","blockedUri","sourceFile","lineNumber","disposition","occurrenceCount","firstSeen","lastSeen"}],"paginationLinks"=>[{"href","label","active"}]]
 */
$errorMessage = $errorMessage ?? null;
$successMessage = $successMessage ?? null;
$token = $token ?? "";
$settings = $settings ?? ["collection" => false, "retentionDays" => 30, "maxRows" => 5000];
$stats = $stats ?? ["totalViolations" => 0, "uniqueViolations" => 0, "last24h" => 0, "affectedResources" => 0];
$detail = $detail ?? null;
$filters = $filters ?? ["directive" => "", "domain" => "", "source" => "", "disposition" => "", "from" => "", "to" => "", "p" => 1];
$list = $list ?? ["unavailable" => false, "total" => 0, "totalPages" => 1, "page" => 1, "rows" => [], "paginationLinks" => []];
?>

<?php if($errorMessage !== null): ?>
<div class="alert alert-danger"><?php echo security_pack_e($errorMessage); ?></div>
<?php endif; ?>
<?php if($successMessage !== null): ?>
<div class="alert alert-success"><?php echo security_pack_e($successMessage); ?></div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Collection Settings</h3>
    <form method="post" action="?module=security_pack&amp;c=cspReports&amp;a=save" class="form-inline">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <label style="margin-right:16px;"><input type="checkbox" name="csp_report_collection" value="1" <?php echo $settings["collection"] ? "checked" : ""; ?>> Collect CSP violation reports</label>
        <label style="margin-right:8px;">Retention (days) <input type="number" min="1" max="365" name="csp_report_retention_days" class="form-control" style="width:90px;display:inline-block;" value="<?php echo (int) $settings["retentionDays"]; ?>"></label>
        <label style="margin-right:8px;">Max stored (unique) reports <input type="number" min="100" max="200000" name="csp_report_max_rows" class="form-control" style="width:110px;display:inline-block;" value="<?php echo (int) $settings["maxRows"]; ?>"></label>
        <button type="submit" class="btn btn-primary">Save</button>
    </form>
    <?php if(!$settings["collection"]): ?>
        <p class="text-muted small" style="margin-top:8px;">Collection is off — the public report endpoint responds but records nothing. Enabling this requires <code>Content-Security-Policy-Report-Only</code> to also be enabled on the Settings tab (advanced/off by default).</p>
    <?php else: ?>
        <p class="text-muted small" style="margin-top:8px;">Reports are grouped by directive + resource origin + source file — repeated identical violations increment one row's counter rather than creating new rows. Retention and the max-stored-rows cap are enforced by the daily cleanup job.</p>
    <?php endif; ?>
    <form method="post" action="?module=security_pack&amp;c=cspReports&amp;a=clear" style="margin-top:8px;" onsubmit="return confirm('Delete ALL stored CSP reports? This cannot be undone.')">
        <input type="hidden" name="security_pack_token" value="<?php echo security_pack_e($token); ?>">
        <button type="submit" class="btn btn-danger btn-sm">Clear All Reports</button>
    </form>
</div>

<div class="sp-stats-row" style="margin-bottom:16px;">
    <?php echo security_pack_render_component("stat-card", ["label" => "Total Violations", "value" => $stats["totalViolations"], "hint" => "all-time occurrence count across all groups"]); ?>
    <?php echo security_pack_render_component("stat-card", ["label" => "Unique Violations", "value" => $stats["uniqueViolations"], "hint" => "distinct directive + resource + source shapes"]); ?>
    <?php echo security_pack_render_component("stat-card", ["label" => "Last 24 Hours", "value" => $stats["last24h"], "hint" => "distinct violation groups last seen in the last 24h"]); ?>
    <?php echo security_pack_render_component("stat-card", ["label" => "Affected Resources", "value" => $stats["affectedResources"], "hint" => "distinct blocked resource URIs observed"]); ?>
</div>

<?php if($detail !== null): ?>
<div class="sp-card" style="margin-bottom:16px;">
    <h3 class="sp-card-title">Violation Detail</h3>
    <?php if(!empty($detail["notFound"])): ?>
        <div class="alert alert-warning">Report not found.</div>
    <?php else: ?>
        <table class="table table-condensed">
            <?php foreach ($detail["fields"] as $label => $value): ?>
                <tr><td width="180"><strong><?php echo security_pack_e($label); ?></strong></td><td><?php echo security_pack_e($value ?? "—"); ?></td></tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>
</div>
<?php endif; ?>

<div class="sp-card" style="margin-bottom:16px;">
    <form method="get" class="form-inline">
        <input type="hidden" name="module" value="security_pack"><input type="hidden" name="c" value="cspReports">
        <input type="text" name="directive" class="form-control" placeholder="Directive" value="<?php echo security_pack_e($filters["directive"]); ?>">
        <input type="text" name="domain" class="form-control" placeholder="Domain / blocked URI contains" value="<?php echo security_pack_e($filters["domain"]); ?>">
        <input type="text" name="source" class="form-control" placeholder="Source file contains" value="<?php echo security_pack_e($filters["source"]); ?>">
        <select name="disposition" class="form-control">
            <option value="">Any disposition</option>
            <option value="report" <?php echo $filters["disposition"] === "report" ? "selected" : ""; ?>>report</option>
            <option value="enforce" <?php echo $filters["disposition"] === "enforce" ? "selected" : ""; ?>>enforce</option>
        </select>
        <input type="date" name="from" class="form-control" value="<?php echo security_pack_e($filters["from"]); ?>">
        <input type="date" name="to" class="form-control" value="<?php echo security_pack_e($filters["to"]); ?>">
        <button type="submit" class="btn btn-primary">Filter</button>
        <a href="?module=security_pack&amp;c=cspReports" class="btn btn-default">Reset</a>
    </form>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Grouped Violations <span style="font-weight:400;color:var(--sp-text-muted);"><?php echo number_format($list["total"]); ?> group<?php echo $list["total"] === 1 ? "" : "s"; ?></span></h3>
    <?php if(!empty($list["unavailable"])): ?>
        <div class="alert alert-warning">CSP reports table is not available yet — save the module settings once to run migrations.</div>
    <?php elseif(!count($list["rows"])): ?>
        <?php
        $hasFilters = $filters["directive"] || $filters["domain"] || $filters["source"] || $filters["disposition"];
        echo security_pack_render_component("empty-state", ["message" => "No CSP violations recorded" . ($hasFilters ? " matching the current filters." : " yet.")]);
        ?>
    <?php else: ?>
        <div class="table-responsive">
            <table class="table table-condensed">
                <thead><tr><th>Directive</th><th>Blocked Resource</th><th>Source</th><th>Disposition</th><th>Occurrences</th><th>First Seen</th><th>Last Seen</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($list["rows"] as $row): ?>
                    <tr>
                        <td><code><?php echo security_pack_e($row["directive"]); ?></code></td>
                        <td style="word-break:break-all;"><?php echo security_pack_e($row["blockedUri"]); ?></td>
                        <td style="word-break:break-all;"><?php echo security_pack_e($row["sourceFile"]); ?><?php echo $row["lineNumber"] ? ":" . (int) $row["lineNumber"] : ""; ?></td>
                        <td><?php echo security_pack_e($row["disposition"]); ?></td>
                        <td><?php echo number_format($row["occurrenceCount"]); ?></td>
                        <td><?php echo security_pack_e($row["firstSeen"]); ?></td>
                        <td><?php echo security_pack_e($row["lastSeen"]); ?></td>
                        <td><a class="btn btn-default btn-sm" href="?module=security_pack&amp;c=cspReports&amp;view=<?php echo (int) $row["id"]; ?>">View</a></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php if(count($list["paginationLinks"]) > 1): ?>
        <nav><ul class="pagination">
            <?php foreach ($list["paginationLinks"] as $link): ?>
                <li <?php echo $link["active"] ? 'class="active"' : ""; ?>><a href="<?php echo security_pack_e($link["href"]); ?>"><?php echo security_pack_e($link["label"]); ?></a></li>
            <?php endforeach; ?>
        </ul></nav>
        <?php endif; ?>
    <?php endif; ?>
</div>

<p class="text-muted small" style="margin-top:12px;">CSP stays in <strong>Report-Only</strong> mode — nothing here enforces a policy. <a href="?module=security_pack&amp;c=cspReports&amp;a=policy">Open Policy Analysis &raquo;</a></p>
