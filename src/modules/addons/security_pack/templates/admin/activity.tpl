<?php
/**
 * Expected variables (all prepared by ActivityController::index() — the
 * Capsule query, filtering, and pagination MATH are all still in the
 * controller, unchanged; this template only formats what it's given):
 *   array $filters      ["type","severity","ip","country","search","dateFrom","dateTo"] — current filter values, for re-populating the form
 *   array $eventTypes   distinct event_type values, for the filter dropdown
 *   iterable $events    raw rows from dctlab_security_pack_events (stdClass: created_at, event_type, severity, actor_type, actor_id, ip, country_code, message, context) — untouched from the original query
 *   int $total
 *   array $paginationLinks  [["href","label","active","disabled"], ...] — pre-built by the controller (same page-window math as before: current page +/- 3)
 */
$filters = $filters ?? ["type" => "", "severity" => "", "ip" => "", "country" => "", "search" => "", "dateFrom" => "", "dateTo" => ""];
$eventTypes = $eventTypes ?? [];
$events = $events ?? [];
$total = $total ?? 0;
$paginationLinks = $paginationLinks ?? [];
?>
<div class="sp-card">
    <form method="get" class="form-inline">
        <input type="hidden" name="module" value="security_pack"><input type="hidden" name="c" value="activity">
        <input type="text" name="q" class="form-control" placeholder="Search message/type" value="<?php echo security_pack_e($filters["search"]); ?>">
        <select name="type" class="form-control">
            <option value="">All Event Types</option>
            <?php foreach ($eventTypes as $t): ?>
                <option value="<?php echo security_pack_e($t); ?>" <?php echo $filters["type"] === $t ? "selected" : ""; ?>><?php echo security_pack_e($t); ?></option>
            <?php endforeach; ?>
        </select>
        <select name="severity" class="form-control">
            <option value="">All Severities</option>
            <?php foreach (["info" => "Info", "warning" => "Warning", "critical" => "Critical"] as $val => $label): ?>
                <option value="<?php echo $val; ?>" <?php echo $filters["severity"] === $val ? "selected" : ""; ?>><?php echo $label; ?></option>
            <?php endforeach; ?>
        </select>
        <input type="text" name="ip" class="form-control" style="width:140px;" placeholder="IP contains" value="<?php echo security_pack_e($filters["ip"]); ?>">
        <input type="text" name="country" class="form-control" style="width:80px;" placeholder="Country" maxlength="2" value="<?php echo security_pack_e($filters["country"]); ?>">
        <input type="date" name="from" class="form-control" value="<?php echo security_pack_e($filters["dateFrom"]); ?>">
        <input type="date" name="to" class="form-control" value="<?php echo security_pack_e($filters["dateTo"]); ?>">
        <button type="submit" class="btn btn-primary">Filter</button>
        <a href="?module=security_pack&amp;c=activity" class="btn btn-default">Reset</a>
    </form>
</div>

<div class="sp-card">
    <h3 class="sp-card-title">Security Activity <span style="font-weight:400;color:var(--sp-text-muted);"><?php echo (int) $total; ?> event<?php echo $total === 1 ? "" : "s"; ?></span></h3>
    <?php if(!count($events)): ?>
        <p class="sp-empty">No events match the current filters.</p>
    <?php else: ?>
        <?php
        // Context/column layout rules below are carried over verbatim from
        // the pre-Phase-3 controller (2.7.1-2.7.4 fixes) — same historical
        // bugs (context JSON overflowing the row, IPv6 addresses colliding
        // with the Country column) apply regardless of which layer renders
        // the markup, so the same fixes are preserved here rather than
        // rediscovered later.
        $contextPreviewLimit = 220;
        ?>
        <div class="table-responsive">
            <table class="table table-condensed" style="table-layout:fixed;">
                <colgroup>
                    <col style="width:100px;"><col style="width:230px;"><col style="width:70px;"><col style="width:90px;"><col style="width:190px;"><col style="width:70px;"><col>
                </colgroup>
                <thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Actor</th><th>IP</th><th>Country</th><th>Message</th></tr></thead>
                <tbody>
                <?php foreach ($events as $event): ?>
                    <?php
                    $sevBadge = $event->severity === "critical"
                        ? '<span class="label label-danger">critical</span>'
                        : ($event->severity === "warning" ? '<span class="label label-warning">warning</span>' : '<span class="label label-default">info</span>');
                    $actor = $event->actor_type ? ($event->actor_type . " #" . $event->actor_id) : "—";

                    $contextHtml = "";
                    if($event->context) {
                        $ctx = json_decode((string) $event->context, true);
                        if($ctx) {
                            $contextJson = json_encode($ctx);
                            $truncated = mb_strlen($contextJson) > $contextPreviewLimit;
                            $contextDisplay = $truncated ? (mb_substr($contextJson, 0, $contextPreviewLimit) . "…") : $contextJson;
                            $contextHtml = "<br><small class=\"text-muted\" style=\"word-break:break-all;\">" . security_pack_e($contextDisplay) . ($truncated ? " <em>(truncated — see dctlab_security_pack_events.context for the full value)</em>" : "") . "</small>";
                        }
                    }
                    ?>
                    <tr>
                        <td><?php echo security_pack_e($event->created_at); ?></td>
                        <td style="word-break:break-word;"><code style="white-space:normal;word-break:break-word;"><?php echo security_pack_e($event->event_type); ?></code></td>
                        <td><?php echo $sevBadge; ?></td>
                        <td style="word-break:break-word;"><?php echo security_pack_e($actor); ?></td>
                        <td style="word-break:break-all;"><?php echo security_pack_e($event->ip); ?></td>
                        <td><?php echo security_pack_e($event->country_code); ?></td>
                        <td style="word-wrap:break-word;overflow-wrap:break-word;"><?php echo security_pack_e($event->message); ?><?php echo $contextHtml; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php if(count($paginationLinks) > 1): ?>
<nav><ul class="pagination">
    <?php foreach ($paginationLinks as $link): ?>
        <li class="<?php echo $link["disabled"] ? "disabled" : ($link["active"] ? "active" : ""); ?>">
            <a href="<?php echo security_pack_e($link["href"]); ?>"><?php echo $link["label"]; ?></a>
        </li>
    <?php endforeach; ?>
</ul></nav>
<?php endif; ?>
