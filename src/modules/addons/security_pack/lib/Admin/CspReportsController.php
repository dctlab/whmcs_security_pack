<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

use WHMCS\Module\Addon\Security_Pack\Security\CspReportService;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — CSP Reports (System > CSP Reports).
 *
 * Read-only browser over the dctlab_security_pack_csp_reports table
 * (populated by csp-report.php, the public collection endpoint) plus a
 * small settings panel for collection/retention and a "Policy Analysis"
 * view. Every value rendered here originated as untrusted browser input
 * — nothing is echoed without htmlspecialchars(), and CSP report content
 * (directives/URIs/user agents) is never treated as executable or safe.
 *
 * PHASE 3.6B (2026-08-24): migrated to the templates/admin/ presentation
 * layer. index()/save()/clear() — the POST-only+CSRF guard, the two
 * updateOrInsert()/delete() calls, the security_pack_record_event() calls
 * — and settings()/readFilters()/applyFilters()/originForDisplay() — the
 * exact query filters, LIKE-escaping, and origin-grouping logic — are all
 * copied verbatim, byte-for-byte. Only render()/renderSettingsPanel()/
 * renderStats()/renderFilters()/renderList()/renderDetail()/policy()
 * (which echoed HTML directly) were rebuilt to produce a view-model for
 * TemplateRenderer; no query, no validation rule, and no redirect target
 * changed.
 */
class CspReportsController
{
    private const PER_PAGE = 25;

    public function index($vars = [])
    {
        $action = isset($_REQUEST["a"]) ? (string) $_REQUEST["a"] : "index";
        // Security Pack 2.5 (Step 11 discipline, same as every other
        // controller since 2.3): every state-changing action here is
        // POST-only + CSRF-validated. List/detail/policy views stay GET
        // (read-only).
        $postOnlyActions = ["save", "clear"];
        if(in_array($action, $postOnlyActions, true)) {
            if($_SERVER["REQUEST_METHOD"] !== "POST") {
                redir("module=security_pack&c=cspReports", "addonmodules.php");
            }
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_csp_error"] = "Your session token expired — please try again.";
                redir("module=security_pack&c=cspReports", "addonmodules.php");
            }
        }

        switch ($action) {
            case "save":
                $this->save();
                return;
            case "clear":
                $this->clear();
                return;
            case "policy":
                $this->policy();
                return;
        }

        $this->render();
    }

    private function settings()
    {
        $settings = security_pack_settings();
        return [
            "collection" => !empty($settings["csp_report_collection"]) && $settings["csp_report_collection"] !== "0",
            "retention_days" => isset($settings["csp_report_retention_days"]) ? max(1, (int) $settings["csp_report_retention_days"]) : 30,
            "max_rows" => isset($settings["csp_report_max_rows"]) ? max(100, (int) $settings["csp_report_max_rows"]) : 5000,
        ];
    }

    private function render()
    {
        $token = security_pack_csrf_token();
        $settings = $this->settings();

        $errorMessage = null;
        if(isset($_SESSION["nnm_csp_error"])) {
            $errorMessage = (string) $_SESSION["nnm_csp_error"];
            unset($_SESSION["nnm_csp_error"]);
        }
        $successMessage = null;
        if(isset($_SESSION["nnm_csp_success"])) {
            $successMessage = (string) $_SESSION["nnm_csp_success"];
            unset($_SESSION["nnm_csp_success"]);
        }

        $stats = $this->buildStats();

        $viewId = isset($_GET["view"]) ? (int) $_GET["view"] : 0;
        $detail = $viewId > 0 ? $this->buildDetail($viewId) : null;

        $filters = $this->readFilters();
        $list = $this->buildList($filters);

        $content = TemplateRenderer::render("csp-reports", [
            "errorMessage" => $errorMessage,
            "successMessage" => $successMessage,
            "token" => $token,
            "settings" => ["collection" => $settings["collection"], "retentionDays" => $settings["retention_days"], "maxRows" => $settings["max_rows"]],
            "stats" => $stats,
            "detail" => $detail,
            "filters" => $filters,
            "list" => $list,
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "CSP Reports",
            "pageDescription" => "Browse Content-Security-Policy violation reports collected from browsers.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /** Same 4 queries/try-catch the original renderStats() ran, just returned instead of echoed. */
    private function buildStats(): array
    {
        try {
            $totalViolations = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->sum("occurrence_count");
            $uniqueViolations = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->count();
            $last24h = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->where("last_seen", ">=", date("Y-m-d H:i:s", time() - 86400))->count();
            $affectedResources = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->whereNotNull("blocked_uri")->distinct()->count("blocked_uri");
        } catch (\Throwable $e) {
            $totalViolations = $uniqueViolations = $last24h = $affectedResources = 0;
        }
        return ["totalViolations" => $totalViolations, "uniqueViolations" => $uniqueViolations, "last24h" => $last24h, "affectedResources" => $affectedResources];
    }

    private function readFilters(): array
    {
        return [
            "directive" => trim((string) ($_GET["directive"] ?? "")),
            "domain" => trim((string) ($_GET["domain"] ?? "")),
            "source" => trim((string) ($_GET["source"] ?? "")),
            "disposition" => trim((string) ($_GET["disposition"] ?? "")),
            "from" => trim((string) ($_GET["from"] ?? "")),
            "to" => trim((string) ($_GET["to"] ?? "")),
            "p" => max(1, (int) ($_GET["p"] ?? 1)),
        ];
    }

    private function applyFilters($query, array $filters)
    {
        if($filters["directive"] !== "") {
            $query->where("violated_directive", "like", "%" . str_replace(["%", "_"], ["\\%", "\\_"], $filters["directive"]) . "%");
        }
        if($filters["domain"] !== "") {
            $query->where("blocked_uri", "like", "%" . str_replace(["%", "_"], ["\\%", "\\_"], $filters["domain"]) . "%");
        }
        if($filters["source"] !== "") {
            $query->where("source_file", "like", "%" . str_replace(["%", "_"], ["\\%", "\\_"], $filters["source"]) . "%");
        }
        if(in_array($filters["disposition"], ["report", "enforce"], true)) {
            $query->where("disposition", $filters["disposition"]);
        }
        if($filters["from"] !== "" && strtotime($filters["from"]) !== false) {
            $query->where("last_seen", ">=", date("Y-m-d 00:00:00", strtotime($filters["from"])));
        }
        if($filters["to"] !== "" && strtotime($filters["to"]) !== false) {
            $query->where("last_seen", "<=", date("Y-m-d 23:59:59", strtotime($filters["to"])));
        }
        return $query;
    }

    /** Same query/pagination MATH as the original renderList(), just returned as data instead of echoed. */
    private function buildList(array $filters): array
    {
        try {
            $query = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports");
            $query = $this->applyFilters($query, $filters);
            $total = (clone $query)->count();
            $totalPages = max(1, (int) ceil($total / self::PER_PAGE));
            $page = min($filters["p"], $totalPages);
            $rows = $query->orderBy("occurrence_count", "DESC")->offset(($page - 1) * self::PER_PAGE)->limit(self::PER_PAGE)->get();
        } catch (\Throwable $e) {
            return ["unavailable" => true, "total" => 0, "totalPages" => 1, "page" => 1, "rows" => [], "paginationLinks" => []];
        }

        $rowsOut = [];
        foreach ($rows as $row) {
            $rowsOut[] = [
                "id" => (int) $row->id,
                "directive" => (string) $row->violated_directive,
                "blockedUri" => $row->blocked_uri ?: "(none)",
                "sourceFile" => $row->source_file ?: "—",
                "lineNumber" => $row->line_number ? (int) $row->line_number : null,
                "disposition" => $row->disposition ?: "—",
                "occurrenceCount" => (int) $row->occurrence_count,
                "firstSeen" => $row->first_seen,
                "lastSeen" => $row->last_seen,
            ];
        }

        $paginationLinks = [];
        if($totalPages > 1) {
            for ($i = 1; $i <= $totalPages; $i++) {
                $qs = array_filter(array_merge($filters, ["module" => "security_pack", "c" => "cspReports", "p" => $i]), static fn ($v) => $v !== "" && $v !== null);
                $paginationLinks[] = ["href" => "?" . http_build_query($qs), "label" => (string) $i, "active" => $i === $page];
            }
        }

        return ["unavailable" => false, "total" => $total, "totalPages" => $totalPages, "page" => $page, "rows" => $rowsOut, "paginationLinks" => $paginationLinks];
    }

    /** Same query/field list as the original renderDetail(), just returned as data instead of echoed. */
    private function buildDetail(int $id): array
    {
        try {
            $row = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->where("id", $id)->first();
        } catch (\Throwable $e) {
            $row = null;
        }
        if(!$row) {
            return ["notFound" => true, "fields" => []];
        }
        return [
            "notFound" => false,
            "fields" => [
                "Violated Directive" => $row->violated_directive,
                "Effective Directive" => $row->effective_directive,
                "Document URI" => $row->document_uri,
                "Blocked URI" => $row->blocked_uri,
                "Source File" => $row->source_file,
                "Line" => $row->line_number,
                "Column" => $row->column_number,
                "Disposition" => $row->disposition,
                "Sample Referrer" => $row->sample_referrer,
                "Sample User Agent" => $row->sample_user_agent,
                "First Seen" => $row->first_seen,
                "Last Seen" => $row->last_seen,
                "Occurrences" => number_format((int) $row->occurrence_count),
            ],
        ];
    }

    private function policy()
    {
        $token = security_pack_csrf_token();
        $errorMessage = null;
        if(isset($_SESSION["nnm_csp_error"])) {
            $errorMessage = (string) $_SESSION["nnm_csp_error"];
            unset($_SESSION["nnm_csp_error"]);
        }

        try {
            $rows = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                ->select(["blocked_uri", "occurrence_count", "violated_directive"])
                ->whereNotNull("blocked_uri")
                ->orderBy("occurrence_count", "DESC")
                ->limit(2000)
                ->get();
        } catch (\Throwable $e) {
            $content = TemplateRenderer::render("csp-policy", ["errorMessage" => $errorMessage, "status" => "unavailable"]);
            echo TemplateRenderer::assetTags();
            echo TemplateRenderer::render("layout", ["pageTitle" => "CSP Policy Analysis", "pageDescription" => "", "pageActionsHtml" => "", "content" => $content]);
            return;
        }

        $byOrigin = [];
        foreach ($rows as $row) {
            $origin = self::originForDisplay((string) $row->blocked_uri);
            if(!isset($byOrigin[$origin])) {
                $byOrigin[$origin] = ["count" => 0, "directives" => []];
            }
            $byOrigin[$origin]["count"] += (int) $row->occurrence_count;
            $byOrigin[$origin]["directives"][(string) $row->violated_directive] = true;
        }
        arsort($byOrigin);

        if(!$byOrigin) {
            $content = TemplateRenderer::render("csp-policy", ["errorMessage" => $errorMessage, "status" => "empty"]);
            echo TemplateRenderer::assetTags();
            echo TemplateRenderer::render("layout", ["pageTitle" => "CSP Policy Analysis", "pageDescription" => "", "pageActionsHtml" => "", "content" => $content]);
            return;
        }

        $originRows = [];
        $suggested = [];
        foreach ($byOrigin as $origin => $data) {
            $classification = CspReportService::classifySource($origin);
            if($classification !== "Observed") {
                $suggested[$origin] = $data["count"];
            }
            $badgeClass = $classification === "Likely third-party" ? "label-info" : ($classification === "Unrecognized" ? "label-warning" : "label-default");
            $originRows[] = [
                "origin" => $origin,
                "classification" => $classification,
                "badgeClass" => $badgeClass,
                "directivesList" => implode(", ", array_keys($data["directives"])),
                "count" => $data["count"],
            ];
        }

        $content = TemplateRenderer::render("csp-policy", [
            "errorMessage" => $errorMessage,
            "status" => "ok",
            "originRows" => $originRows,
            "suggested" => array_keys($suggested),
        ]);
        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", ["pageTitle" => "CSP Policy Analysis", "pageDescription" => "", "pageActionsHtml" => "", "content" => $content]);
    }

    private static function originForDisplay(string $uri): string
    {
        if(in_array($uri, ["inline", "eval", "self", ""], true)) {
            return $uri;
        }
        $parts = parse_url($uri);
        if(!$parts || empty($parts["host"])) {
            return $uri;
        }
        $scheme = $parts["scheme"] ?? "";
        return ($scheme ? $scheme . "://" : "") . $parts["host"];
    }

    private function save()
    {
        $collection = isset($_POST["csp_report_collection"]) && $_POST["csp_report_collection"] ? "1" : "0";
        $retentionDays = max(1, min(365, (int) ($_POST["csp_report_retention_days"] ?? 30)));
        $maxRows = max(100, min(200000, (int) ($_POST["csp_report_max_rows"] ?? 5000)));

        $before = [
            "collection" => $this->settings()["collection"],
        ];

        if($collection === "1") {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "csp_report_collection"], ["setting" => "csp_report_collection", "value" => "1"]);
        } else {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->where("setting", "csp_report_collection")->delete();
        }
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "csp_report_retention_days"], ["setting" => "csp_report_retention_days", "value" => (string) $retentionDays]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "csp_report_max_rows"], ["setting" => "csp_report_max_rows", "value" => (string) $maxRows]);

        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("csp.policy.changed", "CSP report collection settings updated.", ["before" => $before, "after" => ["collection" => $collection === "1"]]);
        }

        $_SESSION["nnm_csp_success"] = "Settings saved.";
        redir("module=security_pack&c=cspReports", "addonmodules.php");
    }

    private function clear()
    {
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->delete();
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("csp.report.cleared", "Admin cleared all stored CSP reports.", []);
        }
        $_SESSION["nnm_csp_success"] = "All CSP reports cleared.";
        redir("module=security_pack&c=cspReports", "addonmodules.php");
    }
}
