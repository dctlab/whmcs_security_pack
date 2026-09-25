<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.1 — Security Activity Center.
 *
 * PHASE 3.3 (2026-08-24): migrated to the templates/admin/ presentation
 * layer, same pattern validated on Dashboard (Phase 3.2). The filter
 * parsing, the Capsule query (still fully parameterized — no raw SQL
 * string concatenation of user input), the pagination MATH, and the
 * event-type list are all UNCHANGED here; only the echo-based rendering
 * moved into activity.tpl. Filterable/paginated browser on top of the
 * EXISTING Phase 1 dctlab_security_pack_events table — no second event
 * table, no second logging mechanism.
 */
class ActivityController
{
    private const PER_PAGE = 25;

    private function e($v)
    {
        return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
    }

    public function index($vars = [])
    {
        $type = trim((string) ($_GET["type"] ?? ""));
        $severity = trim((string) ($_GET["severity"] ?? ""));
        $ip = trim((string) ($_GET["ip"] ?? ""));
        $country = trim((string) ($_GET["country"] ?? ""));
        $search = trim((string) ($_GET["q"] ?? ""));
        $dateFrom = trim((string) ($_GET["from"] ?? ""));
        $dateTo = trim((string) ($_GET["to"] ?? ""));
        $page = max(1, (int) ($_GET["p"] ?? 1));

        $query = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events");

        if($type !== "") {
            $query->where("event_type", $type);
        }
        if($severity !== "" && in_array($severity, ["info", "warning", "critical"], true)) {
            $query->where("severity", $severity);
        }
        if($ip !== "") {
            $query->where("ip", "like", "%" . str_replace(["%", "_"], ["\\%", "\\_"], $ip) . "%");
        }
        if($country !== "") {
            $query->where("country_code", strtoupper(substr($country, 0, 2)));
        }
        if($search !== "") {
            $needle = "%" . str_replace(["%", "_"], ["\\%", "\\_"], $search) . "%";
            $query->where(function ($q) use ($needle) {
                $q->where("message", "like", $needle)->orWhere("event_type", "like", $needle);
            });
        }
        if($dateFrom !== "" && strtotime($dateFrom) !== false) {
            $query->where("created_at", ">=", date("Y-m-d 00:00:00", strtotime($dateFrom)));
        }
        if($dateTo !== "" && strtotime($dateTo) !== false) {
            $query->where("created_at", "<=", date("Y-m-d 23:59:59", strtotime($dateTo)));
        }

        $total = (clone $query)->count();
        $totalPages = max(1, (int) ceil($total / self::PER_PAGE));
        $page = min($page, $totalPages);

        $events = $query->orderBy("id", "DESC")->offset(($page - 1) * self::PER_PAGE)->limit(self::PER_PAGE)->get();

        $eventTypes = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")->select("event_type")->distinct()->orderBy("event_type")->pluck("event_type");

        $filters = [
            "type" => $type, "severity" => $severity, "ip" => $ip, "country" => $country,
            "search" => $search, "dateFrom" => $dateFrom, "dateTo" => $dateTo,
        ];

        $content = TemplateRenderer::render("activity", [
            "filters" => $filters,
            "eventTypes" => is_array($eventTypes) ? $eventTypes : $eventTypes->toArray(),
            "events" => $events,
            "total" => $total,
            "paginationLinks" => $this->buildPaginationLinks($page, $totalPages, $filters),
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Security Activity Center",
            "pageDescription" => "Filterable, paginated history of every recorded security event.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /**
     * Same page-window (current +/- 3), same disabled/active rules, and
     * the same query-string shape as the pre-Phase-3 renderPagination()
     * — just returned as data instead of echoed, so the template can
     * render it with security_pack_e() like everything else.
     */
    private function buildPaginationLinks(int $page, int $totalPages, array $filters): array
    {
        if($totalPages <= 1) {
            return [];
        }
        $qs = function ($p) use ($filters) {
            $params = [
                "module" => "security_pack", "c" => "activity", "p" => $p,
                "type" => $filters["type"], "severity" => $filters["severity"], "ip" => $filters["ip"],
                "country" => $filters["country"], "q" => $filters["search"], "from" => $filters["dateFrom"], "to" => $filters["dateTo"],
            ];
            return "?" . http_build_query(array_filter($params, static fn ($v) => $v !== ""));
        };

        $links = [];
        $links[] = ["href" => $qs(max(1, $page - 1)), "label" => "&laquo;", "active" => false, "disabled" => $page <= 1];
        $start = max(1, $page - 3);
        $end = min($totalPages, $page + 3);
        for ($i = $start; $i <= $end; $i++) {
            $links[] = ["href" => $qs($i), "label" => (string) $i, "active" => $i === $page, "disabled" => false];
        }
        $links[] = ["href" => $qs(min($totalPages, $page + 1)), "label" => "&raquo;", "active" => false, "disabled" => $page >= $totalPages];
        return $links;
    }
}
