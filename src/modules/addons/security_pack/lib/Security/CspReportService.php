<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.5 — CSP violation report handling.
 *
 * normalizeReport()/groupingKey()/classifySource() are pure, DB-free
 * functions (testable without a database). record()/purge()/stats() are
 * the DB-backed wrappers used by the public collection endpoint
 * (csp-report.php) and the admin CspReportsController.
 *
 * CSP reports are UNTRUSTED INPUT from any visitor's browser — every
 * value here is treated that way: bounded lengths, no execution, no
 * reflection back into any context without escaping by the caller.
 */
class CspReportService
{
    private const MAX_FIELD_LENGTH = 500;

    /**
     * Extracts and bounds-checks the handful of fields this module
     * stores from a raw decoded CSP report body. Accepts either the
     * classic `{"csp-report": {...}}` shape (report-uri) or the modern
     * Reporting API array-of-reports shape (report-to) with
     * `body.blockedURL` naming. Returns null if the payload doesn't look
     * like a CSP report at all (missing every recognized field).
     */
    public static function normalizeReport($decoded): ?array
    {
        if(!is_array($decoded)) {
            return null;
        }

        // report-uri classic shape: {"csp-report": {...}}
        $inner = null;
        if(isset($decoded["csp-report"]) && is_array($decoded["csp-report"])) {
            $inner = $decoded["csp-report"];
        } elseif(isset($decoded["body"]) && is_array($decoded["body"]) && (isset($decoded["type"]) ? $decoded["type"] === "csp-violation" : true)) {
            // Reporting API shape: [{"type":"csp-violation","body":{...}}]
            $inner = $decoded["body"];
        } elseif(isset($decoded[0]) && is_array($decoded[0])) {
            // Array-wrapped Reporting API payload — take the first report.
            return self::normalizeReport($decoded[0]);
        } else {
            $inner = $decoded;
        }

        $get = static function (array $arr, array $keys) {
            foreach ($keys as $k) {
                if(isset($arr[$k]) && is_scalar($arr[$k]) && (string) $arr[$k] !== "") {
                    return (string) $arr[$k];
                }
            }
            return null;
        };
        $trim = static function (?string $v) {
            return $v === null ? null : mb_substr(trim($v), 0, self::MAX_FIELD_LENGTH);
        };

        $violatedDirective = $trim($get($inner, ["violated-directive", "violatedDirective"]));
        $effectiveDirective = $trim($get($inner, ["effective-directive", "effectiveDirective"]));
        $blockedUri = $trim($get($inner, ["blocked-uri", "blockedURL", "blockedUri"]));
        $documentUri = $trim($get($inner, ["document-uri", "documentURL", "documentUri"]));
        $sourceFile = $trim($get($inner, ["source-file", "sourceFile"]));
        $disposition = $trim($get($inner, ["disposition"]));
        $lineRaw = $get($inner, ["line-number", "lineNumber"]);
        $columnRaw = $get($inner, ["column-number", "columnNumber"]);

        if($violatedDirective === null && $effectiveDirective === null && $blockedUri === null) {
            // Doesn't look like a CSP report at all — nothing recognizable.
            return null;
        }

        return [
            "violated_directive" => $violatedDirective,
            "effective_directive" => $effectiveDirective ?: $violatedDirective,
            "blocked_uri" => $blockedUri,
            "document_uri" => $documentUri,
            "source_file" => $sourceFile,
            "line_number" => ctype_digit((string) $lineRaw) ? (int) $lineRaw : null,
            "column_number" => ctype_digit((string) $columnRaw) ? (int) $columnRaw : null,
            "disposition" => in_array($disposition, ["enforce", "report"], true) ? $disposition : null,
        ];
    }

    /**
     * Deterministic grouping key for "the same violation shape" — the
     * directive plus the blocked resource's origin (scheme+host, not the
     * full path/query, which is often unique per request and would
     * otherwise defeat grouping) plus the source file. Two reports with
     * identical inputs always produce the same key; that's the whole
     * point (bounded storage via occurrence_count instead of one row per
     * report).
     */
    public static function groupingKey(array $normalized): string
    {
        $origin = self::originOf((string) ($normalized["blocked_uri"] ?? ""));
        $parts = [
            (string) ($normalized["effective_directive"] ?? $normalized["violated_directive"] ?? ""),
            $origin,
            (string) ($normalized["source_file"] ?? ""),
        ];
        return hash("sha256", implode("|", $parts));
    }

    private static function originOf(string $uri): string
    {
        if($uri === "" || in_array($uri, ["inline", "eval", "self", "about", "data"], true)) {
            return $uri;
        }
        $parts = parse_url($uri);
        if(!$parts || empty($parts["host"])) {
            return $uri; // e.g. "inline", "data:...", or unparsable — keep as-is, still deterministic
        }
        $scheme = $parts["scheme"] ?? "";
        return ($scheme ? $scheme . "://" : "") . $parts["host"];
    }

    /**
     * Conservative, non-authoritative classification for Policy Analysis
     * — deliberately uses hedged terminology ("Observed", "Unrecognized",
     * "Likely third-party") rather than a security verdict. Never labels
     * anything "safe".
     */
    public static function classifySource(string $blockedUri, ?array $currentPolicySources = null): string
    {
        $origin = self::originOf($blockedUri);
        if(in_array($origin, ["inline", "eval", "self", ""], true)) {
            return "Observed";
        }
        if(is_array($currentPolicySources) && in_array($origin, $currentPolicySources, true)) {
            return "Observed";
        }
        $knownThirdPartyHints = ["google", "gstatic", "googleapis", "facebook", "cloudflare", "cdn", "stripe", "paypal", "recaptcha", "analytics", "sentry", "jsdelivr", "cdnjs"];
        foreach ($knownThirdPartyHints as $hint) {
            if(stripos($origin, $hint) !== false) {
                return "Likely third-party";
            }
        }
        return "Unrecognized";
    }

    /**
     * Records one (already-normalized) report — inserts a new grouped
     * row or increments occurrence_count/last_seen on an existing one.
     * Never throws; a DB error here must not break the public endpoint's
     * response.
     */
    public static function record(array $normalized, string $userAgent, string $referrer): bool
    {
        try {
            $key = self::groupingKey($normalized);
            $now = date("Y-m-d H:i:s");
            $existing = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->where("group_key", $key)->first();
            if($existing) {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->where("id", $existing->id)->update([
                    "occurrence_count" => $existing->occurrence_count + 1,
                    "last_seen" => $now,
                ]);
                return true;
            }
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->insert([
                "group_key" => $key,
                "violated_directive" => $normalized["violated_directive"],
                "effective_directive" => $normalized["effective_directive"],
                "blocked_uri" => $normalized["blocked_uri"],
                "document_uri" => $normalized["document_uri"],
                "source_file" => $normalized["source_file"],
                "line_number" => $normalized["line_number"],
                "column_number" => $normalized["column_number"],
                "disposition" => $normalized["disposition"],
                "sample_user_agent" => mb_substr($userAgent, 0, 300),
                "sample_referrer" => mb_substr($referrer, 0, 500),
                "occurrence_count" => 1,
                "first_seen" => $now,
                "last_seen" => $now,
            ]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Retention + max-row bounding — called from DailyCronJob. Deletes
     * rows past the retention window, then (if still over the configured
     * row cap) deletes the oldest-by-last_seen rows until under the cap.
     * Never TRUNCATEs — always a bounded, criteria-based DELETE.
     */
    public static function purge(int $retentionDays, int $maxRows): void
    {
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                ->where("last_seen", "<", date("Y-m-d H:i:s", time() - (max(1, $retentionDays) * 86400)))
                ->delete();

            $total = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->count();
            $maxRows = max(100, $maxRows);
            if($total > $maxRows) {
                $excess = $total - $maxRows;
                $oldestIds = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")
                    ->orderBy("last_seen", "ASC")
                    ->limit($excess)
                    ->pluck("id");
                if(count($oldestIds)) {
                    \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->whereIn("id", $oldestIds)->delete();
                }
            }
        } catch (\Throwable $e) {
        }
    }
}
