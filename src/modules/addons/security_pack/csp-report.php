<?php

declare(strict_types=1);

/**
 * Security Pack 2.5 — public CSP violation report collector.
 *
 * This is DELIBERATELY a standalone entry point, not routed through the
 * admin addon-module page (which requires an authenticated admin
 * session) or the client-area page hooks (a session may or may not
 * exist). Browsers submit CSP violation reports automatically via
 * navigator.sendBeacon()/fetch(), for ANY visitor including anonymous
 * guests on the client area — there is no session to authenticate
 * against, the same as any other CSP report-uri target on the web.
 *
 * Every byte read from the request past this point is UNTRUSTED INPUT.
 * Treated accordingly:
 *   - only POST is accepted
 *   - only a CSP-report-shaped content type is accepted
 *   - a hard body-size cap is enforced BEFORE reading the body
 *   - JSON is decoded with json_decode() only (never eval, never
 *     unserialize) and a malformed/non-object payload is rejected
 *   - the collected fields are bounded-length strings only — nothing
 *     here is ever executed, included, or reflected back to the caller
 *   - abusive callers are throttled via the EXISTING RateLimiter service
 *     (no second rate limiter), keyed by IP; on any internal error this
 *     endpoint fails CLOSED (204 with nothing recorded) rather than
 *     risking unbounded writes — the opposite of RateLimiter's own
 *     documented fail-open default, and deliberately so: this table has
 *     an explicit row cap (CspReportService::purge()) but a runaway
 *     write loop between cron runs is still worth refusing outright.
 *   - this endpoint never queries anything by request input other than
 *     the settings row (fixed key) and the rate-limit counter (keyed by
 *     IP, itself validated) — no user-controlled value ever reaches a
 *     WHERE clause here.
 */

// Always respond with an empty, cacheable-looking 204 — never leak
// whether collection is enabled, whether the DB is reachable, or any
// other internal state to the calling browser.
function security_pack_csp_endpoint_finish(int $code): void
{
    http_response_code($code);
    header("Content-Length: 0");
    exit;
}

if(($_SERVER["REQUEST_METHOD"] ?? "") !== "POST") {
    security_pack_csp_endpoint_finish(405);
}

$contentType = strtolower((string) ($_SERVER["CONTENT_TYPE"] ?? ""));
$looksLikeCspReport = strpos($contentType, "application/csp-report") !== false
    || strpos($contentType, "application/json") !== false
    || strpos($contentType, "application/reports+json") !== false;
if(!$looksLikeCspReport) {
    security_pack_csp_endpoint_finish(415);
}

const SECURITY_PACK_CSP_MAX_BODY_BYTES = 16384; // 16 KB — a real CSP report is a few hundred bytes
$declaredLength = (int) ($_SERVER["CONTENT_LENGTH"] ?? 0);
if($declaredLength > SECURITY_PACK_CSP_MAX_BODY_BYTES) {
    security_pack_csp_endpoint_finish(413);
}

$raw = file_get_contents("php://input", false, null, 0, SECURITY_PACK_CSP_MAX_BODY_BYTES + 1);
if($raw === false || $raw === "" || strlen($raw) > SECURITY_PACK_CSP_MAX_BODY_BYTES) {
    security_pack_csp_endpoint_finish(400);
}

$decoded = json_decode($raw, true);
if(!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
    security_pack_csp_endpoint_finish(400);
}

// Bootstrap just enough of WHMCS to reach the database — deliberately
// NOT requiring hooks.php (that would re-register every add_hook()
// callback and re-run its top-level side-effecting blocks, none of
// which belong in a narrow, unauthenticated telemetry endpoint).
$initFile = dirname(__DIR__, 3) . DIRECTORY_SEPARATOR . "init.php";
if(!is_file($initFile)) {
    security_pack_csp_endpoint_finish(204);
}

try {
    require_once $initFile;

    if(!defined("WHMCS")) {
        define("WHMCS", true);
    }
    require_once __DIR__ . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "Security" . DIRECTORY_SEPARATOR . "IpUtil.php";
    require_once __DIR__ . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "Security" . DIRECTORY_SEPARATOR . "RateLimiter.php";
    require_once __DIR__ . DIRECTORY_SEPARATOR . "lib" . DIRECTORY_SEPARATOR . "Security" . DIRECTORY_SEPARATOR . "CspReportService.php";

    // Same settings row every other part of the module reads — a
    // single, minimal, direct query (the same one hooks.php's
    // security_pack_settings() runs) rather than pulling in the whole
    // hooks.php file and its side effects just for this.
    $settingsRaw = \Illuminate\Database\Capsule\Manager::table("nnm_security_pack")->pluck("value", "setting");
    $settings = is_array($settingsRaw) ? $settingsRaw : $settingsRaw->toArray();

    if(empty($settings["csp_report_collection"]) || $settings["csp_report_collection"] === "0") {
        // Collection is an explicit admin opt-in (off by default) — an
        // admin who never turns this on never has this endpoint write
        // anything, even though the file itself is always reachable.
        security_pack_csp_endpoint_finish(204);
    }

    $ip = $_SERVER["REMOTE_ADDR"] ?? "";
    if($ip && !\WHMCS\Module\Addon\Security_Pack\Security\IpUtil::isValidIp((string) $ip)) {
        $ip = "";
    }

    $maxPerWindow = 30;
    $windowSeconds = 60;
    $allowed = $ip !== "" ? \WHMCS\Module\Addon\Security_Pack\Security\RateLimiter::hit("csp_report:" . $ip, $maxPerWindow, $windowSeconds) : true;
    if(!$allowed) {
        security_pack_csp_endpoint_finish(204);
    }

    $normalized = \WHMCS\Module\Addon\Security_Pack\Security\CspReportService::normalizeReport($decoded);
    if($normalized === null) {
        security_pack_csp_endpoint_finish(204);
    }

    $userAgent = (string) ($_SERVER["HTTP_USER_AGENT"] ?? "");
    $referrer = (string) ($_SERVER["HTTP_REFERER"] ?? "");
    \WHMCS\Module\Addon\Security_Pack\Security\CspReportService::record($normalized, $userAgent, $referrer);
} catch (\Throwable $e) {
    // Never surface internal errors (stack traces, DB details) to a
    // public, unauthenticated endpoint.
}

security_pack_csp_endpoint_finish(204);
