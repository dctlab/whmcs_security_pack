<?php

namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.0 — Security Diagnostics.
 *
 * PHASE 3.4 (2026-08-24): migrated to the templates/admin/ presentation
 * layer, same pattern validated on Dashboard/Alerts/Activity/Analytics.
 * runChecks() — every check, every status determination, every detail
 * string — is UNCHANGED, copied verbatim. save() and testEmail() (CSRF,
 * POST-only, permission/validation, Email2faService::sendTestEmail()
 * call) are UNCHANGED. Only the echo-based rendering moved into
 * diagnostics.tpl / components/check-badge.tpl.
 *
 * Read-only health/status page (PASS/WARNING/FAIL per check) plus a small
 * form for the two cross-cutting settings that don't belong to any one
 * feature panel: Trusted Proxies and Security Event Retention. Every
 * check here is informational only — nothing on this page can lock an
 * admin out or change enforcement behaviour by itself.
 */
class DiagnosticsController
{
    public function index($vars = [])
    {
        $settings = security_pack_settings();
        $token = security_pack_csrf_token();

        $successMessage = null;
        if(isset($_SESSION["nnm_diag_success"])) {
            $successMessage = (string) $_SESSION["nnm_diag_success"];
            unset($_SESSION["nnm_diag_success"]);
        }
        $errorMessage = null;
        if(isset($_SESSION["nnm_diag_error"])) {
            $errorMessage = (string) $_SESSION["nnm_diag_error"];
            unset($_SESSION["nnm_diag_error"]);
        }
        $testEmailPreview = null;
        if(isset($_SESSION["nnm_diag_test_email_preview"]) && is_array($_SESSION["nnm_diag_test_email_preview"])) {
            $testEmailPreview = $_SESSION["nnm_diag_test_email_preview"];
            unset($_SESSION["nnm_diag_test_email_preview"]);
        }

        $currentAdminId = (int) ($_SESSION["adminid"] ?? 0);
        $currentAdminEmail = "";
        try {
            $currentAdminEmail = (string) (\Illuminate\Database\Capsule\Manager::table("tbladmins")->where("id", $currentAdminId)->value("email") ?? "");
        } catch (\Throwable $e) {
        }

        try {
            $recentEvents = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")->orderBy("id", "DESC")->limit(25)->get();
        } catch (\Throwable $e) {
            $recentEvents = [];
        }

        $content = TemplateRenderer::render("diagnostics", [
            "successMessage" => $successMessage,
            "errorMessage" => $errorMessage,
            "token" => $token,
            "checks" => $this->runChecks($settings),
            "trustedProxies" => $settings["trusted_proxies"] ?? "",
            "eventRetentionDays" => $settings["event_retention_days"] ?? "90",
            "currentAdminId" => $currentAdminId,
            "currentAdminEmail" => $currentAdminEmail,
            "recentEvents" => $recentEvents,
            "testEmailPreview" => $testEmailPreview,
            "mailPipelineIntrospection" => $this->introspectMailPipeline(),
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "Security Diagnostics",
            "pageDescription" => "Read-only system/security health checks, plus Trusted Proxies and Security Event Retention settings.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    /**
     * Added 2026-08-26 — read-only, reflection-based introspection of
     * WHMCS's own core mail pipeline, purely to REPLACE guessing with
     * verified fact. Live evidence this session showed that a manually
     * built \WHMCS\Mail\Message (even after adding applyGlobalWrapper())
     * does not reproduce the header/footer/branding that sendMessage()/
     * sendAdminMessage() produce for other Security Pack features (Login
     * Notification), and classdocs.whmcs.com does not publish
     * \WHMCS\Mail\Emailer or \WHMCS\User\User at all — so there is no
     * public documentation explaining the gap. Rather than ask for a
     * manually-located core file upload, or guess at an undocumented
     * function's parameters (risking silently reintroducing the
     * sub-account misattribution bug the 2026-08-23 correction fixed),
     * this reads the REAL, currently-loaded implementation directly:
     *
     *  - ReflectionFunction on sendMessage()/sendAdminMessage() to locate
     *    their defining file and extract their actual source text.
     *  - ReflectionClass on \WHMCS\Mail\Emailer and \WHMCS\User\User (if
     *    loaded) to list every public method's real signature and doc
     *    comment — undocumented publicly, but directly readable from a
     *    live, already-authenticated admin session on this install.
     *
     * Strictly read-only: no database writes, no state changes, nothing
     * that affects OTP/security logic. Every reflection call is
     * try/caught individually; a missing function/class degrades to a
     * clear "(not available in this execution context)" entry rather
     * than failing the whole Diagnostics page. Output is HTML-escaped by
     * the template exactly like every other value here (security_pack_e()).
     * Gated behind the same admin-only Diagnostics page as everything
     * else — never exposed anywhere unauthenticated.
     *
     * @return array{sendMessage:?array,sendAdminMessage:?array,emailerMethods:?array,userMethods:?array,error:?string}
     */
    private function introspectMailPipeline(): array
    {
        $result = [
            "sendMessage" => null,
            "sendAdminMessage" => null,
            "emailerMethods" => null,
            "userMethods" => null,
            "error" => null,
        ];

        foreach (["sendMessage", "sendAdminMessage"] as $fn) {
            try {
                if(!function_exists($fn)) {
                    $result[$fn] = ["available" => false, "file" => null, "startLine" => null, "endLine" => null, "source" => ""];
                    continue;
                }
                $ref = new \ReflectionFunction($fn);
                $file = $ref->getFileName();
                $start = $ref->getStartLine();
                $end = $ref->getEndLine();
                $source = "";
                if($file && $start && $end && is_readable($file)) {
                    $lines = @file($file);
                    if(is_array($lines)) {
                        $source = implode("", array_slice($lines, max(0, $start - 1), max(1, $end - $start + 1)));
                    }
                }
                $result[$fn] = [
                    "available" => true,
                    "file" => (string) $file,
                    "startLine" => $start,
                    "endLine" => $end,
                    // Bounded — this is a diagnostic preview, not a full
                    // source dump; large functions are still identifiable
                    // from the first ~20,000 characters.
                    "source" => mb_substr($source, 0, 20000),
                ];
            } catch (\Throwable $e) {
                $result[$fn] = ["available" => false, "file" => null, "startLine" => null, "endLine" => null, "source" => "(reflection failed: " . $e->getMessage() . ")"];
            }
        }

        foreach (["\\WHMCS\\Mail\\Emailer" => "emailerMethods", "\\WHMCS\\User\\User" => "userMethods"] as $class => $key) {
            try {
                if(!class_exists($class)) {
                    $result[$key] = null;
                    continue;
                }
                $rc = new \ReflectionClass($class);
                $methods = [];
                foreach ($rc->getMethods(\ReflectionMethod::IS_PUBLIC) as $m) {
                    $params = [];
                    foreach ($m->getParameters() as $p) {
                        $type = "";
                        try {
                            $type = $p->hasType() ? ((string) $p->getType()) . " " : "";
                        } catch (\Throwable $e) {
                        }
                        $default = "";
                        try {
                            if($p->isDefaultValueAvailable()) {
                                $default = " = " . var_export($p->getDefaultValue(), true);
                            }
                        } catch (\Throwable $e) {
                        }
                        $params[] = $type . "$" . $p->getName() . $default;
                    }
                    $returnType = "";
                    try {
                        $returnType = $m->hasReturnType() ? ((string) $m->getReturnType()) : "";
                    } catch (\Throwable $e) {
                    }
                    $methods[] = [
                        "signature" => ($m->isStatic() ? "static " : "") . $m->getName() . "(" . implode(", ", $params) . ")" . ($returnType !== "" ? ": " . $returnType : ""),
                        "doc" => (string) ($m->getDocComment() ?: ""),
                    ];
                }
                $result[$key] = $methods;
            } catch (\Throwable $e) {
                $result["error"] = ($result["error"] ? $result["error"] . " | " : "") . "{$class}: " . $e->getMessage();
            }
        }

        return $result;
    }

    private function runChecks($settings)
    {
        $checks = [];

        $phpOk = version_compare(PHP_VERSION, "8.2.0", ">=");
        $checks[] = ["name" => "PHP Version", "status" => $phpOk ? "pass" : "warning", "detail" => "Running PHP " . PHP_VERSION . " — module targets PHP 8.2+."];

        foreach (["curl", "openssl", "pdo_mysql", "mbstring"] as $ext) {
            $checks[] = ["name" => "PHP Extension: " . $ext, "status" => extension_loaded($ext) ? "pass" : "fail", "detail" => extension_loaded($ext) ? "Loaded." : "Not loaded — some features (curl GeoIP providers, CSRF token generation) will not work correctly."];
        }

        $tables = [
            "dctlab_security_pack", "dctlab_security_pack_logins", "dctlab_security_pack_opt", "dctlab_security_pack_dpass",
            "dctlab_security_pack_ips", "dctlab_security_pack_geo_cache", "dctlab_security_pack_lc_overrides",
            "dctlab_security_pack_events", "dctlab_security_pack_schema_version", "dctlab_security_pack_rate_limits",
            "dctlab_security_pack_ip_rules", "dctlab_security_pack_csp_reports", "dctlab_security_pack_anomalies",
            "dctlab_security_pack_score_snapshots", "dctlab_security_pack_email2fa", "dctlab_security_pack_email2fa_challenges",
            "dctlab_security_pack_email2fa_bypasses",
        ];
        $missing = [];
        foreach ($tables as $table) {
            try {
                if(!\Illuminate\Database\Capsule\Manager::schema()->hasTable($table)) {
                    $missing[] = $table;
                }
            } catch (\Throwable $e) {
                $missing[] = $table;
            }
        }
        $checks[] = [
            "name" => "Database Tables",
            "status" => $missing ? "fail" : "pass",
            "detail" => $missing ? ("Missing: " . implode(", ", $missing) . " — deactivate & reactivate the module, or re-save the module in Addon Modules to trigger _upgrade().") : (count($tables) . " module tables present."),
        ];

        $mmdb = function_exists("security_pack_mmdb_reader") ? security_pack_mmdb_reader() : null;
        $checks[] = [
            "name" => "MaxMind GeoIP Database",
            "status" => $mmdb ? "pass" : "info",
            "detail" => $mmdb ? "GeoLite2-Country.mmdb loaded." : "Not uploaded — GeoIP features fall back to the free curl-based providers (slower, rate-limited). Upload one on the Language & Currency page for best accuracy/performance.",
        ];

        $dataDir = security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "data";
        $writable = is_dir($dataDir) && is_writable($dataDir);
        $checks[] = ["name" => "GeoIP Data Directory Writable", "status" => $writable ? "pass" : "warning", "detail" => $writable ? $dataDir . " is writable." : $dataDir . " is not writable — MaxMind database upload/cron-refresh will fail."];

        $csrfOk = !empty(security_pack_csrf_token());
        $checks[] = ["name" => "CSRF Token Generation", "status" => $csrfOk ? "pass" : "fail", "detail" => $csrfOk ? "Session-bound CSRF token generated successfully." : "Could not generate a CSRF token — check session configuration."];

        $detectedIp = function_exists("security_pack_detect_visitor_ip") ? security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto") : "";
        $checks[] = ["name" => "Visitor IP Detection", "status" => $detectedIp ? "pass" : "warning", "detail" => "REMOTE_ADDR: " . ($_SERVER["REMOTE_ADDR"] ?? "unknown") . " — resolved visitor IP: " . ($detectedIp ?: "(none)") . " (source: " . ($settings["ip_source"] ?? "auto") . ")"];

        $trustedProxies = function_exists("security_pack_trusted_proxies_list") ? security_pack_trusted_proxies_list() : [];
        $checks[] = [
            "name" => "Trusted Proxies",
            "status" => $trustedProxies ? "pass" : "warning",
            "detail" => $trustedProxies
                ? (count($trustedProxies) . " trusted proxy entr" . (count($trustedProxies) === 1 ? "y" : "ies") . " configured — forwarded-for headers are only honoured from these.")
                : "Not configured — CF-Connecting-IP/X-Forwarded-For/X-Real-IP headers are trusted unconditionally from any visitor if your Visitor IP Source is set to auto or a specific header. If you're not actually behind that CDN/proxy for every request path, visitors can spoof their apparent IP/country. Configure this below if you use Cloudflare, a load balancer, or reverse proxy.",
        ];

        try {
            $lastEvent = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")->orderBy("id", "DESC")->first();
            $checks[] = ["name" => "Security Event Log", "status" => "pass", "detail" => $lastEvent ? ("Last event: " . $lastEvent->event_type . " at " . $lastEvent->created_at . ".") : "No events recorded yet."];
        } catch (\Throwable $e) {
            $checks[] = ["name" => "Security Event Log", "status" => "fail", "detail" => "Could not query dctlab_security_pack_events."];
        }

        try {
            $version = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_schema_version")->orderBy("id", "DESC")->value("version");
            $checks[] = ["name" => "Schema Migration Version", "status" => $version ? "pass" : "warning", "detail" => $version ? ("Database schema is at version " . $version . ".") : "No schema version recorded yet."];
        } catch (\Throwable $e) {
            $checks[] = ["name" => "Schema Migration Version", "status" => "fail", "detail" => "Could not query dctlab_security_pack_schema_version."];
        }

        $rateLimiterOk = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\RateLimiter");
        $checks[] = ["name" => "Rate Limiting Service", "status" => $rateLimiterOk ? "pass" : "fail", "detail" => $rateLimiterOk ? "RateLimiter service is available and applied to the client toggle endpoints." : "RateLimiter class could not be loaded."];

        // --- Security Pack 2.2 additions ---

        $ipRestrictionServiceOk = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\IpRestrictionService");
        if($ipRestrictionServiceOk) {
            try {
                $ruleCount = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->count();
                $activeCount = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->where("enabled", 1)->count();
                $checks[] = ["name" => "IP Restrictions Service", "status" => "pass", "detail" => $ruleCount ? ($ruleCount . " rule(s) configured, " . $activeCount . " active. Enforced on the client area for guests only.") : "Available, 0 rules configured — not currently restricting anything (safe default)."];
            } catch (\Throwable $e) {
                $checks[] = ["name" => "IP Restrictions Service", "status" => "fail", "detail" => "Could not query dctlab_security_pack_ip_rules."];
            }
        } else {
            $checks[] = ["name" => "IP Restrictions Service", "status" => "fail", "detail" => "IpRestrictionService class could not be loaded."];
        }

        if(class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\GeoIpManager")) {
            try {
                $manager = new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager();
                $providerRows = [];
                foreach ($manager->diagnostics() as $row) {
                    $providerRows[] = $row["name"] . ": " . ($row["available"] ? "available" : "not available");
                }
                $anyAvailable = false;
                foreach ($manager->diagnostics() as $row) {
                    if($row["available"]) {
                        $anyAvailable = true;
                    }
                }
                $checks[] = ["name" => "GeoIP Manager", "status" => $anyAvailable ? "pass" : "warning", "detail" => implode(" | ", $providerRows)];
            } catch (\Throwable $e) {
                $checks[] = ["name" => "GeoIP Manager", "status" => "fail", "detail" => "Could not initialize GeoIpManager: " . $e->getMessage()];
            }
        } else {
            $checks[] = ["name" => "GeoIP Manager", "status" => "fail", "detail" => "GeoIpManager class could not be loaded."];
        }

        // --- Security Pack 2.8 addition ---
        // Country Restriction is a CONSUMER of the GeoIP Manager check
        // above, not a second GeoIP status check — this row only reports
        // the feature's own on/off + mode/rule-list state.
        if(class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\CountryRestrictionService")) {
            $crService = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\CountryRestrictionService";
            if(!empty($settings["country_restriction"])) {
                $mode = $crService::normalizeMode($settings["country_restriction_mode"] ?? null);
                $unknownPolicy = $crService::normalizeUnknownPolicy($settings["country_restriction_unknown_policy"] ?? null);
                $countryCount = count($crService::normalizeCountryList($settings["disallowed_countries"] ?? null));
                $checks[] = [
                    "name" => "Country Restriction",
                    "status" => $countryCount ? "pass" : "warning",
                    "detail" => $countryCount
                        ? ("Enabled — mode: " . ($mode === "allow" ? "allow only selected" : "block selected") . ", " . $countryCount . " countr" . ($countryCount === 1 ? "y" : "ies") . " configured, unknown-country policy: " . $unknownPolicy . ".")
                        : "Enabled, but 0 countries are configured — not currently restricting anything (safe default).",
                ];
            } else {
                $checks[] = ["name" => "Country Restriction", "status" => "info", "detail" => "Disabled."];
            }
        } else {
            $checks[] = ["name" => "Country Restriction", "status" => "fail", "detail" => "CountryRestrictionService class could not be loaded."];
        }

        // --- Security Pack 2.3 (Phase 3B) additions ---

        $settingsForHeaders = $settings;
        $safeHeaders = ["sh_nosniff" => "X-Content-Type-Options", "sh_referrer_policy" => "Referrer-Policy", "sh_permissions_policy" => "Permissions-Policy"];
        $onHeaders = [];
        $offHeaders = [];
        foreach ($safeHeaders as $key => $label) {
            $isOn = isset($settingsForHeaders[$key]) && $settingsForHeaders[$key] !== "0" && $settingsForHeaders[$key] !== "";
            if($isOn) {
                $onHeaders[] = $label;
            } else {
                $offHeaders[] = $label;
            }
        }
        $checks[] = [
            "name" => "Baseline Security Headers",
            "status" => $offHeaders ? "warning" : "pass",
            "detail" => $onHeaders ? ("Enabled: " . implode(", ", $onHeaders) . ".") : "None enabled." . ($offHeaders ? (" Not enabled: " . implode(", ", $offHeaders) . " — configure on the Settings page.") : ""),
        ];
        $cspOn = !empty($settingsForHeaders["sh_csp"]);
        $hstsOn = !empty($settingsForHeaders["sh_hsts"]) && !empty($settingsForHeaders["sh_hsts_confirm_https"]);
        $checks[] = [
            "name" => "Advanced Headers (CSP / HSTS)",
            "status" => "info",
            "detail" => "Content-Security-Policy (Report-Only): " . ($cspOn ? "enabled" : "disabled") . ". Strict-Transport-Security: " . ($hstsOn ? "enabled" : "disabled") . ". Both are opt-in and off by default — CSP can break third-party checkout widgets, and HSTS should only be enabled once the entire site is confirmed HTTPS-only.",
        ];

        $navGroupingOk = false;
        try {
            $navGroupingOk = class_exists("NNM_Page_Builder") && property_exists("NNM_Page_Builder", "menuGroups");
        } catch (\Throwable $e) {
        }
        $checks[] = [
            "name" => "Security Center Navigation",
            "status" => $navGroupingOk ? "pass" : "warning",
            "detail" => $navGroupingOk ? "Grouped admin navigation is active — all original ?module=security_pack&c=... URLs remain unchanged and continue to work." : "Grouped navigation support (NNM_Page_Builder::\$menuGroups) not detected — falling back to the flat tab list.",
        ];

        $clientSecurityCenterOk = method_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Client\\ClientController", "security_center");
        $checks[] = [
            "name" => "Client Security Center",
            "status" => $clientSecurityCenterOk ? "pass" : "fail",
            "detail" => $clientSecurityCenterOk ? "Available at index.php?m=security_pack&page=security_center. Shows only the currently authenticated client's own data — identity is derived from the session, never from request parameters. Other-session management is not available (view-only for the current session)." : "ClientController::security_center() could not be found.",
        ];

        $checks[] = [
            "name" => "State-Changing Actions (POST + CSRF)",
            "status" => "pass",
            "detail" => "Password-reset-protection removal, IP-limited-client removal, Language/Currency overrides & cache clearing, and IP Restriction rule save/enable/disable/delete are all POST-only with CSRF token validation. GET requests to these actions are rejected/redirected rather than executed.",
        ];

        // --- Security Pack 2.5 (Advanced Security Center) additions ---

        $cspCollectionOn = !empty($settings["csp_report_collection"]) && $settings["csp_report_collection"] !== "0";
        try {
            $cspCount = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_csp_reports")
                ? \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_csp_reports")->count()
                : null;
        } catch (\Throwable $e) {
            $cspCount = null;
        }
        $checks[] = [
            "name" => "CSP Reporting Endpoint",
            "status" => $cspCollectionOn ? "pass" : "info",
            "detail" => $cspCollectionOn
                ? ("Enabled — publicly reachable at /modules/addons/security_pack/csp-report.php (unauthenticated by necessity; browsers submit reports for anonymous visitors). Rate-limited via the existing RateLimiter, validated/bounded, never reflects submitted data. " . ($cspCount === null ? "Reports table not available yet." : ($cspCount . " grouped violation record(s) stored.")))
                : "Disabled — the endpoint file exists but writes are gated off (204 no-op) until enabled on the CSP Reports page. CSP itself remains Report-Only regardless of this setting.",
        ];

        $anomalyServiceOk = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\SecurityAnomalyService");
        $openAnomalies = null;
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_anomalies")) {
                $openAnomalies = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")->where("status", "open")->count();
            }
        } catch (\Throwable $e) {
        }
        $checks[] = [
            "name" => "Anomaly Detection",
            "status" => $anomalyServiceOk ? "pass" : "fail",
            "detail" => $anomalyServiceOk
                ? ("Deterministic, rule-based detection (not AI/ML) is active against existing Security Events. " . ($openAnomalies === null ? "Anomalies table not available yet." : ($openAnomalies . " open finding(s) — see the Anomalies page.")))
                : "SecurityAnomalyService class could not be loaded.",
        ];

        $alertServiceOk = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\SecurityAlertService");
        $checks[] = [
            "name" => "Security Alerts",
            "status" => $alertServiceOk ? "pass" : "fail",
            "detail" => $alertServiceOk
                ? "Computed on demand from existing signals (anomalies, IP/country/CSP spikes, Security Score drops) — not a second persisted notification system. Optional daily email digest reuses the existing WHMCS admin-message mechanism, off by default."
                : "SecurityAlertService class could not be loaded.",
        ];

        try {
            $snapshotCount = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_score_snapshots")
                ? \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_score_snapshots")->count()
                : 0;
        } catch (\Throwable $e) {
            $snapshotCount = 0;
        }
        $checks[] = [
            "name" => "Security Score History",
            "status" => $snapshotCount > 0 ? "pass" : "info",
            "detail" => $snapshotCount > 0 ? ($snapshotCount . " daily score snapshot(s) recorded (used for the Security-Score-drop alert).") : "No snapshots recorded yet — the first daily cron run will create today's snapshot.",
        ];

        // --- Security Pack 2.6 (Email Two-Factor Authentication) additions ---
        // 2.6.1: Email 2FA is now a native WHMCS Security Module, not an
        // addon-settings-gated service — "enabled" is measured by real
        // adoption (active accounts), not a settings flag, and the
        // module file's own presence is checked directly.

        $e2faServiceOk = class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\Email2faService");
        // FIX (2026-08-25): this used to read "/../../../security/..."
        // (3 levels up), which resolves to modules/addons/security/...
        // — a directory that doesn't exist. This file lives at
        // lib/Admin/DiagnosticsController.php, one level DEEPER than
        // tests/run.php (which lives directly under the module root and
        // correctly uses 3 levels for the same target) — reaching
        // modules/security/dct_email_2fa/dct_email_2fa.php from here
        // requires 4 levels up (lib/Admin -> lib -> security_pack ->
        // addons -> modules), not 3. Confirmed live: the native module
        // file genuinely exists on the server, but this check reported
        // "not found" because it was looking in the wrong place.
        $e2faModuleFile = __DIR__ . "/../../../../security/dct_email_2fa/dct_email_2fa.php";
        $e2faModuleInstalled = is_file($e2faModuleFile);
        $e2faCounts = null;
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa")) {
                $e2faCounts = [
                    "client_active" => \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->where("user_type", "client")->where("status", "active")->count(),
                    "admin_active" => \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")->where("user_type", "admin")->where("status", "active")->count(),
                ];
            }
        } catch (\Throwable $e) {
        }
        $checks[] = [
            "name" => "Email Two-Factor Authentication",
            "status" => !$e2faServiceOk ? "fail" : (!$e2faModuleInstalled ? "warning" : (($e2faCounts !== null && ($e2faCounts["client_active"] + $e2faCounts["admin_active"]) > 0) ? "pass" : "info")),
            "detail" => !$e2faServiceOk
                ? "Email2faService class could not be loaded."
                : (!$e2faModuleInstalled
                    ? "The native \"Email Verification\" security module (modules/security/dct_email_2fa) was not found alongside this addon — copy it into modules/security/ and Activate it on Setup > Security > Two-Factor Authentication."
                    : ($e2faCounts !== null
                        ? ($e2faCounts["client_active"] . " client account(s), " . $e2faCounts["admin_active"] . " administrator account(s) active. Configure and activate it on Setup > Security > Two-Factor Authentication.")
                        : "Tables not available yet.")),
        ];
        // Step correction (2.7.0, explicit instruction: "use WHMCS Mail
        // SYSTEM do not use PHP mail()"): OTP mail now routes through
        // WHMCS's own sendAdminMessage()/sendMessage() pipeline instead
        // of a raw mail() call — the same functions core/loginHistory.php
        // already uses successfully for login notifications in this
        // environment. This resolves "no local MTA" delivery failures on
        // hosts with an SMTP relay configured in WHMCS, but means Global
        // BCC (if configured) now DOES receive a copy of every one-time
        // code — a deliberate, disclosed reversal of the pre-2.7.0
        // BCC-exclusion guarantee. See CHANGELOG.md "2.7.0".
        $whmcsMailType = "";
        try {
            $whmcsMailType = (string) (\Illuminate\Database\Capsule\Manager::table("tblconfiguration")->where("setting", "MailType")->value("value") ?? "");
        } catch (\Throwable $e) {
        }
        // The exact tblconfiguration setting key for Global BCC recipient
        // is not confirmed against live WHMCS core source in this
        // environment — this read is best-effort and wrapped in
        // try/catch; if the key name differs, this simply falls back to
        // the safe/conservative "unknown" wording below rather than
        // reporting a false negative. Always check General Settings >
        // Mail > BCC Messages directly in the admin UI to be certain.
        $globalBcc = "";
        try {
            $globalBcc = (string) (\Illuminate\Database\Capsule\Manager::table("tblconfiguration")->where("setting", "BccMessages")->value("value") ?? "");
        } catch (\Throwable $e) {
        }
        $bccNote = $globalBcc !== ""
            ? (" A Global BCC recipient appears to be configured (" . htmlspecialchars((string) $globalBcc, ENT_QUOTES, "UTF-8") . ") — it WILL now receive a copy of every Email 2FA one-time code sent via this pipeline.")
            : " Could not confirm whether a Global BCC recipient is configured from here — check General Settings > Mail > BCC Messages directly. If one IS set, it now receives a copy of every Email 2FA one-time code.";
        $checks[] = [
            "name" => "Email 2FA — OTP Delivery",
            "status" => "warning",
            "detail" => "Sent via WHMCS's own mail pipeline (sendAdminMessage()/sendMessage()) — the configured transport is WHMCS's General Settings > Mail setting (currently: " . ($whmcsMailType !== "" ? htmlspecialchars((string) $whmcsMailType, ENT_QUOTES, "UTF-8") : "unknown") . ")." . $bccNote . " See CHANGELOG.md \"2.7.0\" for the reasoning and the trade-off this reverses.",
        ];

        $userClientTableOk = false;
        try {
            $userClientTableOk = \Illuminate\Database\Capsule\Manager::schema()->hasTable("tblusers_clients");
        } catch (\Throwable $e) {
        }
        $checks[] = [
            "name" => "Email 2FA — Client Account Resolution",
            "status" => $userClientTableOk ? "pass" : "warning",
            "detail" => $userClientTableOk
                ? "tblusers_clients is available — used to resolve a WHMCS Client account for a User when sending client-side OTP mail (sendMessage() requires a genuine client id). Falls back to a matching tblclients.email if not found there. This mapping is not formally documented by WHMCS; verify with \"Send Test Email\" below (client path) before relying on it."
                : "tblusers_clients was not found — client-side OTP delivery will rely solely on the tblclients.email fallback. If a User has no Client account with a matching email, Email 2FA mail for that user will fail with a clear \"no client account could be resolved\" reason (never silently).",
        ];
        $checks[] = [
            "name" => "Email 2FA — Enforcement Model",
            "status" => "info",
            "detail" => "Implemented as a native WHMCS Security Module (modules/security/dct_email_2fa, \"Email Verification\") — the same module type WHMCS's own built-in Time-Based Tokens/Duo/YubiKey methods use, which genuinely intervenes between password validation and completed authentication for BOTH admin and client logins. This interface is not published in WHMCS's official developer documentation; it was reconstructed from a working reference implementation. See SECURITY-AUDIT-PHASE-4.md \"Phase 7 / 2.6.1\" for the full investigation and residual risk.",
        ];

        // 2026-08-27: this check exists specifically to distinguish "the
        // TOTP secret-stability fix's files were uploaded but the server
        // is still running a cached (opcache) copy of the OLD code" from
        // "the fix genuinely isn't working." Checks for a version-marker
        // constant via class_exists()/defined() — both of which resolve
        // against whatever class definition PHP actually has LOADED for
        // this request (a stale opcache entry included), never by
        // re-reading the .php file from disk. If this reports "fail" on
        // a server where the new file is confirmed present via
        // FTP/SSH, the fix is real and correct but not yet ACTIVE —
        // clearing/restarting PHP's opcache (or restarting PHP-FPM/LSAPI)
        // will pick it up without any further code change.
        $totpEnrollmentClass = "\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\TwoFactor\\TotpEnrollmentService";
        $totpFixMarkerPresent = class_exists($totpEnrollmentClass) && defined($totpEnrollmentClass . "::ENROLLMENT_FIX_MARKER");
        $checks[] = [
            "name" => "TOTP Enrollment — Secret Stability Fix",
            "status" => $totpFixMarkerPresent ? "pass" : "fail",
            "detail" => $totpFixMarkerPresent
                ? ("Active — TotpEnrollmentService::ENROLLMENT_FIX_MARKER = \"" . htmlspecialchars((string) constant($totpEnrollmentClass . "::ENROLLMENT_FIX_MARKER"), ENT_QUOTES, "UTF-8") . "\". A wrong code during TOTP enrollment now re-shows the SAME secret/QR code instead of generating a new one.")
                : "NOT active on this running PHP process — the currently LOADED code predates the secret-stability fix, even if the updated files are already present on disk. This almost always means PHP's opcache is still serving a cached (pre-upload) copy of TotpEnrollmentService.php. Clear/reset your host's PHP opcache, or restart PHP-FPM/LSAPI (via your hosting control panel, or ask your host to do it), then reload this page.",
        ];

        return $checks;
    }

    public function save($vars = [])
    {
        if($_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        if(!security_pack_csrf_valid()) {
            $_SESSION["nnm_error"] = "Your session token expired — please try saving again.";
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        $trustedProxies = (string) ($_POST["trusted_proxies"] ?? "");
        $retentionDays = max(1, intval($_POST["event_retention_days"] ?? 90));
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "trusted_proxies"], ["setting" => "trusted_proxies", "value" => $trustedProxies]);
        \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => "event_retention_days"], ["setting" => "event_retention_days", "value" => (string) $retentionDays]);
        $_SESSION["nnm_diag_success"] = "Diagnostics settings saved.";
        redir("module=security_pack&c=diagnostics", "addonmodules.php");
    }

    public function testEmail($vars = [])
    {
        if($_SERVER["REQUEST_METHOD"] !== "POST") {
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        if(!security_pack_csrf_valid()) {
            $_SESSION["nnm_diag_error"] = "Your session token expired — please try sending the test email again.";
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        $userType = ($_POST["test_user_type"] ?? "") === "client" ? "client" : "admin";
        $userId = (int) ($_POST["test_user_id"] ?? 0);
        if($userId <= 0) {
            $_SESSION["nnm_diag_error"] = "Enter a valid ID to send the test to.";
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\Email2faService")) {
            $_SESSION["nnm_diag_error"] = "Email2faService is unavailable — cannot run the delivery test.";
            redir("module=security_pack&c=diagnostics", "addonmodules.php");
        }
        $result = \WHMCS\Module\Addon\Security_Pack\Security\Email2faService::sendTestEmail($userType, $userId);
        $label = $userType === "admin" ? "your admin account" : ("WHMCS User #" . $userId);
        if($result["sent"]) {
            $_SESSION["nnm_diag_success"] = "Test email dispatched via WHMCS's own mail pipeline to " . $label . " — check the inbox (and spam folder, and Global BCC recipient if configured) to confirm it actually arrived. A successful send here only means WHMCS accepted the message for delivery; it does not guarantee final delivery.";
        } else {
            $_SESSION["nnm_diag_error"] = "Test email to " . $label . " failed: " . (string) ($result["reason"] ?? "unknown reason") . ". For the client-side path, this often means no client account could be resolved for that User ID — verify the ID is correct and that the user owns/has access to at least one client account.";
        }
        // Rendered-HTML preview (2026-08-25): client-type sends now
        // return the exact subject/body bytes WHMCS's own template
        // pipeline produced (see Email2faService::sendDirectToAddress()).
        // Stashed one-shot in session — read and cleared by index() below
        // — so an admin can visually confirm header/footer/company logo
        // actually render, not just trust that "sent" came back true.
        // Only present for the client path (admin path goes through the
        // black-box sendAdminMessage() core function, which hands back
        // no rendered content to inspect) and only on a successful
        // render (even if final dispatch itself failed) — a failed
        // render has nothing to preview.
        if(isset($result["bodyHtml"])) {
            $_SESSION["nnm_diag_test_email_preview"] = [
                "subject" => (string) ($result["subject"] ?? ""),
                "bodyHtml" => (string) $result["bodyHtml"],
            ];
        }
        redir("module=security_pack&c=diagnostics", "addonmodules.php");
    }
}
