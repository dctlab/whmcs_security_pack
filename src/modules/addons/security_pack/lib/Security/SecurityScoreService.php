<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.1 — Security Score Service.
 *
 * Computes a deterministic, explainable 0-100 security score from the
 * module's actual configuration + a small set of environment "facts"
 * (GeoIP DB loaded, tables present, etc). Nothing here is hard-coded or
 * random — the same $settings/$facts input always produces the same
 * score, which is what makes it unit-testable (see tests/ScoreServiceTest.php)
 * without touching a live database.
 *
 * compute() is a pure function: all state is passed in via $settings and
 * $facts rather than read from globals, so tests can exercise it with
 * synthetic input. gatherFacts() is the one place that actually talks to
 * the database/filesystem for real admin page use.
 */
class SecurityScoreService
{
    /**
     * @param array $settings the security_pack_settings() array
     * @param array $facts    ["geoip_loaded"=>bool, "tables_ok"=>bool,
     *                          "data_dir_writable"=>bool, "events_last_7d"=>int]
     * @return array{score:int,max:int,categories:array,recommendations:array}
     */
    public static function compute(array $settings, array $facts): array
    {
        $on = static function ($key) use ($settings) {
            return isset($settings[$key]) && $settings[$key] !== "0" && $settings[$key] !== "";
        };

        $categories = [];
        $recommendations = [];

        // --- Authentication (15) ---
        $authEarned = 0;
        $authEarned += $on("login_notification") ? 5 : 0;
        if(!$on("login_notification")) {
            $recommendations[] = self::rec("warning", "Client login notifications are disabled.", "Enable Client Login Notification", "?module=security_pack&c=settings", "authentication");
        }
        $authEarned += $on("admin_login_notification") ? 5 : 0;
        if(!$on("admin_login_notification")) {
            $recommendations[] = self::rec("warning", "Admin login notifications are disabled.", "Enable Admin Login Notification", "?module=security_pack&c=settings", "authentication");
        }
        // Security Pack 2.6.1 — Email 2FA is now a native WHMCS Security
        // Module (modules/security/dct_email_2fa), activated/configured
        // on Setup > Security > Two-Factor Authentication rather than
        // via an addon setting this service can read — so "is the
        // service on" is no longer a settings flag. It is instead
        // measured the same way real adoption always was here: whether
        // any account (client or admin) actually has it ACTIVE (Step
        // 78: never award points for a feature being switched on
        // globally with no real usage — there is no longer even a
        // global switch to check, only real per-account adoption).
        $email2faAnyActive = (int) ($facts["email2fa_any_active_count"] ?? 0);
        $authEarned += $email2faAnyActive > 0 ? 5 : 0;
        if($email2faAnyActive === 0) {
            $recommendations[] = self::rec("info", "Email Two-Factor Authentication is not active for any account yet.", "Configure Email 2FA", "?module=security_pack&c=email2fa", "authentication");
        }
        $adminEmail2faActive = (int) ($facts["admin_email2fa_active_count"] ?? 0);
        $authEarned += $adminEmail2faActive > 0 ? 5 : 0;
        if($email2faAnyActive > 0 && $adminEmail2faActive === 0) {
            $recommendations[] = self::rec("warning", "No administrator account has Email Two-Factor Authentication active yet — admin accounts are the highest-value target.", "Review Email 2FA", "?module=security_pack&c=email2fa", "authentication");
        }
        $categories["Authentication"] = ["earned" => $authEarned, "max" => 20];

        // --- Login Protection (15) ---
        $loginEarned = 0;
        $loginEarned += $on("login_history") ? 5 : 0;
        $loginEarned += $on("ip_range_limits") ? 5 : 0;
        $loginEarned += $on("password_reset") ? 5 : 0;
        if(!$on("login_history")) {
            $recommendations[] = self::rec("info", "Login history tracking is disabled.", "Enable Login History", "?module=security_pack&c=settings", "login_protection");
        }
        $categories["Login Protection"] = ["earned" => $loginEarned, "max" => 15];

        // --- IP Protection (15) ---
        $ipEarned = 0;
        $trustedProxiesConfigured = !empty(trim((string) ($settings["trusted_proxies"] ?? "")));
        $ipEarned += $trustedProxiesConfigured ? 10 : 0;
        if(!$trustedProxiesConfigured) {
            $recommendations[] = self::rec("warning", "Trusted Proxies are not configured.", "Configure Trusted Proxies", "?module=security_pack&c=diagnostics", "ip_protection");
        }
        $ipEarned += $on("ip_range_limits") ? 5 : 0;
        $categories["IP Protection"] = ["earned" => $ipEarned, "max" => 15];

        // --- Geo Protection (15) ---
        $geoEarned = 0;
        $geoFeatureOn = $on("lang_currency") || $on("country_restriction");
        $geoEarned += $geoFeatureOn ? 10 : 0;
        $geoEarned += !empty($facts["geoip_loaded"]) ? 5 : 0;
        if($geoFeatureOn && empty($facts["geoip_loaded"])) {
            $recommendations[] = self::rec("info", "No MaxMind GeoIP database uploaded — GeoIP features are falling back to slower/rate-limited free providers.", "Upload a GeoIP Database", "?module=security_pack&c=langCurrency", "geo_protection");
        } elseif(!$geoFeatureOn) {
            $recommendations[] = self::rec("info", "GeoIP protection (Country Restriction / Language & Currency) is not enabled.", "Review GeoIP Protection", "?module=security_pack&c=langCurrency", "geo_protection");
        } else {
            $recommendations[] = self::rec("pass", "GeoIP protection is configured correctly.", "", "?module=security_pack&c=langCurrency", "geo_protection");
        }
        // Security Pack 2.8: Country Restriction being ON with zero
        // countries configured is a safe no-op (never treated as a
        // scoring penalty — it's not a security regression, just an
        // incomplete setup), but it IS worth surfacing so an admin who
        // enabled the feature and forgot to add rules notices.
        if($on("country_restriction") && class_exists(__NAMESPACE__ . "\\CountryRestrictionService") && empty(CountryRestrictionService::normalizeCountryList($settings["disallowed_countries"] ?? null))) {
            $recommendations[] = self::rec("info", "Country Restriction is enabled but no countries are configured yet — it isn't restricting anything.", "Configure Country Restriction", "?module=security_pack&c=countryRestriction", "geo_protection");
        }
        $categories["Geo Protection"] = ["earned" => $geoEarned, "max" => 15];

        // --- Account Protection (10) ---
        $acctEarned = 0;
        $acctEarned += $on("block_free_emails") ? 5 : 0;
        $acctEarned += $on("password_reset") ? 5 : 0;
        $categories["Account Protection"] = ["earned" => $acctEarned, "max" => 10];

        // --- Notifications (10) ---
        $notifEarned = 0;
        $notifEarned += $on("allow_disable_notification") ? 5 : 0;
        $notifEarned += ($on("login_notification") && $on("admin_login_notification")) ? 5 : 0;
        $categories["Notifications"] = ["earned" => $notifEarned, "max" => 10];

        // --- Configuration / System Health (10) ---
        $sysEarned = 0;
        $sysEarned += !empty($facts["tables_ok"]) ? 5 : 0;
        $sysEarned += !empty($facts["data_dir_writable"]) ? 5 : 0;
        if(empty($facts["tables_ok"])) {
            $recommendations[] = self::rec("critical", "One or more DCTLAB Security Pack database tables are missing.", "Open Security Diagnostics", "?module=security_pack&c=diagnostics", "system_health");
        }
        $categories["System Health"] = ["earned" => $sysEarned, "max" => 10];

        // --- Event Coverage (10) ---
        $eventEarned = 0;
        $eventsLast7d = (int) ($facts["events_last_7d"] ?? 0);
        $eventEarned += $eventsLast7d > 0 ? 5 : 0;
        $retentionDays = (int) ($settings["event_retention_days"] ?? 90);
        $eventEarned += ($retentionDays >= 30 && $retentionDays <= 365) ? 5 : 0;
        $categories["Event Coverage"] = ["earned" => $eventEarned, "max" => 10];

        // --- Architecture Health (10) — Security Pack 2.2. This is
        // system/architecture availability, NOT "did you turn on an
        // optional feature" — IP Restrictions and extra GeoIP providers
        // are opt-in, so an install that hasn't configured them yet is
        // not penalized here beyond the info-level nudge below. ---
        $archEarned = 0;
        $archEarned += !empty($facts["ip_restriction_service_ok"]) ? 5 : 0;
        $archEarned += !empty($facts["geoip_provider_available"]) ? 5 : 0;
        if(empty($facts["ip_restriction_service_ok"])) {
            $recommendations[] = self::rec("warning", "The IP Restrictions service/table is not available.", "Open Security Diagnostics", "?module=security_pack&c=diagnostics", "architecture");
        } elseif(empty($facts["ip_rules_configured"])) {
            $recommendations[] = self::rec("info", "No IP Restriction rules are configured yet (optional).", "Review IP Restrictions", "?module=security_pack&c=ipRestrictions", "architecture");
        }
        // Security Pack 2.3 — Response Headers (5 of Architecture Health's
        // 15). Only the three no-compatibility-risk headers count toward
        // the score. CSP and HSTS are legitimately risky-by-default (can
        // break checkout / lock visitors out over plain HTTP), so leaving
        // them off is never penalized and turning them on never earns
        // extra points here — this category rewards the safe baseline,
        // not "maximum headers enabled".
        $safeHeadersOn = $on("sh_nosniff") && $on("sh_referrer_policy") && $on("sh_permissions_policy");
        $archEarned += $safeHeadersOn ? 5 : 0;
        if(!$safeHeadersOn) {
            $recommendations[] = self::rec("info", "Not all baseline security response headers are enabled.", "Review Security Headers", "?module=security_pack&c=settings", "architecture");
        }
        $categories["Architecture Health"] = ["earned" => $archEarned, "max" => 15];

        // --- Security Intelligence (10) — Security Pack 2.5. Extends
        // THIS service rather than a second "AdvancedSecurityScoreService"
        // (no architectural reason exists for a second service). Rewards
        // observability (CSP report collection turned on) and a clean
        // anomaly state — deliberately does NOT fluctuate with ordinary
        // telemetry volume (an ordinary day with zero anomalies and CSP
        // collection off scores the same tomorrow as it does today; only
        // a genuine unresolved HIGH/CRITICAL anomaly moves this number).
        $intelEarned = 0;
        $cspCollectionOn = $on("csp_report_collection");
        $intelEarned += $cspCollectionOn ? 5 : 0;
        if(!$cspCollectionOn) {
            $recommendations[] = self::rec("info", "CSP violation report collection is not enabled — you won't see when the browser blocks something unexpected.", "Review CSP Reports", "?module=security_pack&c=cspReports", "security_intelligence");
        }
        $openHighSeverityAnomalies = (int) ($facts["open_high_severity_anomalies"] ?? 0);
        $intelEarned += $openHighSeverityAnomalies === 0 ? 5 : 0;
        if($openHighSeverityAnomalies > 0) {
            $recommendations[] = self::rec("warning", $openHighSeverityAnomalies . " unresolved high-severity security anomal" . ($openHighSeverityAnomalies === 1 ? "y" : "ies") . ".", "Review Anomalies", "?module=security_pack&c=anomalies", "security_intelligence");
        } else {
            $recommendations[] = self::rec("pass", "No unresolved high-severity anomalies.", "", "?module=security_pack&c=anomalies", "security_intelligence");
        }
        $categories["Security Intelligence"] = ["earned" => $intelEarned, "max" => 10];

        $score = 0;
        $max = 0;
        foreach ($categories as $cat) {
            $score += $cat["earned"];
            $max += $cat["max"];
        }

        // Highest-severity, most-actionable items first; PASS entries last.
        $severityOrder = ["critical" => 0, "warning" => 1, "info" => 2, "pass" => 3];
        usort($recommendations, static function ($a, $b) use ($severityOrder) {
            return ($severityOrder[$a["severity"]] ?? 9) <=> ($severityOrder[$b["severity"]] ?? 9);
        });

        return [
            "score" => $score,
            "max" => $max,
            "categories" => $categories,
            "recommendations" => $recommendations,
        ];
    }

    private static function rec($severity, $message, $action, $href, $category)
    {
        return ["severity" => $severity, "message" => $message, "action" => $action, "href" => $href, "category" => $category];
    }

    /**
     * Gathers real environment facts for the live admin dashboard. Kept
     * separate from compute() so compute() itself stays a pure,
     * testable function.
     */
    public static function gatherFacts(): array
    {
        $tablesOk = true;
        $tables = [
            "dctlab_security_pack", "dctlab_security_pack_logins", "dctlab_security_pack_opt", "dctlab_security_pack_dpass",
            "dctlab_security_pack_ips", "dctlab_security_pack_geo_cache", "dctlab_security_pack_lc_overrides",
            "dctlab_security_pack_events", "dctlab_security_pack_schema_version", "dctlab_security_pack_rate_limits",
            "dctlab_security_pack_ip_rules",
        ];
        foreach ($tables as $table) {
            try {
                if(!\Illuminate\Database\Capsule\Manager::schema()->hasTable($table)) {
                    $tablesOk = false;
                    break;
                }
            } catch (\Throwable $e) {
                $tablesOk = false;
                break;
            }
        }

        $geoipLoaded = function_exists("security_pack_mmdb_reader") ? (bool) security_pack_mmdb_reader() : false;

        $dataDir = defined("security_pack_module_root") ? security_pack_module_root . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "data" : "";
        $dataDirWritable = $dataDir && is_dir($dataDir) && is_writable($dataDir);

        $eventsLast7d = 0;
        try {
            $eventsLast7d = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
                ->where("created_at", ">=", date("Y-m-d H:i:s", time() - (7 * 86400)))
                ->count();
        } catch (\Throwable $e) {
        }

        $ipRestrictionServiceOk = false;
        $ipRulesConfigured = false;
        try {
            $ipRestrictionServiceOk = \Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_ip_rules");
            if($ipRestrictionServiceOk) {
                $ipRulesConfigured = (bool) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")->count();
            }
        } catch (\Throwable $e) {
        }

        $geoipProviderAvailable = false;
        if(class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Security\\GeoIpManager")) {
            try {
                $manager = new \WHMCS\Module\Addon\Security_Pack\Security\GeoIpManager();
                foreach ($manager->diagnostics() as $row) {
                    if($row["available"]) {
                        $geoipProviderAvailable = true;
                    }
                }
            } catch (\Throwable $e) {
            }
        }

        // Security Pack 2.5 — bounded COUNT query only (never loads the
        // anomalies table into PHP); table may not exist yet on an
        // install that hasn't upgraded, so this is guarded the same way
        // every other fact above is.
        $openHighSeverityAnomalies = 0;
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_anomalies")) {
                $openHighSeverityAnomalies = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_anomalies")
                    ->where("status", "open")
                    ->whereIn("severity", ["high", "critical"])
                    ->count();
            }
        } catch (\Throwable $e) {
        }

        // Security Pack 2.6 — a single bounded COUNT, not a full table
        // load, purely to know whether at least one administrator
        // (the higher-value target) actually has Email 2FA ACTIVE — not
        // merely "the feature is switched on somewhere" (Step 78: don't
        // award points for a feature being enabled globally with no
        // real adoption).
        $adminEmail2faActiveCount = 0;
        $email2faAnyActiveCount = 0;
        try {
            if(\Illuminate\Database\Capsule\Manager::schema()->hasTable("dctlab_security_pack_email2fa")) {
                $adminEmail2faActiveCount = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
                    ->where("user_type", "admin")->where("status", "active")->count();
                $email2faAnyActiveCount = (int) \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_email2fa")
                    ->where("status", "active")->count();
            }
        } catch (\Throwable $e) {
        }

        return [
            "tables_ok" => $tablesOk,
            "geoip_loaded" => $geoipLoaded,
            "data_dir_writable" => $dataDirWritable,
            "events_last_7d" => $eventsLast7d,
            "ip_restriction_service_ok" => $ipRestrictionServiceOk,
            "ip_rules_configured" => $ipRulesConfigured,
            "geoip_provider_available" => $geoipProviderAvailable,
            "open_high_severity_anomalies" => $openHighSeverityAnomalies,
            "admin_email2fa_active_count" => $adminEmail2faActiveCount,
            "email2fa_any_active_count" => $email2faAnyActiveCount,
        ];
    }
}
