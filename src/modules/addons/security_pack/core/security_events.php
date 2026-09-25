<?php

declare(strict_types=1);

// Security Pack 2.0: centralized security event recorder. Every
// subsystem (login/account protection, IP security, country
// restriction, settings changes, GeoIP failures) should call
// security_pack_record_event() instead of writing its own ad-hoc log
// line, so the admin Diagnostics/Activity view has one consistent,
// queryable feed. Never pass secrets, passwords, or auth tokens in
// $context — this is written to the database in plain text.

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * @param string $eventType  short dot-namespaced identifier, e.g.
 *                            "login.client.success", "ip.blocked",
 *                            "country.blocked", "settings.updated"
 * @param string $message    short human-readable description
 * @param array  $context    arbitrary structured extra data (JSON
 *                            encoded on write) — never put secrets here
 * @param string $severity   info|warning|critical
 */
function security_pack_record_event($eventType, $message = "", array $context = [], $severity = "info")
{
    try {
        $ip = "";
        if(function_exists("security_pack_detect_visitor_ip")) {
            $settings = function_exists("security_pack_settings") ? security_pack_settings() : [];
            $ip = security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto");
        }
        if(!$ip) {
            global $remote_ip;
            $ip = $remote_ip ?: ($_SERVER["REMOTE_ADDR"] ?? "");
        }
        $country = "";
        if($ip && function_exists("security_pack_resolve_country")) {
            try {
                $country = security_pack_resolve_country($ip);
            } catch (\Throwable $e) {
                $country = "";
            }
        }
        $actorType = "";
        $actorId = "";
        if(isset($_SESSION["adminid"]) && $_SESSION["adminid"]) {
            $actorType = "admin";
            $actorId = (string) $_SESSION["adminid"];
        } elseif(isset($_SESSION["uid"]) && $_SESSION["uid"]) {
            $actorType = "client";
            $actorId = (string) $_SESSION["uid"];
        }
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")->insert([
            "event_type" => substr((string) $eventType, 0, 64),
            "severity" => in_array($severity, ["info", "warning", "critical"], true) ? $severity : "info",
            "message" => (string) $message,
            "ip" => $ip ? substr($ip, 0, 45) : null,
            "country_code" => $country ?: null,
            "actor_type" => $actorType ?: null,
            "actor_id" => $actorId ?: null,
            "context" => $context ? json_encode($context) : null,
            "created_at" => date("Y-m-d H:i:s"),
        ]);
    } catch (\Throwable $e) {
        // Event logging must never break the request it's observing —
        // e.g. the table doesn't exist yet because _upgrade() hasn't run
        // on this install. Silently drop the event rather than fatal.
    }
}

/**
 * Deletes events older than the configured retention window. Called from
 * the existing DailyCronJob hook (see core/loginHistory.php) so no new
 * cron entry is needed. Defaults to 90 days if unset.
 */
function security_pack_prune_events()
{
    $settings = function_exists("security_pack_settings") ? security_pack_settings() : [];
    $days = isset($settings["event_retention_days"]) ? max(1, intval($settings["event_retention_days"])) : 90;
    try {
        Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_events")
            ->where("created_at", "<", date("Y-m-d H:i:s", time() - ($days * 86400)))
            ->delete();
    } catch (\Throwable $e) {
    }
}
