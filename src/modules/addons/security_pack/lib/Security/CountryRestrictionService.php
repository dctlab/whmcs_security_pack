<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.8 — Country Restriction, rewritten to be a CONSUMER of
 * the existing GeoIP architecture, not a second GeoIP system.
 *
 * This service holds ONLY the pure allow/block decision logic — no
 * country lookup, no MaxMind/curl provider code, no cache, no visitor IP
 * detection. Country resolution is entirely the responsibility of
 * GeoIpManager (via security_pack_resolve_country()), and visitor IP
 * resolution is entirely the responsibility of
 * security_pack_detect_visitor_ip() — both already used by every other
 * Security Pack feature (Language & Currency, IP Restrictions, Security
 * Events, Security Diagnostics). This class never talks to a database,
 * a provider, or a cache table, which also makes it fully unit-testable
 * (see tests/run.php) without any WHMCS runtime.
 *
 * SAFE BY DEFAULT: with the feature disabled, or enabled with no
 * countries selected, evaluate() always returns blocked=false — turning
 * this feature on does nothing destructive until an admin actually
 * configures a rule list.
 */
class CountryRestrictionService
{
    public const MODE_BLOCK = "block";
    public const MODE_ALLOW = "allow";

    public const UNKNOWN_ALLOW = "allow";
    public const UNKNOWN_BLOCK = "block";

    /**
     * Pure decision core. $settings is the module's flat settings array
     * (as returned by security_pack_settings()); $countryCode is the
     * ISO country code already resolved by GeoIpManager for this
     * visitor, or null/empty if it could not be determined (MaxMind
     * unavailable, provider failure/timeout, private/invalid IP, etc.).
     *
     * @return array{blocked:bool, reason:string, mode:string}
     */
    public static function evaluate(array $settings, ?string $countryCode): array
    {
        $mode = self::normalizeMode($settings["country_restriction_mode"] ?? null);
        $unknownPolicy = self::normalizeUnknownPolicy($settings["country_restriction_unknown_policy"] ?? null);

        if(empty($settings["country_restriction"])) {
            return ["blocked" => false, "reason" => "country_restriction_disabled", "mode" => $mode];
        }

        $countryCode = $countryCode ? strtoupper(trim($countryCode)) : "";

        if($countryCode === "") {
            // Explicit, documented, configurable policy — never silently
            // treat "unknown" as "allowed" or "blocked" by accident. The
            // recommended/default policy is Allow (fail open): a GeoIP
            // outage should not lock out every visitor.
            return [
                "blocked" => $unknownPolicy === self::UNKNOWN_BLOCK,
                "reason" => "unknown_country_policy_" . $unknownPolicy,
                "mode" => $mode,
            ];
        }

        $selected = self::normalizeCountryList($settings["disallowed_countries"] ?? null);
        if(!$selected) {
            // No rule list configured — nothing to enforce, regardless of
            // mode. This matches the pre-2.8 "no selected countries =
            // no-op" behaviour for block mode, and extends the same
            // fail-safe default to allow mode (an accidental empty
            // allow-list must never lock out every visitor).
            return ["blocked" => false, "reason" => "no_countries_configured", "mode" => $mode];
        }

        $inList = in_array($countryCode, $selected, true);

        if($mode === self::MODE_ALLOW) {
            return [
                "blocked" => !$inList,
                "reason" => $inList ? "in_allow_list" : "not_in_allow_list",
                "mode" => $mode,
            ];
        }

        return [
            "blocked" => $inList,
            "reason" => $inList ? "in_block_list" : "not_in_block_list",
            "mode" => $mode,
        ];
    }

    public static function normalizeMode(?string $mode): string
    {
        return $mode === self::MODE_ALLOW ? self::MODE_ALLOW : self::MODE_BLOCK;
    }

    public static function normalizeUnknownPolicy(?string $policy): string
    {
        return $policy === self::UNKNOWN_BLOCK ? self::UNKNOWN_BLOCK : self::UNKNOWN_ALLOW;
    }

    /**
     * Normalizes a raw settings value (JSON-encoded array, as saved by
     * the admin UI) into a de-duplicated, uppercased list of 2-letter
     * codes. Never throws on malformed JSON/input.
     */
    public static function normalizeCountryList($raw): array
    {
        if(is_string($raw) && $raw !== "") {
            $decoded = json_decode($raw, true);
            $raw = is_array($decoded) ? $decoded : [];
        }
        if(!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $code) {
            $code = strtoupper(trim((string) $code));
            if(preg_match("/^[A-Z]{2}$/", $code)) {
                $out[$code] = true;
            }
        }
        return array_keys($out);
    }

    /**
     * Validates a single country code against the module's EXISTING
     * authoritative country list (core/countries.json — the same file
     * Language & Currency and the admin country picker already use).
     * Deliberately does not maintain a second/duplicate list of valid
     * ISO codes.
     */
    public static function isValidCountryCode(string $code, array $knownCodes): bool
    {
        $code = strtoupper(trim($code));
        if(!preg_match("/^[A-Z]{2}$/", $code)) {
            return false;
        }
        return isset($knownCodes[$code]) || in_array($code, $knownCodes, true);
    }
}
