<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

use WHMCS\Module\Addon\Security_Pack\Security\Providers\MaxMindProvider;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — GeoIpManager: the SINGLE authoritative GeoIP lookup
 * path. security_pack_resolve_country() (hooks.php, used by every
 * feature since 1.2.0 — Country Restriction, Language & Currency, the
 * admin Test-a-Lookup tool) now delegates here instead of containing its
 * own copy of the provider-selection/caching logic.
 *
 * IMPORTANT (Step 25 of the 2.2 spec): this class does NOT read
 * CF-Connecting-IP / X-Forwarded-For / X-Real-IP itself. It only ever
 * receives an already-resolved IP string from the caller — the
 * authoritative trusted-proxy-aware resolver is (and remains)
 * security_pack_detect_visitor_ip() in hooks.php. Keeping IP resolution
 * and GeoIP lookup as separate responsibilities is what stops a future
 * change from having two different places that could disagree about
 * "who is the visitor".
 *
 * Uses the EXISTING dctlab_security_pack_geo_cache table/schema verbatim —
 * no cache migration, no data loss for already-cached lookups.
 *
 * 2026-08-27 — per explicit request, GeoIP resolution is now MaxMind-only
 * for every caller (Country Restriction, Language & Currency, the admin
 * Test-a-Lookup tool): the CurlApiProvider (freeipapi.com/geojs.io/
 * ipapi.co) fallback was removed from the default provider chain, so a
 * visitor's IP is never sent to a third-party geolocation API — only
 * looked up locally against an uploaded MaxMind database. If MaxMind
 * can't resolve an IP (no database uploaded, or the IP isn't in it), the
 * lookup fails cleanly and the caller's own "unknown country" handling
 * applies (e.g. Country Restriction's Unknown-country Policy), exactly
 * as it already did whenever every configured provider failed before
 * this change. CurlApiProvider/providers/*.php are left in place, just
 * no longer wired into this default chain — a caller can still pass its
 * own provider list to the constructor if a future need re-introduces
 * them explicitly.
 */
class GeoIpManager
{
    /** @var GeoProviderInterface[] */
    private array $providers;

    public function __construct(array $providers = [])
    {
        $this->providers = $providers ?: [new MaxMindProvider()];
    }

    /**
     * @return GeoProviderInterface[]
     */
    public function providers(): array
    {
        return $this->providers;
    }

    /**
     * Resolves the country for $ip, using the DB cache first, then each
     * configured provider in order until one succeeds. Never throws —
     * any provider exception is caught by that provider's own lookup()
     * implementation, and a private/reserved/invalid IP short-circuits
     * to a clean failure before any provider or cache table is touched.
     */
    public function lookup(string $ip): GeoResult
    {
        if(!IpUtil::isValidIp($ip) || IpUtil::isPrivateOrReserved($ip)) {
            // Never send a private/loopback/reserved-range address to an
            // external API, and never bother querying the cache table
            // for something that was never going to resolve to a real
            // country (Step 24 of the 2.2 spec).
            return GeoResult::failure($ip, "skipped:private-or-invalid");
        }

        $ipHash = hash("sha256", $ip);
        $cacheAvailable = true;
        try {
            $cached = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_geo_cache")
                ->where("ip_hash", $ipHash)
                ->where("expires_at", ">", date("Y-m-d H:i:s"))
                ->first();
            if($cached) {
                $result = new GeoResult($ip, (bool) $cached->country_code, (string) $cached->country_code, "cache", true);
                return $result;
            }
        } catch (\Throwable $e) {
            // Table not created yet (module updated without _upgrade
            // running) — fall through and look the IP up without
            // caching, same fallback behaviour as pre-2.2.
            $cacheAvailable = false;
        }

        $result = GeoResult::failure($ip, "none");
        foreach ($this->providers as $provider) {
            try {
                if(!$provider->isAvailable()) {
                    continue;
                }
                $attempt = $provider->lookup($ip);
            } catch (\Throwable $e) {
                // A provider that throws instead of returning a failed
                // GeoResult is a bug in that provider, but it must never
                // take down the page that triggered the lookup.
                continue;
            }
            if($attempt->success && $attempt->countryCode) {
                $result = $attempt;
                break;
            }
        }

        if($cacheAvailable) {
            $settings = function_exists("security_pack_settings") ? security_pack_settings() : [];
            $cacheDays = isset($settings["geo_cache_days"]) ? max(1, intval($settings["geo_cache_days"])) : 7;
            $ttlDays = $result->success ? $cacheDays : 1;
            try {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_geo_cache")->updateOrInsert(
                    ["ip_hash" => $ipHash],
                    ["ip_hash" => $ipHash, "country_code" => $result->countryCode, "expires_at" => date("Y-m-d H:i:s", time() + ($ttlDays * 86400)), "updated_at" => date("Y-m-d H:i:s")]
                );
            } catch (\Throwable $e) {
                // Worst case: this IP gets looked up again next time.
            }
        }

        return $result;
    }

    /**
     * Health summary for the Diagnostics page — which providers exist
     * and whether each is currently usable.
     */
    public function diagnostics(): array
    {
        $rows = [];
        foreach ($this->providers as $provider) {
            $rows[] = ["name" => $provider->name(), "available" => $provider->isAvailable()];
        }
        return $rows;
    }
}
