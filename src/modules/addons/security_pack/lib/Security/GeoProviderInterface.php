<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — provider-based GeoIP architecture.
 *
 * Every provider (MaxMind local database, curl-based free APIs, any
 * future provider) implements this. lookup() must NEVER throw for
 * ordinary failure cases (no data, network error, timeout, invalid IP) —
 * it should catch internally and return a failed GeoResult, since
 * GeoIpManager treats an exception as a bug, not "no data", and a GeoIP
 * failure must never break the WHMCS page rendering it.
 */
interface GeoProviderInterface
{
    /**
     * A short machine-readable identifier for this provider, used as
     * GeoResult::$source and in diagnostics ("maxmind", "curl:ipapico").
     */
    public function name(): string;

    /**
     * Whether this provider is currently usable (e.g. MaxMind has a
     * .mmdb file loaded). Checked by GeoIpManager before calling
     * lookup() so unusable providers are skipped without a wasted call.
     */
    public function isAvailable(): bool;

    public function lookup(string $ip): GeoResult;
}
