<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\GeoProviderInterface;
use WHMCS\Module\Addon\Security_Pack\Security\GeoResult;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — MaxMind GeoLite2-Country provider.
 *
 * Thin adapter around the EXISTING working
 * security_pack_mmdb_reader()/\WHMCS\Module\Addon\Security_Pack\MaxMindDb\Reader
 * — the working .mmdb parsing logic from 1.2.0/2.0.0 is reused verbatim,
 * not rewritten, per the "preserve current GeoIP behaviour" requirement.
 * Local database lookup, no network call, no timeout needed.
 */
class MaxMindProvider implements GeoProviderInterface
{
    public function name(): string
    {
        return "maxmind";
    }

    public function isAvailable(): bool
    {
        return function_exists("security_pack_mmdb_reader") && (bool) security_pack_mmdb_reader();
    }

    public function lookup(string $ip): GeoResult
    {
        if(!$this->isAvailable()) {
            return GeoResult::failure($ip, $this->name());
        }
        try {
            $reader = security_pack_mmdb_reader();
            $result = $reader->lookup($ip);
            if($result && !empty($result["country_code"])) {
                return new GeoResult($ip, true, (string) $result["country_code"], $this->name());
            }
        } catch (\Throwable $e) {
            // Corrupt/unsupported .mmdb entry for this IP, or a parser
            // edge case — never fatal, GeoIpManager will fall through to
            // the next provider.
        }
        return GeoResult::failure($ip, $this->name());
    }
}
