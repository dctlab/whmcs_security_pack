<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — consistent GeoIP result value object.
 *
 * Only `ip`, `country_code`, `success`, `source`, and `cached` are
 * actually populated by any provider currently implemented (MaxMind
 * GeoLite2-Country and the free curl country-lookup APIs only return a
 * country code, nothing more granular) — region/city/lat/lon/timezone are
 * present in the shape for forward compatibility with a future provider
 * that supports them, but are left null rather than invented/guessed.
 */
class GeoResult
{
    public string $ip;
    public bool $success;
    public ?string $countryCode;
    public ?string $countryName = null;
    public ?string $region = null;
    public ?string $city = null;
    public ?float $latitude = null;
    public ?float $longitude = null;
    public ?string $timezone = null;
    public string $source;
    public bool $cached = false;

    public function __construct(string $ip, bool $success, ?string $countryCode, string $source, bool $cached = false)
    {
        $this->ip = $ip;
        $this->success = $success;
        $this->countryCode = $countryCode ?: null;
        $this->source = $source;
        $this->cached = $cached;
    }

    public static function failure(string $ip, string $source = "none"): self
    {
        return new self($ip, false, null, $source, false);
    }

    public function toArray(): array
    {
        return [
            "ip" => $this->ip,
            "success" => $this->success,
            "country_code" => $this->countryCode,
            "country_name" => $this->countryName,
            "region" => $this->region,
            "city" => $this->city,
            "latitude" => $this->latitude,
            "longitude" => $this->longitude,
            "timezone" => $this->timezone,
            "source" => $this->source,
            "cached" => $this->cached,
        ];
    }
}
