<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\GeoProviderInterface;
use WHMCS\Module\Addon\Security_Pack\Security\GeoResult;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — free curl/API GeoIP provider(s), as one
 * GeoProviderInterface implementation.
 *
 * Wraps the EXISTING working providers/*.php classes (freeipapi,
 * geojsio, ipapico) exactly as they were called from
 * security_pack_resolve_country() in 1.2.0/2.0.0/2.1.0 — same admin
 * "providers" setting, same random-shuffle-then-try-each behaviour, same
 * short-circuit on first valid 2-letter country code. Nothing here was
 * rewritten; this class only moves the existing loop behind the new
 * GeoProviderInterface boundary so GeoIpManager can treat "MaxMind" and
 * "the curl fallbacks" uniformly.
 *
 * $ip passed in is always the already-validated (FILTER_VALIDATE_IP,
 * non-private/reserved) visitor IP by the time it reaches here — see
 * GeoIpManager::lookup() — so no further validation is done before it's
 * appended to each provider's request URL.
 */
class CurlApiProvider implements GeoProviderInterface
{
    public function name(): string
    {
        return "curl";
    }

    public function isAvailable(): bool
    {
        return (bool) $this->selectedProviders();
    }

    public function lookup(string $ip): GeoResult
    {
        $providers = $this->selectedProviders();
        if(!$providers) {
            return GeoResult::failure($ip, $this->name());
        }
        shuffle($providers);
        foreach ($providers as $provider) {
            $providerFile = security_pack_module_root . "/providers/" . $provider . ".php";
            if(!class_exists($provider)) {
                if(!file_exists($providerFile)) {
                    continue;
                }
                require_once $providerFile;
            }
            try {
                $api = new $provider();
                $countryCode = strtoupper((string) $api->getDetails($ip));
            } catch (\Throwable $e) {
                $countryCode = "";
            }
            if($countryCode && preg_match("/^[A-Z]{2}$/", $countryCode)) {
                return new GeoResult($ip, true, $countryCode, "curl:" . $provider);
            }
        }
        return GeoResult::failure($ip, $this->name());
    }

    private function selectedProviders(): array
    {
        $settings = function_exists("security_pack_settings") ? security_pack_settings() : [];
        $selected = !empty($settings["providers"]) ? (json_decode($settings["providers"], true) ?: []) : [];
        if($selected) {
            return $selected;
        }
        $all = [];
        foreach (glob(security_pack_module_root . "/providers/*.php") ?: [] as $filename) {
            if(basename($filename) !== "index.php") {
                $all[] = str_replace(".php", "", basename($filename));
            }
        }
        return $all;
    }
}
