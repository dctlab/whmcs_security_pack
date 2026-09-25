<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Pure, dependency-free IP/CIDR logic used by the Phase 1 trusted-proxy
 * resolver (hooks.php: security_pack_is_trusted_proxy()) and by the
 * Phase 2 IP Restrictions service. Kept dependency-free (no DB, no WHMCS
 * API calls) specifically so it can be exercised by the plain-PHP test
 * suite in tests/ without needing a live WHMCS database.
 *
 * This is the SINGLE authoritative CIDR-matching implementation for the
 * module — hooks.php's security_pack_is_trusted_proxy() delegates to
 * self::matchesAny() rather than re-implementing the same logic, per the
 * "one authoritative implementation per responsibility" rule.
 */
class IpUtil
{
    /**
     * True if $ip (IPv4 or IPv6) equals or falls inside any entry in
     * $list. Each entry may be a bare IP or a CIDR ("a.b.c.d/nn" or
     * "ipv6::/nn"). Malformed entries/IPs are silently skipped (never
     * throw) so one bad line in an admin-entered list can't take down
     * every request.
     */
    public static function matchesAny(string $ip, array $list): bool
    {
        if($ip === '' || !$list) {
            return false;
        }
        foreach ($list as $entry) {
            if(self::matchesOne($ip, (string) $entry)) {
                return true;
            }
        }
        return false;
    }

    public static function matchesOne(string $ip, string $entry): bool
    {
        $entry = trim($entry);
        if($entry === '') {
            return false;
        }
        if(strpos($entry, '/') === false) {
            return filter_var($ip, FILTER_VALIDATE_IP) !== false
                && filter_var($entry, FILTER_VALIDATE_IP) !== false
                && hash_equals($entry, $ip);
        }
        [$subnet, $maskBitsRaw] = explode('/', $entry, 2);
        if(!ctype_digit($maskBitsRaw)) {
            return false;
        }
        $maskBits = (int) $maskBitsRaw;
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }
        $totalBits = strlen($ipBin) * 8;
        if($maskBits < 0 || $maskBits > $totalBits) {
            return false;
        }
        $bytes = intdiv($maskBits, 8);
        $bits = $maskBits % 8;
        if($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        if($bits > 0) {
            $mask = chr((0xFF << (8 - $bits)) & 0xFF);
            if((substr($ipBin, $bytes, 1) & $mask) !== (substr($subnetBin, $bytes, 1) & $mask)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Parses a newline/comma separated admin textarea into a clean array
     * of non-empty trimmed entries.
     */
    public static function parseList(string $raw): array
    {
        if($raw === '') {
            return [];
        }
        $parts = preg_split('/[\r\n,]+/', $raw) ?: [];
        return array_values(array_filter(array_map('trim', $parts), static fn ($v) => $v !== ''));
    }

    public static function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * True if $entry is a well-formed bare IP ("203.0.113.5") or CIDR
     * ("203.0.113.0/24", "2001:db8::/32") — used to validate admin input
     * for Trusted Proxies / IP Restrictions BEFORE it's stored, so a typo
     * fails loudly at save time instead of silently never matching (or
     * worse, matching everything) later.
     */
    public static function isValidEntry(string $entry): bool
    {
        $entry = trim($entry);
        if($entry === '') {
            return false;
        }
        if(strpos($entry, '/') === false) {
            return self::isValidIp($entry);
        }
        [$subnet, $maskBitsRaw] = explode('/', $entry, 2) + [1 => ''];
        if(!ctype_digit((string) $maskBitsRaw) || !self::isValidIp($subnet)) {
            return false;
        }
        $bin = @inet_pton($subnet);
        if($bin === false) {
            return false;
        }
        $maxBits = strlen($bin) * 8;
        $maskBits = (int) $maskBitsRaw;
        return $maskBits >= 0 && $maskBits <= $maxBits;
    }

    /**
     * Mask bits ("specificity") of a validated entry — 32/128 for a bare
     * IPv4/IPv6 address, or the CIDR's own mask. Returns 0 for an invalid
     * entry (callers should validate with isValidEntry() first). Used by
     * IpRestrictionService to rank an exact-IP rule above a CIDR, and a
     * narrower CIDR above a broader one.
     */
    public static function specificity(string $entry): int
    {
        $entry = trim($entry);
        if(strpos($entry, '/') === false) {
            $bin = @inet_pton($entry);
            return $bin === false ? 0 : strlen($bin) * 8;
        }
        [$subnet, $maskBitsRaw] = explode('/', $entry, 2) + [1 => ''];
        if(!ctype_digit((string) $maskBitsRaw)) {
            return 0;
        }
        return self::isValidEntry($entry) ? (int) $maskBitsRaw : 0;
    }

    public static function isPrivateOrReserved(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }
}
