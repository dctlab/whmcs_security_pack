<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

use WHMCS\Module\Addon\Security_Pack\Security\IpUtil;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — dedicated 2FA IP/CIDR exemption store (Requirements
 * doc Section 1: "Allow administrators and clients to configure and
 * exclude static company IP addresses/IP ranges from 2FA requirements").
 *
 * DELIBERATELY NOT `IpRestrictionService`. That class is a general
 * allow/block gate (used elsewhere to decide whether a request is
 * allowed to reach WHMCS at all) with its own priority/specificity
 * precedence rules for resolving CONFLICTING allow vs. block rules —
 * none of that applies here. This is a much simpler question: "does
 * this IP, for this specific identity (or globally), mean the 2FA
 * challenge is not required?" There is no allow/block conflict to
 * resolve — every matching row here means the same thing (exempt), so
 * this class has no precedence logic at all, just membership.
 *
 * Reuses `IpUtil` (the shared, pure, dependency-free CIDR matcher) for
 * the actual IP-in-range test — that utility is genuinely
 * responsibility-neutral (Section "one authoritative implementation per
 * responsibility" — matching an IP against a CIDR isn't itself
 * allow/block-specific logic), so reusing it is NOT the same thing as
 * repurposing IpRestrictionService's rule engine.
 *
 * TWO SCOPES, never conflated:
 *   - GLOBAL ("company IP") rows: `user_id`/`user_type` both NULL.
 *     Admin-managed. Applies to every identity's 2FA challenge decision.
 *   - USER-scoped rows: `user_id`+`user_type` both set to an EXACT
 *     identity. Applies ONLY to that exact (user_id, user_type) pair —
 *     this is what keeps a primary client's own trusted-IP exemption
 *     from silently covering a future sub-account: a sub-account is a
 *     DIFFERENT `user_type` value (see UserIdentityType), so it is a
 *     different row set entirely, by construction — the same isolation
 *     property TwoFactorBypassService already relies on.
 *
 * isExempt() FAILS CLOSED on any DB error — an exemption lookup failure
 * must never silently skip a 2FA challenge that would otherwise be
 * required (the opposite direction of IpRestrictionService's own
 * documented "safe by default" fail-open, which is correct there
 * because failing open there means "don't block a legitimate request";
 * failing open HERE would mean "don't require 2FA", the less safe
 * direction).
 */
class TwoFactorIpExemptionService
{
    private const TABLE = "dctlab_security_pack_2fa_ip_exemptions";

    /**
     * PURE decision core (no DB access, unit tested directly): given the
     * already-fetched global entries and this exact identity's own
     * entries, is $ip covered by any of them? Injected-entries pattern,
     * same as this project's other DB-backed decision functions.
     *
     * @param string[] $globalEntries
     * @param string[] $userEntries
     */
    public static function isExemptGivenEntries(string $ip, array $globalEntries, array $userEntries): bool
    {
        return IpUtil::matchesAny($ip, array_merge($globalEntries, $userEntries));
    }

    public static function isExempt(string $ip, int $userId, string $userType): bool
    {
        if($ip === '') {
            return false;
        }
        try {
            $global = self::activeEntries(null, null);
            $userScoped = $userId > 0 ? self::activeEntries($userId, $userType) : [];
        } catch (\Throwable $e) {
            return false; // fail closed — see class docblock
        }
        return self::isExemptGivenEntries($ip, $global, $userScoped);
    }

    /** @return string[] */
    private static function activeEntries(?int $userId, ?string $userType): array
    {
        $q = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("enabled", 1);
        if($userId === null) {
            $q->whereNull("user_id");
        } else {
            $q->where("user_id", $userId)->where("user_type", $userType);
        }
        $entries = $q->pluck("entry");
        return $entries ? array_values($entries->toArray()) : [];
    }

    /** @return array{ok:bool, error?:string} */
    public static function addGlobal(string $entry, string $actorLabel, string $reason = ""): array
    {
        return self::add(null, null, $entry, $actorLabel, $reason);
    }

    /** @return array{ok:bool, error?:string} */
    public static function addForUser(int $userId, string $userType, string $entry, string $actorLabel, string $reason = ""): array
    {
        if($userId <= 0) {
            return ["ok" => false, "error" => "A valid User ID is required."];
        }
        return self::add($userId, $userType, $entry, $actorLabel, $reason);
    }

    /** @return array{ok:bool, error?:string} */
    private static function add(?int $userId, ?string $userType, string $entry, string $actorLabel, string $reason): array
    {
        $entry = trim($entry);
        if(!IpUtil::isValidEntry($entry)) {
            return ["ok" => false, "error" => "\"" . $entry . "\" is not a valid IP address or CIDR range."];
        }
        $now = date("Y-m-d H:i:s");
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert([
                "user_id" => $userId,
                "user_type" => $userId !== null ? $userType : null,
                "entry" => $entry,
                "reason" => mb_substr($reason, 0, 255),
                "created_by" => $actorLabel,
                "enabled" => 1,
                "created_at" => $now,
                "updated_at" => $now,
            ]);
        } catch (\Throwable $e) {
            return ["ok" => false, "error" => "Could not save the exemption — please try again."];
        }
        if(function_exists("security_pack_record_event")) {
            $scopeLabel = $userId !== null ? ($userType . " #" . $userId) : "company-wide (all identities)";
            security_pack_record_event(
                "2fa.ip_exemption.created",
                "2FA IP exemption \"" . $entry . "\" added, scope: " . $scopeLabel . ".",
                ["entry" => $entry, "user_id" => $userId, "user_type" => $userType, "actor" => $actorLabel]
            );
        }
        return ["ok" => true];
    }

    public static function remove(int $id, string $actorLabel): void
    {
        try {
            $row = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $id)->first();
            if(!$row) {
                return;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $id)->delete();
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event(
                "2fa.ip_exemption.removed",
                "2FA IP exemption \"" . $row->entry . "\" removed.",
                ["id" => $id, "entry" => $row->entry, "actor" => $actorLabel]
            );
        }
    }

    /** @return array all global (company-wide) exemption rows, newest first */
    public static function listGlobal(int $limit = 200): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->whereNull("user_id")
                ->orderBy("id", "DESC")->limit($limit)->get();
            return $rows ? $rows->toArray() : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** @return array every user-scoped exemption row (any identity), newest first — for the admin overview table */
    public static function listUserScoped(int $limit = 200): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->whereNotNull("user_id")
                ->orderBy("id", "DESC")->limit($limit)->get();
            return $rows ? $rows->toArray() : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * 2026-08-22 — Requirements doc Step 6 ("Trusted IP Reporting" —
     * distinguish none/global/per-user, never confused with the
     * general-purpose IpRestrictionService). Existence-only checks,
     * deliberately WITHOUT an IP argument — isExempt()/isExemptGivenEntries()
     * above answer "is THIS ip covered right now", which needs a
     * concrete IP to test against and isn't what an admin overview
     * table (no specific login in progress) needs; these two answer
     * "does any active exemption of this kind exist at all", the
     * question the reporting table actually asks. Fail-CLOSED (false)
     * on any DB error, same direction as isExempt() — a report that
     * can't confirm an exemption exists should never claim one does.
     */
    public static function hasActiveGlobalExemption(): bool
    {
        try {
            return \Illuminate\Database\Capsule\Manager::table(self::TABLE)->whereNull("user_id")->where("enabled", 1)->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    public static function hasActiveUserExemption(int $userId, string $userType): bool
    {
        if($userId <= 0) {
            return false;
        }
        try {
            return \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("enabled", 1)->exists();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * PURE decision logic (no DB access — unit tested directly): the
     * exact three-state label the admin reporting overview shows for
     * "Trusted IP". A per-user exemption is reported even when a global
     * one ALSO exists (the more specific fact is more useful to an
     * admin than "None" or a generic "Global" that would hide it) —
     * this is purely a DISPLAY precedence choice; it does not change
     * which IPs are actually exempt (isExemptGivenEntries() already
     * merges both lists regardless of what this label shows).
     */
    public static function reportLabel(bool $hasGlobalExemption, bool $hasUserExemption): string
    {
        if($hasUserExemption) {
            return "Per-User Exemption";
        }
        if($hasGlobalExemption) {
            return "Global Exemption";
        }
        return "None";
    }
}
