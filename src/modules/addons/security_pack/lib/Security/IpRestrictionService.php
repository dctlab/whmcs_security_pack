<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.2 — centralized IP Restrictions (ALLOW/BLOCK rules).
 *
 * This is the ONE authoritative place IP allow/block decisions are made.
 * Built entirely on top of the existing, already-tested IpUtil for
 * IP/CIDR matching — no second CIDR implementation.
 *
 * SAFE BY DEFAULT: with zero rules configured (the state of every
 * upgraded install until an admin explicitly adds one), evaluate()
 * always returns allowed=true. Nothing is enforced just by upgrading.
 *
 * Rule precedence (documented, deterministic — Step 12 of the 2.2 spec):
 *   1. Higher specificity wins (an exact /32 or /128 IP beats a CIDR;
 *      a narrower CIDR beats a broader one — e.g. /28 beats /24).
 *   2. Among equal specificity, higher admin-set `priority` wins.
 *   3. Among equal specificity AND priority, the most recently created/
 *      updated rule (highest id) wins — never left to arbitrary DB
 *      ordering.
 *   BLOCK vs ALLOW is NOT itself a precedence tiebreaker — whichever
 *   rule wins by the above is the one that applies, whether it's an
 *   allow or a block. This lets an admin carve a specific ALLOW
 *   exception out of a broader BLOCK range (or vice versa) predictably.
 */
class IpRestrictionService
{
    /**
     * Pure evaluation core — no database access, fully unit-testable
     * (see tests/run.php). $rules is an array of plain arrays, each with
     * keys: id, rule_type ('allow'|'block'), target, mask_bits, priority.
     * Callers are expected to have already filtered to enabled,
     * non-expired rules before calling this.
     *
     * @return array{allowed:bool, matched_rule:?array, reason:string}
     */
    public static function evaluateAgainstRules(string $ip, array $rules): array
    {
        if(!IpUtil::isValidIp($ip)) {
            return ["allowed" => true, "matched_rule" => null, "reason" => "invalid IP — no restriction applied"];
        }

        $matches = [];
        foreach ($rules as $rule) {
            if(!isset($rule["target"]) || !IpUtil::matchesOne($ip, (string) $rule["target"])) {
                continue;
            }
            $matches[] = $rule;
        }

        if(!$matches) {
            return ["allowed" => true, "matched_rule" => null, "reason" => "no matching rule — default allow"];
        }

        usort($matches, static function ($a, $b) {
            $specA = (int) ($a["mask_bits"] ?? 0);
            $specB = (int) ($b["mask_bits"] ?? 0);
            if($specA !== $specB) {
                return $specB <=> $specA; // higher mask_bits (more specific) first
            }
            $prioA = (int) ($a["priority"] ?? 0);
            $prioB = (int) ($b["priority"] ?? 0);
            if($prioA !== $prioB) {
                return $prioB <=> $prioA;
            }
            return (int) ($b["id"] ?? 0) <=> (int) ($a["id"] ?? 0); // most recent wins
        });

        $winner = $matches[0];
        $allowed = ($winner["rule_type"] ?? "allow") !== "block";
        $reason = $allowed
            ? "matched ALLOW rule for " . ($winner["target"] ?? "?")
            : "matched BLOCK rule for " . ($winner["target"] ?? "?");

        return ["allowed" => $allowed, "matched_rule" => $winner, "reason" => $reason];
    }

    /**
     * Real evaluate() for live request handling — loads enabled,
     * non-expired rules from the database and delegates to the pure
     * evaluator above. Fails open (allowed=true) if the table can't be
     * queried, same fail-open philosophy as RateLimiter::hit() — a
     * transient DB problem must never turn into "block everyone".
     */
    public static function evaluate(string $ip): array
    {
        try {
            $rules = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_ip_rules")
                ->where("enabled", 1)
                ->where(function ($q) {
                    $q->whereNull("expires_at")->orWhere("expires_at", ">", date("Y-m-d H:i:s"));
                })
                ->get()
                ->map(static function ($row) {
                    return (array) $row;
                })
                ->all();
        } catch (\Throwable $e) {
            return ["allowed" => true, "matched_rule" => null, "reason" => "IP rules table unavailable — failing open"];
        }
        return self::evaluateAgainstRules($ip, $rules);
    }

    /**
     * Validates+normalizes admin input for a rule's target field.
     * Returns the trimmed entry + its mask_bits, or null if invalid.
     */
    public static function normalizeTarget(string $target): ?array
    {
        $target = trim($target);
        if(!IpUtil::isValidEntry($target)) {
            return null;
        }
        return ["target" => $target, "mask_bits" => IpUtil::specificity($target)];
    }

    /**
     * Admin lockout protection (Step 16 of the 2.2 spec): would saving a
     * BLOCK rule for $target also block $currentAdminIp? Checked BEFORE
     * saving, using the same evaluator a real request would use, so the
     * warning reflects actual precedence (e.g. an existing narrower
     * ALLOW rule already protecting the admin's IP correctly suppresses
     * the warning).
     */
    public static function wouldLockOutCurrentAdmin(string $currentAdminIp, string $candidateTarget, array $existingRules = []): bool
    {
        if(!IpUtil::isValidIp($currentAdminIp) || !IpUtil::matchesOne($currentAdminIp, $candidateTarget)) {
            return false;
        }
        $candidate = [
            "id" => PHP_INT_MAX, // a not-yet-saved rule always wins ties against existing rules of equal specificity/priority
            "rule_type" => "block",
            "target" => $candidateTarget,
            "mask_bits" => IpUtil::specificity($candidateTarget),
            "priority" => 0,
        ];
        $result = self::evaluateAgainstRules($currentAdminIp, array_merge($existingRules, [$candidate]));
        return $result["allowed"] === false;
    }
}
