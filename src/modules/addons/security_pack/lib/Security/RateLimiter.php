<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 2.1 — centralized rate limiting service.
 *
 * Backed by a small dedicated counter table (dctlab_security_pack_rate_limits)
 * rather than dctlab_security_pack_events — events are an append-only audit
 * log and are the wrong shape for "how many hits in the current window",
 * so this is a genuine new-responsibility table, not a duplicate of the
 * Phase 1 event system (per the "one authoritative implementation per
 * responsibility" rule: events record WHAT happened, RateLimiter tracks
 * HOW OFTEN something is being attempted right now).
 *
 * evaluate() is a pure, dependency-free function — the actual
 * fixed-window counting logic — so it can be unit tested (see
 * tests/RateLimiterTest.php) without a database. hit()/isBlocked() are
 * thin DB-backed wrappers around it for real request handling.
 *
 * Deliberately NOT wired into the core WHMCS login flow
 * (UserLogin/AdminLogin hooks) in this release — WHMCS's own login
 * throttling already exists there, and getting a custom lockout wrong on
 * the admin or client login path risks locking out legitimate users
 * (explicitly called out as unacceptable). It's applied here only to
 * this module's own lower-risk AJAX endpoints (login notification /
 * disable-password-reset toggles) as a concrete, safe first use — see
 * ClientController for the call sites.
 */
class RateLimiter
{
    /**
     * Pure fixed-window rate limit evaluation.
     *
     * @param int $hitsInWindow  hits already recorded in the current window
     * @param int $maxHits       max allowed hits per window
     * @return array{allowed:bool, remaining:int}
     */
    public static function evaluate(int $hitsInWindow, int $maxHits): array
    {
        $maxHits = max(1, $maxHits);
        $hitsInWindow = max(0, $hitsInWindow);
        $allowed = $hitsInWindow < $maxHits;
        return [
            "allowed" => $allowed,
            "remaining" => max(0, $maxHits - $hitsInWindow - 1),
        ];
    }

    /**
     * True if $windowStartedAt (unix timestamp) is still within
     * $windowSeconds of $now — i.e. whether the counter should keep
     * accumulating or reset to a fresh window.
     */
    public static function isSameWindow(int $windowStartedAt, int $now, int $windowSeconds): bool
    {
        return $windowStartedAt > 0 && ($now - $windowStartedAt) < max(1, $windowSeconds);
    }

    /**
     * Records one hit for $key (e.g. "client_toggle:203.0.113.5") and
     * returns whether this hit should be allowed to proceed, per the
     * given $maxHits per $windowSeconds fixed window. Logs a
     * "ratelimit.exceeded" security event the first time a key trips the
     * limit (not on every subsequent request, to avoid flooding the
     * event log).
     */
    public static function hit(string $key, int $maxHits, int $windowSeconds): bool
    {
        $now = time();
        try {
            $row = \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_rate_limits")->where("rate_key", $key)->first();
            if(!$row || !self::isSameWindow(strtotime((string) $row->window_started_at), $now, $windowSeconds)) {
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_rate_limits")->updateOrInsert(
                    ["rate_key" => $key],
                    ["rate_key" => $key, "hits" => 1, "window_started_at" => date("Y-m-d H:i:s", $now), "updated_at" => date("Y-m-d H:i:s", $now)]
                );
                return true;
            }
            $result = self::evaluate((int) $row->hits, $maxHits);
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_rate_limits")->where("rate_key", $key)->update([
                "hits" => $row->hits + 1,
                "updated_at" => date("Y-m-d H:i:s", $now),
            ]);
            if(!$result["allowed"] && (int) $row->hits === $maxHits && function_exists("security_pack_record_event")) {
                security_pack_record_event("ratelimit.exceeded", "Rate limit exceeded for " . $key . ".", ["key" => $key, "max_hits" => $maxHits, "window_seconds" => $windowSeconds], "warning");
            }
            return $result["allowed"];
        } catch (\Throwable $e) {
            // Never let rate-limit bookkeeping itself break the request
            // it's protecting — fail open rather than locking everyone
            // out because the table is momentarily unavailable.
            return true;
        }
    }

    /**
     * Best-effort cleanup of stale counters — called from DailyCronJob.
     */
    public static function prune(int $olderThanSeconds = 86400): void
    {
        try {
            \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack_rate_limits")
                ->where("updated_at", "<", date("Y-m-d H:i:s", time() - $olderThanSeconds))
                ->delete();
        } catch (\Throwable $e) {
        }
    }
}
