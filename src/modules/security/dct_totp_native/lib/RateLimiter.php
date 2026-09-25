<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — fixed-window rate limiting, backed by this module's
 * own `mod_dct_totp_native_rate_limits` counter table.
 *
 * evaluate()/isSameWindow() are pure, dependency-free functions — the
 * actual fixed-window counting logic — so they are unit testable
 * without a database (see tests/run.php). hit() is the thin DB-backed
 * wrapper used by Enrollment for real request handling.
 *
 * Deliberately fails OPEN (returns true / "allowed") if the rate-limit
 * table itself is unavailable for any reason — a rate limiter must
 * never become the reason a legitimate login is blocked.
 */
class RateLimiter
{
    /**
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

    public static function isSameWindow(int $windowStartedAt, int $now, int $windowSeconds): bool
    {
        return $windowStartedAt > 0 && ($now - $windowStartedAt) < max(1, $windowSeconds);
    }

    /**
     * Records one hit for $key and returns whether it should be allowed
     * to proceed, per the given $maxHits per $windowSeconds fixed
     * window. Logs the first time a key trips the limit (not on every
     * subsequent request, to avoid flooding the activity log).
     */
    public static function hit(string $key, int $maxHits, int $windowSeconds): bool
    {
        Schema::ensure();
        $now = time();
        try {
            $table = Schema::RATE_LIMITS_TABLE;
            $row = \Illuminate\Database\Capsule\Manager::table($table)->where("rate_key", $key)->first();
            if (!$row || !self::isSameWindow(strtotime((string) $row->window_started_at), $now, $windowSeconds)) {
                \Illuminate\Database\Capsule\Manager::table($table)->updateOrInsert(
                    ["rate_key" => $key],
                    ["rate_key" => $key, "hits" => 1, "window_started_at" => date("Y-m-d H:i:s", $now), "updated_at" => date("Y-m-d H:i:s", $now)]
                );
                return true;
            }
            $result = self::evaluate((int) $row->hits, $maxHits);
            \Illuminate\Database\Capsule\Manager::table($table)->where("rate_key", $key)->update([
                "hits" => $row->hits + 1,
                "updated_at" => date("Y-m-d H:i:s", $now),
            ]);
            if (!$result["allowed"] && (int) $row->hits === $maxHits) {
                EventLog::record("Rate limit exceeded for key: " . $key);
            }
            return $result["allowed"];
        } catch (\Throwable $e) {
            return true; // fail open — never lock everyone out over a DB hiccup
        }
    }

    /** Best-effort cleanup of stale counters — call periodically from a cron/scheduled task if desired. */
    public static function prune(int $olderThanSeconds = 86400): void
    {
        Schema::ensure();
        try {
            \Illuminate\Database\Capsule\Manager::table(Schema::RATE_LIMITS_TABLE)
                ->where("updated_at", "<", date("Y-m-d H:i:s", time() - $olderThanSeconds))
                ->delete();
        } catch (\Throwable $e) {
        }
    }
}
