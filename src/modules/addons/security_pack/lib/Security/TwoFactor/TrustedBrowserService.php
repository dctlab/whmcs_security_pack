<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — "Remember this browser for 30 days" (Requirements doc
 * Section 3), 2026-08-22.
 *
 * DELIBERATELY INDEPENDENT from every existing bypass/exemption system:
 *   - TwoFactorBypassService's same-IP bypass is granted automatically
 *     after ANY successful verification, keyed by (user, IP) — no device
 *     identity at all; any browser on that IP is covered.
 *   - TwoFactorIpExemptionService is an admin/company-configured network
 *     exemption — never tied to a specific successful verification.
 *   - THIS class is granted only when the user EXPLICITLY opts in on a
 *     REAL successful verification (never a bypass/exemption shortcut —
 *     enforced by construction: the live security modules only ever
 *     check the "remember browser" checkbox inside the genuine
 *     code-or-recovery-code success branch, never inside the
 *     bypass/exemption/trusted-browser-itself auto-submit branches,
 *     which return before that checkbox could ever be read), keyed by a
 *     high-entropy opaque DEVICE TOKEN, never an IP address.
 * No storage, table, or decision logic is shared between these three —
 * see each module's own docblock for why they must stay separate.
 *
 * TOKEN DESIGN: a 32-byte (256-bit) `random_bytes()` value, base64url-
 * encoded for cookie transport, is the ONLY secret. The database never
 * stores it — only `hash('sha256', $token)`. This is a deliberately
 * DIFFERENT hash choice from OtpEngine::hashOtp() (bcrypt via
 * password_hash()): bcrypt is for a short, low-entropy, guessable OTP
 * where the point of a slow, salted hash is to make offline brute-force
 * expensive even if the hash leaks. A 256-bit random token doesn't have
 * that problem — the entropy itself is what protects it — and a lookup
 * needs a fast, deterministic hash so it can be looked up by exact
 * match (`WHERE token_hash = ?`, narrowed by an index) rather than
 * compared row-by-row with a slow verify function. Using bcrypt here
 * would only add cost with no real security benefit.
 *
 * IDENTITY ISOLATION: every row is scoped by the exact (user_id,
 * user_type) pair — the SAME isolation guarantee established in
 * v3.1.28. `client:123` and `admin:123` and a future `contact:123` are
 * three different row sets by construction; nothing here ever looks up
 * a token by anything other than the exact identity presenting it.
 *
 * SERVER-SIDE EXPIRY: verify()/isValidForIdentity() always check the
 * stored `expires_at` — the cookie's own browser-side expiry is only a
 * convenience for the browser to stop sending it eventually and is
 * never trusted as the actual expiry authority.
 */
class TrustedBrowserService
{
    private const TABLE = "dctlab_security_pack_trusted_browsers";
    private const COOKIE_NAME = "security_pack_trusted_device";
    public const DEFAULT_DAYS = 30;

    // --- Pure logic (no DB, no I/O — unit tested directly) -------------

    /**
     * Given an already-fetched candidate row's plain scalars, is it
     * currently a valid trusted-browser grant? A row is valid only if
     * it has never been revoked AND its absolute expiry has not passed
     * — there is no sliding/renewing expiry (Section 4: "prefer an
     * absolute 30-day expiry rather than silently extending the
     * lifetime on every request" — confirmed: nothing in this class
     * ever rewrites `expires_at` after creation).
     */
    public static function isRowValid(?string $revokedAt, int $expiresAtTs, int $nowTs): bool
    {
        return $revokedAt === null && $expiresAtTs > 0 && $nowTs < $expiresAtTs;
    }

    /** Deterministic, fast lookup hash — see class docblock for why this is sha256, not bcrypt. */
    public static function hashToken(string $rawToken): string
    {
        return hash("sha256", $rawToken);
    }

    /**
     * Cryptographically random opaque token. 32 bytes (256 bits) of
     * `random_bytes()` — never `rand()`/`mt_rand()`/`uniqid()`, matching
     * OtpEngine::generateOtp()'s own "never a weak PRNG" rule. base64url
     * encoded (`+/` -> `-_`, no padding) so it's safe to place directly
     * in a cookie value without additional escaping.
     */
    public static function generateToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), "+/", "-_"), "=");
    }

    /**
     * 2026-08-22 — Requirements doc Step 6 ("Trusted Browser Reporting" —
     * count + latest expiry, never the token/hash). PURE decision logic
     * (no DB access — unit tested directly): given already-fetched rows
     * (as returned by listForIdentity(), or any array of objects/arrays
     * exposing an `expires_at` value), summarizes them for display. Takes
     * data in rather than querying itself, same injected-data pattern as
     * every other pure function in this codebase — the admin reporting
     * overview fetches once via listForIdentity() and reuses the result
     * for both the summary shown here and the full per-row detail
     * already shown in the "Manage a User's 2FA" panel, never a second
     * query for the same data. Only ever reads expires_at — even if a
     * caller passed a row object that happened to include token_hash,
     * this function does not look at it, and nothing here ever returns
     * it.
     *
     * @param array $rows objects/arrays each exposing an `expires_at` value (string, sortable as MySQL DATETIME)
     * @return array{count:int,has_any:bool,latest_expires_at:?string}
     */
    public static function summarize(array $rows): array
    {
        $count = count($rows);
        $latestExpiry = null;
        foreach ($rows as $row) {
            $expiresAt = is_array($row) ? ($row["expires_at"] ?? null) : ($row->expires_at ?? null);
            if($expiresAt === null || $expiresAt === "") {
                continue;
            }
            $expiresAt = (string) $expiresAt;
            if($latestExpiry === null || $expiresAt > $latestExpiry) {
                $latestExpiry = $expiresAt;
            }
        }
        return ["count" => $count, "has_any" => $count > 0, "latest_expires_at" => $latestExpiry];
    }

    // --- Cookie I/O ------------------------------------------------------
    //
    // Reuses this project's EXISTING cookie-attribute convention exactly
    // (core/geoip_lang_currency.php's setcookie() call: HttpOnly, Secure
    // when HTTPS, SameSite=Lax, path "/") rather than inventing a new
    // one. The raw token — a high-entropy opaque value with no user ID,
    // user type, or other identifying/sensitive data embedded in it — is
    // the only thing ever placed in the cookie (Section "Do not put the
    // user's ID or sensitive information directly into the cookie").

    public static function cookieName(): string
    {
        return self::COOKIE_NAME;
    }

    public static function setCookie(string $rawToken): void
    {
        if(headers_sent()) {
            return;
        }
        @setcookie(self::COOKIE_NAME, $rawToken, [
            "expires" => time() + (self::DEFAULT_DAYS * 86400),
            "path" => "/",
            "secure" => !empty($_SERVER["HTTPS"]),
            "httponly" => true,
            "samesite" => "Lax",
        ]);
    }

    public static function clearCookie(): void
    {
        if(headers_sent()) {
            return;
        }
        @setcookie(self::COOKIE_NAME, "", [
            "expires" => time() - 3600,
            "path" => "/",
            "secure" => !empty($_SERVER["HTTPS"]),
            "httponly" => true,
            "samesite" => "Lax",
        ]);
    }

    public static function readCookieToken(): string
    {
        $v = $_COOKIE[self::COOKIE_NAME] ?? "";
        return is_string($v) ? $v : "";
    }

    // --- DB-backed orchestration -----------------------------------------

    /**
     * Read-only check used at CHALLENGE time (deciding whether to skip
     * straight to the auto-submit form) — deliberately does NOT touch
     * `last_used_at` or record a "used" event, since the challenge-time
     * check is not yet the authoritative decision (the auto-submitted
     * hidden field is independently re-checked by consume() at VERIFY
     * time, same "never trust a hidden field alone" discipline the
     * existing bypass check already follows).
     */
    public static function isValidForIdentity(string $rawToken, int $userId, string $userType): bool
    {
        return self::lookupValidRow($rawToken, $userId, $userType) !== null;
    }

    /**
     * Authoritative check, used at VERIFY time: re-validates the token
     * independently (never trusts that challenge() already said yes),
     * and on success touches `last_used_at` and records
     * "2fa.trusted_browser.used". This is the ONLY place a trusted
     * browser actually grants a login.
     */
    public static function consume(string $rawToken, int $userId, string $userType): bool
    {
        $row = self::lookupValidRow($rawToken, $userId, $userType);
        if($row === null) {
            return false;
        }
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $row->id)
                ->update(["last_used_at" => date("Y-m-d H:i:s")]);
        } catch (\Throwable $e) {
        }
        if(function_exists("security_pack_record_event")) {
            // Never logs the token itself (Section "Do not log the
            // actual token") — only the identity and the row id.
            security_pack_record_event("2fa.trusted_browser.used", "A trusted browser was used to bypass the 2FA challenge for " . $userType . " #" . $userId . ".", ["user_id" => $userId, "user_type" => $userType, "trusted_browser_id" => $row->id]);
        }
        return true;
    }

    private static function lookupValidRow(string $rawToken, int $userId, string $userType)
    {
        if($rawToken === "" || $userId <= 0) {
            return null;
        }
        $hash = self::hashToken($rawToken);
        try {
            $row = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->where("token_hash", $hash)->first();
        } catch (\Throwable $e) {
            return null; // fail closed — see class docblock direction note
        }
        if(!$row) {
            return null;
        }
        $expiresTs = strtotime((string) $row->expires_at) ?: 0;
        return self::isRowValid($row->revoked_at, $expiresTs, time()) ? $row : null;
    }

    /**
     * Creates a new trusted-browser grant — ONLY ever called from the
     * genuine successful-verification branch of a live security module
     * (see class docblock: never from a bypass/exemption/trusted-
     * browser-itself shortcut, which return before this could be
     * reached). Returns the PLAINTEXT token for the caller to place in
     * a cookie — this is the one and only time the plaintext exists
     * outside the browser; it is never stored, logged, or returned
     * again after this call.
     *
     * $deviceLabel is free-text, admin/user-facing metadata only (e.g. a
     * truncated User-Agent string) — never used for any security
     * decision, purely for the revocation UI so a person can tell their
     * trusted devices apart.
     */
    public static function create(int $userId, string $userType, string $deviceLabel, string $ip): ?string
    {
        if($userId <= 0) {
            return null;
        }
        $raw = self::generateToken();
        $now = date("Y-m-d H:i:s");
        $expires = date("Y-m-d H:i:s", time() + (self::DEFAULT_DAYS * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->insert([
                "user_id" => $userId,
                "user_type" => $userType,
                "token_hash" => self::hashToken($raw),
                "device_label" => mb_substr($deviceLabel, 0, 255),
                "created_ip" => mb_substr($ip, 0, 45),
                "created_at" => $now,
                "last_used_at" => null,
                "expires_at" => $expires,
                "revoked_at" => null,
            ]);
        } catch (\Throwable $e) {
            return null;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.trusted_browser.created", "A browser was remembered for " . self::DEFAULT_DAYS . " days for " . $userType . " #" . $userId . ".", ["user_id" => $userId, "user_type" => $userType]);
        }
        return $raw;
    }

    public static function revoke(int $id, string $actorLabel): void
    {
        $now = date("Y-m-d H:i:s");
        try {
            $row = \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $id)->first();
            if(!$row || $row->revoked_at) {
                return;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("id", $id)->update(["revoked_at" => $now]);
        } catch (\Throwable $e) {
            return;
        }
        if(function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.trusted_browser.revoked", "A trusted browser was revoked.", ["trusted_browser_id" => $id, "user_id" => $row->user_id, "user_type" => $row->user_type, "actor" => $actorLabel]);
        }
    }

    /**
     * Revokes EVERY trusted browser for one exact identity — used both
     * by the client-facing "revoke all" control and automatically by
     * disableAllMethods()/TotpEnrollmentService::reset() (Section
     * "Password / 2FA changes" — invalidate on 2FA disable/reset).
     */
    public static function revokeAll(int $userId, string $userType, string $actorLabel): int
    {
        $now = date("Y-m-d H:i:s");
        try {
            $ids = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("revoked_at")->pluck("id");
            if(!$ids || !count($ids)) {
                return 0;
            }
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("revoked_at")
                ->update(["revoked_at" => $now]);
        } catch (\Throwable $e) {
            return 0;
        }
        $count = count($ids);
        if($count > 0 && function_exists("security_pack_record_event")) {
            security_pack_record_event("2fa.trusted_browser.revoked", "All (" . $count . ") trusted browsers revoked for " . $userType . " #" . $userId . ".", ["user_id" => $userId, "user_type" => $userType, "count" => $count, "actor" => $actorLabel]);
        }
        return $count;
    }

    /** @return array every non-revoked (but possibly expired) trusted browser row for one identity, newest first */
    public static function listForIdentity(int $userId, string $userType): array
    {
        try {
            $rows = \Illuminate\Database\Capsule\Manager::table(self::TABLE)
                ->where("user_id", $userId)->where("user_type", $userType)->whereNull("revoked_at")
                ->orderBy("id", "DESC")->get();
            return $rows ? $rows->toArray() : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    public static function purgeExpired(int $retentionDaysAfterExpiry = 30): void
    {
        $cutoff = date("Y-m-d H:i:s", time() - ($retentionDaysAfterExpiry * 86400));
        try {
            \Illuminate\Database\Capsule\Manager::table(self::TABLE)->where("expires_at", "<", $cutoff)->delete();
        } catch (\Throwable $e) {
        }
    }
}
