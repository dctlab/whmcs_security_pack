<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — the ONE canonical list of 2FA identity types
 * (2026-08-22 sub-account foundation phase — Requirements doc Section 4:
 * "Sub-Account 2FA Rules").
 *
 * Every 2FA table/service in this codebase (TwoFactorBypassService,
 * RateLimiter, each provider's own config table, TwoFactorAuthenticationService)
 * already keys strictly off the exact pair `(int $userId, string $userType)`
 * as a free-text column — never a database-level enum — so a THIRD
 * identity type slots in cleanly at the storage layer with zero schema
 * change and, because every row is already scoped by the exact pair, a
 * future "contact" identity's rows are already isolated from its parent
 * client's rows by construction (a different $userType value is a
 * different row set — nothing to "not inherit" because nothing was ever
 * shared).
 *
 * What WAS broken: several admin-facing spots read `$_POST["user_type"]`
 * with a raw binary ternary (`=== "admin" ? "admin" : "client"`), which
 * silently coalesced any unrecognized value — including a future
 * "contact" — into "client". That's not just an omission: it would have
 * misfiled a sub-account's bypass/action under its PARENT client's
 * identity, the exact cross-contamination the requirements doc's
 * "Critical security rule" forbids. This class is the fix — every one of
 * those spots now normalizes through here instead of a bespoke ternary.
 *
 * IMPORTANT — scope of this class: this is identity BOOKKEEPING only
 * (which string is valid, what it displays as). It intentionally knows
 * NOTHING about how a WHMCS sub-account/contact actually logs in, how
 * that session is identified, or whether WHMCS's own security-module
 * contract distinguishes a contact from its parent client at
 * challenge/activate time — those are UNVERIFIED platform questions
 * (see the class docblock on the not-yet-written live-enforcement
 * wiring) that must be checked against a live WHMCS install before any
 * code calls TwoFactorProviderInterface methods with
 * `userType = self::CONTACT` for a REAL logged-in session. Until that
 * verification happens, CONTACT exists here only so admin forms/reports
 * are ready to isolate that data correctly the day it does show up —
 * not because anything in this codebase creates contact-typed rows yet.
 */
class UserIdentityType
{
    public const CLIENT = "client";
    public const ADMIN = "admin";
    public const CONTACT = "contact";

    /** @var string[] */
    public const ALL = [self::CLIENT, self::ADMIN, self::CONTACT];

    /**
     * Normalizes untrusted input (e.g. raw `$_POST["user_type"]`) to one
     * of the known identity types, falling back to $default for
     * anything else — including empty/missing input. Replaces every
     * previous `=== "admin" ? "admin" : "client"` binary coalesce in
     * this codebase; the difference is a THIRD valid value now survives
     * normalization instead of being silently downgraded to "client".
     */
    public static function normalize(?string $raw, string $default = self::CLIENT): string
    {
        $raw = is_string($raw) ? $raw : "";
        return in_array($raw, self::ALL, true) ? $raw : $default;
    }

    public static function label(string $type): string
    {
        switch ($type) {
            case self::ADMIN:
                return "Administrator";
            case self::CONTACT:
                return "Sub-Account / Contact";
            default:
                return "Client/User";
        }
    }
}
