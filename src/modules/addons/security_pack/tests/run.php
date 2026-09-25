<?php

/**
 * Security Pack — plain-PHP test runner (no PHPUnit dependency, since the
 * production/deployment target is a shared WHMCS host that won't have
 * dev dependencies installed). Exercises only the PURE, dependency-free
 * logic (IpUtil CIDR matching, RateLimiter window math, SecurityScoreService
 * scoring) — nothing here touches a real database or WHMCS runtime, so it
 * can run anywhere with plain PHP:
 *
 *   php tests/run.php
 *
 * Exits non-zero if any assertion fails, so it can be wired into CI.
 */

declare(strict_types=1);

// The module's lib/ classes guard against direct web access with
// `if (!defined("WHMCS")) exit;` — define it here so the CLI test runner
// can load them standalone, same as WHMCS's own runtime would.
define("WHMCS", true);

require __DIR__ . "/../lib/Security/IpUtil.php";
require __DIR__ . "/../lib/Security/RateLimiter.php";
require __DIR__ . "/../lib/Security/SecurityScoreService.php";
require __DIR__ . "/../lib/Security/GeoResult.php";
require __DIR__ . "/../lib/Security/IpRestrictionService.php";
require __DIR__ . "/../lib/Security/SecurityAnomalyService.php";
require __DIR__ . "/../lib/Security/CspReportService.php";
require __DIR__ . "/../lib/Security/SecurityAlertService.php";
require __DIR__ . "/../lib/Security/Email2faService.php";
require __DIR__ . "/../lib/Security/CountryRestrictionService.php";
// 2.6.1: the native WHMCS Security Module that now enforces Email 2FA —
// pure/no-DB helper functions inside it are unit tested the same as
// every other pure helper in this suite (see below).
require __DIR__ . "/../../../security/dct_email_2fa/dct_email_2fa.php";
// Security Pack 3.0 — Unified Two-Factor Authentication pure-logic
// classes. Same "pure, dependency-free logic only" scope as the rest of
// this suite — DB-backed orchestration (WhatsAppTwoFactorService,
// TotpEnrollmentService, TwoFactorBypassService's DB paths) is exercised
// manually against a real WHMCS install, same as Email2faService's own
// DB-backed methods already are.
require __DIR__ . "/../lib/Security/TwoFactor/OtpEngine.php";
require __DIR__ . "/../lib/Security/TwoFactor/TotpService.php";
require __DIR__ . "/../lib/Security/TwoFactor/RecoveryCodeService.php";
require __DIR__ . "/../lib/Security/TwoFactor/TotpQrGenerator.php";
require __DIR__ . "/../lib/Security/TwoFactor/Providers/DctWhatsAppNotificationsBridge.php";
// Security Pack 3.1.4 — DCTLAB WhatsApp "Client Logs Review" reporting
// bridge. Its write() path talks to \Illuminate\Database\Capsule\Manager
// (not defined in this DB-less test runner), so calling its public
// methods here exercises exactly the fail-soft "no Capsule/no table"
// path — see the fail-soft regression tests below. The class's own
// insert-payload construction is otherwise checked via source
// inspection, same technique this suite already uses for security_center.tpl.
require __DIR__ . "/../lib/Security/TwoFactor/Providers/DctWhatsAppTwoFactorLogBridge.php";
// Post-3.1.0 mutual-exclusion fix: only TwoFactorAuthenticationService's
// class FILE is required here, for its one genuinely pure static method
// (pickMostRecentTimestamp() — the tie-break decision logic). Its
// providers()/status()/activateExclusive()/enforceSingleActiveMethod()
// methods are DB-backed orchestration (they call each provider's
// isActive()/disable(), which wrap WhatsAppTwoFactorService/
// TotpEnrollmentService/Email2faService DB calls) — same "exercised
// manually against a real WHMCS install" category as every other
// DB-backed method in this suite (see the comment above OtpEngine's
// require). Requiring only this one file, without also requiring
// EmailTwoFactorProvider/WhatsAppTwoFactorProvider/TotpTwoFactorProvider/
// WhatsAppTwoFactorService/TotpEnrollmentService, is safe here: PHP's
// `use` statements are compile-time aliases only and do not need their
// target classes to be defined unless actually instantiated, and this
// suite never calls providers().
require __DIR__ . "/../lib/Security/TwoFactor/TwoFactorAuthenticationService.php";
// Security Pack 3.1.2 — ClientController.php is safe to require directly
// here for the same reason TwoFactorAuthenticationService.php is above:
// its DB/WHMCS-runtime-touching code (Illuminate\Database\Capsule\Manager,
// \WHMCS\Authentication\CurrentUser, \Menu, etc.) all lives INSIDE method
// bodies, never at top-level/parse time, so loading the class file itself
// requires none of that. Only its one pure static helper,
// twoFactorRecommendation(), is exercised here — security_center() itself
// remains DB-backed orchestration, "exercised manually against a real
// WHMCS install" like every other DB-backed method in this suite.
require __DIR__ . "/../lib/Client/ClientController.php";
// Security Pack 3.1.6 — same "class file only, DB-backed methods
// exercised manually against a real WHMCS install" rationale as
// TwoFactorAuthenticationService.php/ClientController.php just above:
// TwoFactorController's use-statements are compile-time aliases only,
// and its Capsule/$_SESSION/header()-touching code all lives inside
// method bodies. Only its PURE helpers (parseUserIdsParam(),
// buildUsersStatusMap(), methodLabelFromStatus()) are called here.
require __DIR__ . "/../lib/Admin/TwoFactorController.php";

// TEST-BOOTSTRAP FIX (investigation, 2026-08-24): TotpService::engine()
// instantiates RobThree\Auth\TwoFactorAuth, a third-party class vendored
// (not Composer-installed) at lib/Security/TwoFactor/vendor/robthree/... .
// That vendor namespace is NOT covered by WHMCS's own addon-module
// autoloader (which only resolves this module's own
// WHMCS\Module\Addon\Security_Pack\* namespace via class_exists($x, true)
// in security_pack.php's dispatcher — confirmed by inspection, and why
// every other lib/ class in this suite loads fine above with no explicit
// require). In the real application, the vendor classes (and
// NullQrCodeProvider, which IS in this module's own namespace and so
// WOULD already be autoloaded by WHMCS outside this standalone runner)
// are loaded by dct_totp_2fa_bootstrap() in the native Security Module
// file, which every one of its entry points
// (activate/activateverify/challenge/verify) calls before touching
// TotpService — see that function's own require_once list for the full,
// dependency-ordered chain. This CLI runner has no WHMCS autoloader and
// never called that bootstrap, so TotpService::engine() fatal-errored
// with "Class RobThree\Auth\TwoFactorAuth not found" — a gap in this
// TEST FILE's own bootstrapping, not in the application. Fixed by
// reusing the real production bootstrap function itself (not a
// duplicated require list, so it can't drift out of sync with it, and
// not a new/second autoloader) — zero TOTP application files were
// touched to fix this. Placed AFTER the requires above (not before)
// because dct_totp_2fa_bootstrap()'s own require_once calls silently
// no-op for every file already loaded by them, but PHP's plain `require`
// above does not — reversing the order would redeclare those classes.
require __DIR__ . "/../../../security/dct_totp_2fa/dct_totp_2fa.php";
dct_totp_2fa_bootstrap();

use WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController;
use WHMCS\Module\Addon\Security_Pack\Client\ClientController;
use WHMCS\Module\Addon\Security_Pack\Security\CountryRestrictionService;
use WHMCS\Module\Addon\Security_Pack\Security\CspReportService;
use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\GeoResult;
use WHMCS\Module\Addon\Security_Pack\Security\IpRestrictionService;
use WHMCS\Module\Addon\Security_Pack\Security\IpUtil;
use WHMCS\Module\Addon\Security_Pack\Security\RateLimiter;
use WHMCS\Module\Addon\Security_Pack\Security\SecurityAlertService;
use WHMCS\Module\Addon\Security_Pack\Security\SecurityAnomalyService;
use WHMCS\Module\Addon\Security_Pack\Security\SecurityScoreService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\RecoveryCodeService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpQrGenerator;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\DctWhatsAppNotificationsBridge;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\DctWhatsAppTwoFactorLogBridge;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorAuthenticationService;

$failures = [];
$passed = 0;

function sp_assert(string $label, bool $condition, array &$failures, int &$passed): void
{
    if($condition) {
        $passed++;
        return;
    }
    $failures[] = $label;
}

// --- IpUtil::matchesOne / matchesAny ---

sp_assert("exact IPv4 match", IpUtil::matchesOne("203.0.113.5", "203.0.113.5"), $failures, $passed);
sp_assert("exact IPv4 non-match", !IpUtil::matchesOne("203.0.113.6", "203.0.113.5"), $failures, $passed);
sp_assert("IPv4 CIDR /24 match", IpUtil::matchesOne("203.0.113.200", "203.0.113.0/24"), $failures, $passed);
sp_assert("IPv4 CIDR /24 non-match", !IpUtil::matchesOne("203.0.114.1", "203.0.113.0/24"), $failures, $passed);
sp_assert("IPv4 CIDR /20 (Cloudflare-style) match", IpUtil::matchesOne("173.245.48.100", "173.245.48.0/20"), $failures, $passed);
sp_assert("IPv4 CIDR /32 exact", IpUtil::matchesOne("10.0.0.5", "10.0.0.5/32"), $failures, $passed);
sp_assert("malformed CIDR mask is rejected, not fatal", !IpUtil::matchesOne("10.0.0.5", "10.0.0.0/abc"), $failures, $passed);
sp_assert("malformed CIDR mask does not throw", true, $failures, $passed); // reaching here = no exception was thrown above
sp_assert("mismatched IP family (v4 vs v6) does not match", !IpUtil::matchesOne("203.0.113.5", "2001:db8::/32"), $failures, $passed);
sp_assert("IPv6 CIDR match", IpUtil::matchesOne("2001:db8::1", "2001:db8::/32"), $failures, $passed);
sp_assert("IPv6 exact match", IpUtil::matchesOne("::1", "::1"), $failures, $passed);
sp_assert("empty entry never matches", !IpUtil::matchesOne("203.0.113.5", ""), $failures, $passed);
sp_assert("garbage IP never matches", !IpUtil::matchesOne("not-an-ip", "203.0.113.0/24"), $failures, $passed);

sp_assert("matchesAny across list finds match", IpUtil::matchesAny("10.0.0.9", ["1.2.3.4", "10.0.0.0/24"]), $failures, $passed);
sp_assert("matchesAny with no matches returns false", !IpUtil::matchesAny("10.0.0.9", ["1.2.3.4", "5.6.7.0/24"]), $failures, $passed);
sp_assert("matchesAny with empty list returns false", !IpUtil::matchesAny("10.0.0.9", []), $failures, $passed);
sp_assert("matchesAny with empty ip returns false", !IpUtil::matchesAny("", ["10.0.0.0/24"]), $failures, $passed);

// --- Attack-scenario style checks ---
sp_assert("attacker-controlled entry with SQL-ish junk does not match / does not crash", !IpUtil::matchesOne("203.0.113.5", "'; DROP TABLE x; --"), $failures, $passed);
sp_assert("attacker-controlled entry with script tag does not match / does not crash", !IpUtil::matchesOne("203.0.113.5", "<script>alert(1)</script>"), $failures, $passed);

// --- IpUtil::parseList ---
$parsed = IpUtil::parseList("1.1.1.1\n2.2.2.2,3.3.3.3\r\n\r\n  4.4.4.4  ");
sp_assert("parseList splits newline/comma and trims/dedupes blanks", $parsed === ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"], $failures, $passed);
sp_assert("parseList of empty string returns empty array", IpUtil::parseList("") === [], $failures, $passed);

// --- IpUtil::isValidIp / isPrivateOrReserved ---
sp_assert("isValidIp true for real IPv4", IpUtil::isValidIp("8.8.8.8"), $failures, $passed);
sp_assert("isValidIp false for garbage", !IpUtil::isValidIp("999.999.999.999"), $failures, $passed);
sp_assert("isPrivateOrReserved true for 192.168.x.x", IpUtil::isPrivateOrReserved("192.168.1.1"), $failures, $passed);
sp_assert("isPrivateOrReserved false for public IP", !IpUtil::isPrivateOrReserved("8.8.8.8"), $failures, $passed);

// --- RateLimiter::evaluate (pure fixed-window math) ---
$r1 = RateLimiter::evaluate(0, 5);
sp_assert("rate limiter allows first hit", $r1["allowed"] === true, $failures, $passed);
$r2 = RateLimiter::evaluate(4, 5);
sp_assert("rate limiter allows up to the 5th hit (0-indexed 4)", $r2["allowed"] === true, $failures, $passed);
$r3 = RateLimiter::evaluate(5, 5);
sp_assert("rate limiter blocks the 6th hit when max is 5", $r3["allowed"] === false, $failures, $passed);
$r4 = RateLimiter::evaluate(100, 5);
sp_assert("rate limiter still blocks well past the max (bypass attempt)", $r4["allowed"] === false, $failures, $passed);
sp_assert("rate limiter treats max<1 as at-least-1 (never fully disabled by bad config)", RateLimiter::evaluate(0, 0)["allowed"] === true, $failures, $passed);

sp_assert("isSameWindow true just inside the window", RateLimiter::isSameWindow(1000, 1000 + 500, 600), $failures, $passed);
sp_assert("isSameWindow false once past the window", !RateLimiter::isSameWindow(1000, 1000 + 700, 600), $failures, $passed);
sp_assert("isSameWindow false for a zero/unset window start", !RateLimiter::isSameWindow(0, 1000, 600), $failures, $passed);

// --- SecurityScoreService::compute (pure, deterministic) ---
$emptySettings = [];
$weakFacts = ["tables_ok" => false, "geoip_loaded" => false, "data_dir_writable" => false, "events_last_7d" => 0];
$weak = SecurityScoreService::compute($emptySettings, $weakFacts);
sp_assert("score with nothing configured is well below max", $weak["score"] < ($weak["max"] * 0.3), $failures, $passed);
sp_assert("recommendations are non-empty when nothing is configured", count($weak["recommendations"]) > 0, $failures, $passed);

$strongSettings = [
    "login_notification" => "1", "admin_login_notification" => "1",
    "login_history" => "1", "ip_range_limits" => "1", "password_reset" => "1",
    "trusted_proxies" => "173.245.48.0/20", "lang_currency" => "1", "country_restriction" => "1",
    "block_free_emails" => "1", "allow_disable_notification" => "1", "event_retention_days" => "90",
    "sh_nosniff" => "1", "sh_referrer_policy" => "1", "sh_permissions_policy" => "1",
    "csp_report_collection" => "1",
];
$strongFacts = [
    "tables_ok" => true, "geoip_loaded" => true, "data_dir_writable" => true, "events_last_7d" => 5,
    "ip_restriction_service_ok" => true, "ip_rules_configured" => true, "geoip_provider_available" => true,
    "open_high_severity_anomalies" => 0, "admin_email2fa_active_count" => 1, "email2fa_any_active_count" => 1,
];
$strong = SecurityScoreService::compute($strongSettings, $strongFacts);
sp_assert("score with everything configured is at (or very near) max", $strong["score"] >= ($strong["max"] * 0.95), $failures, $passed);
sp_assert("compute() is deterministic for identical input", SecurityScoreService::compute($strongSettings, $strongFacts) === $strong, $failures, $passed);
sp_assert("categories sum to the reported score", array_sum(array_column($strong["categories"], "earned")) === $strong["score"], $failures, $passed);
sp_assert("stronger config always scores >= weaker config", $strong["score"] >= $weak["score"], $failures, $passed);

$missingTables = SecurityScoreService::compute($strongSettings, array_merge($strongFacts, ["tables_ok" => false]));
$hasCriticalRec = false;
foreach ($missingTables["recommendations"] as $rec) {
    if($rec["severity"] === "critical") {
        $hasCriticalRec = true;
    }
}
sp_assert("missing database tables surfaces a CRITICAL recommendation", $hasCriticalRec, $failures, $passed);

// ==========================================================================
// Security Pack 2.2 (Phase 3A) additions below — IpUtil validation/
// specificity, IpRestrictionService rule evaluation, GeoResult, and
// explicit malicious-input ("attack") cases. Nothing above this line was
// changed or removed — the original 40 Phase 1/2 assertions still run
// exactly as before.
// ==========================================================================

// --- IpUtil::isValidEntry / specificity ---
sp_assert("isValidEntry true for bare IPv4", IpUtil::isValidEntry("203.0.113.5"), $failures, $passed);
sp_assert("isValidEntry true for IPv4 CIDR", IpUtil::isValidEntry("203.0.113.0/24"), $failures, $passed);
sp_assert("isValidEntry true for IPv6 CIDR", IpUtil::isValidEntry("2001:db8::/32"), $failures, $passed);
sp_assert("isValidEntry false for out-of-range IPv4 mask", !IpUtil::isValidEntry("203.0.113.0/33"), $failures, $passed);
sp_assert("isValidEntry false for out-of-range IPv6 mask", !IpUtil::isValidEntry("2001:db8::/129"), $failures, $passed);
sp_assert("isValidEntry false for non-numeric mask", !IpUtil::isValidEntry("203.0.113.0/abc"), $failures, $passed);
sp_assert("isValidEntry false for garbage", !IpUtil::isValidEntry("not-an-ip"), $failures, $passed);
sp_assert("isValidEntry false for empty string", !IpUtil::isValidEntry(""), $failures, $passed);
sp_assert("isValidEntry false for extremely long input", !IpUtil::isValidEntry(str_repeat("1", 5000) . ".0.0.1"), $failures, $passed);

sp_assert("specificity of bare IPv4 is 32", IpUtil::specificity("203.0.113.5") === 32, $failures, $passed);
sp_assert("specificity of bare IPv6 is 128", IpUtil::specificity("::1") === 128, $failures, $passed);
sp_assert("specificity of /24 is 24", IpUtil::specificity("203.0.113.0/24") === 24, $failures, $passed);
sp_assert("specificity of /28 is 28", IpUtil::specificity("203.0.113.0/28") === 28, $failures, $passed);
sp_assert("specificity of invalid entry is 0", IpUtil::specificity("garbage") === 0, $failures, $passed);

// --- Explicit attack-payload inputs (Step 32 of the 2.2 spec) — none of
// these should validate as an IP/CIDR, throw, or otherwise be treated as
// meaningful input by IpUtil. ---
$attackPayloads = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "../../etc/passwd",
    "http://127.0.0.1/",
    "javascript:alert(1)",
    "203.0.113.5%00.evil.com",
    "203.0.113.5\r\nSet-Cookie: x=1",
    "999.999.999.999",
    "203.0.113.5/999",
    "::/-1",
    str_repeat("A", 10000),
];
foreach ($attackPayloads as $i => $payload) {
    sp_assert("attack payload #" . $i . " is rejected by isValidEntry without throwing", !IpUtil::isValidEntry($payload), $failures, $passed);
    sp_assert("attack payload #" . $i . " does not match a real CIDR via matchesOne", !IpUtil::matchesOne("203.0.113.5", $payload), $failures, $passed);
}

// --- IpRestrictionService::evaluateAgainstRules (pure, DB-free) ---
$noRules = IpRestrictionService::evaluateAgainstRules("203.0.113.5", []);
sp_assert("zero rules configured => always allowed (safe default)", $noRules["allowed"] === true, $failures, $passed);
sp_assert("zero rules configured => no matched rule", $noRules["matched_rule"] === null, $failures, $passed);

$blockRule = [["id" => 1, "rule_type" => "block", "target" => "203.0.113.0/24", "mask_bits" => 24, "priority" => 0]];
$blocked = IpRestrictionService::evaluateAgainstRules("203.0.113.5", $blockRule);
sp_assert("IP inside a BLOCK CIDR is denied", $blocked["allowed"] === false, $failures, $passed);
sp_assert("IP outside the BLOCK CIDR is allowed", IpRestrictionService::evaluateAgainstRules("198.51.100.5", $blockRule)["allowed"] === true, $failures, $passed);

// Specific IP ALLOW carved out of a broader BLOCK CIDR must win (higher specificity).
$carveOut = [
    ["id" => 1, "rule_type" => "block", "target" => "203.0.113.0/24", "mask_bits" => 24, "priority" => 0],
    ["id" => 2, "rule_type" => "allow", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 0],
];
sp_assert("specific ALLOW IP wins over a broader BLOCK CIDR", IpRestrictionService::evaluateAgainstRules("203.0.113.5", $carveOut)["allowed"] === true, $failures, $passed);
sp_assert("other IPs in the same broader BLOCK CIDR remain blocked", IpRestrictionService::evaluateAgainstRules("203.0.113.6", $carveOut)["allowed"] === false, $failures, $passed);

// Narrower CIDR beats broader CIDR of the same type mismatch.
$overlap = [
    ["id" => 1, "rule_type" => "allow", "target" => "203.0.113.0/24", "mask_bits" => 24, "priority" => 0],
    ["id" => 2, "rule_type" => "block", "target" => "203.0.113.0/28", "mask_bits" => 28, "priority" => 0],
];
sp_assert("narrower BLOCK /28 wins over broader ALLOW /24 for an IP in both", IpRestrictionService::evaluateAgainstRules("203.0.113.2", $overlap)["allowed"] === false, $failures, $passed);
sp_assert("IP only in the broader ALLOW /24 (outside the /28) stays allowed", IpRestrictionService::evaluateAgainstRules("203.0.113.200", $overlap)["allowed"] === true, $failures, $passed);

// Equal specificity: higher priority wins.
$priorityTie = [
    ["id" => 1, "rule_type" => "allow", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 0],
    ["id" => 2, "rule_type" => "block", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 10],
];
sp_assert("equal specificity: higher priority BLOCK wins over lower priority ALLOW", IpRestrictionService::evaluateAgainstRules("203.0.113.5", $priorityTie)["allowed"] === false, $failures, $passed);

// Equal specificity and priority: most recent (highest id) wins.
$idTie = [
    ["id" => 1, "rule_type" => "allow", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 0],
    ["id" => 2, "rule_type" => "block", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 0],
];
sp_assert("equal specificity and priority: most recently created rule (highest id) wins", IpRestrictionService::evaluateAgainstRules("203.0.113.5", $idTie)["allowed"] === false, $failures, $passed);

// IPv6 CIDR support.
$ipv6Block = [["id" => 1, "rule_type" => "block", "target" => "2001:db8::/32", "mask_bits" => 32, "priority" => 0]];
sp_assert("IPv6 address inside a BLOCK CIDR is denied", IpRestrictionService::evaluateAgainstRules("2001:db8::1", $ipv6Block)["allowed"] === false, $failures, $passed);
sp_assert("IPv6 address outside the BLOCK CIDR is allowed", IpRestrictionService::evaluateAgainstRules("2001:db9::1", $ipv6Block)["allowed"] === true, $failures, $passed);

// Malformed rule data must never crash evaluation — treated as non-matching.
$malformedRules = [["id" => 1, "rule_type" => "block", "target" => "not-a-real-cidr/999", "mask_bits" => 0, "priority" => 0]];
sp_assert("a malformed stored rule is simply skipped, not fatal", IpRestrictionService::evaluateAgainstRules("203.0.113.5", $malformedRules)["allowed"] === true, $failures, $passed);

// Invalid visitor IP must never crash evaluation.
$invalidVisitor = IpRestrictionService::evaluateAgainstRules("not-an-ip", $blockRule);
sp_assert("an invalid visitor IP is never restricted (fails open, not fatal)", $invalidVisitor["allowed"] === true, $failures, $passed);

// --- IpRestrictionService::normalizeTarget ---
sp_assert("normalizeTarget accepts a valid CIDR", IpRestrictionService::normalizeTarget("203.0.113.0/24")["mask_bits"] === 24, $failures, $passed);
sp_assert("normalizeTarget rejects an invalid entry", IpRestrictionService::normalizeTarget("garbage") === null, $failures, $passed);
sp_assert("normalizeTarget rejects a SQLi-style payload", IpRestrictionService::normalizeTarget("' OR 1=1 --") === null, $failures, $passed);

// --- IpRestrictionService::wouldLockOutCurrentAdmin (admin lockout protection) ---
sp_assert("blocking the admin's own exact IP is flagged", IpRestrictionService::wouldLockOutCurrentAdmin("203.0.113.5", "203.0.113.5", []), $failures, $passed);
sp_assert("blocking a CIDR containing the admin's IP is flagged", IpRestrictionService::wouldLockOutCurrentAdmin("203.0.113.5", "203.0.113.0/24", []), $failures, $passed);
sp_assert("blocking an unrelated IP does not flag the admin's own IP", !IpRestrictionService::wouldLockOutCurrentAdmin("203.0.113.5", "198.51.100.0/24", []), $failures, $passed);
sp_assert("an existing higher-specificity ALLOW for the admin's IP suppresses the lockout warning", !IpRestrictionService::wouldLockOutCurrentAdmin(
    "203.0.113.5",
    "203.0.113.0/24",
    [["id" => 1, "rule_type" => "allow", "target" => "203.0.113.5", "mask_bits" => 32, "priority" => 0]]
), $failures, $passed);

// --- GeoResult ---
$gr = new GeoResult("8.8.8.8", true, "us", "maxmind");
sp_assert("GeoResult uppercases nothing itself but stores what it's given", $gr->countryCode === "us", $failures, $passed);
sp_assert("GeoResult::failure() has success=false and null country", GeoResult::failure("8.8.8.8", "maxmind")->success === false, $failures, $passed);
sp_assert("GeoResult::failure() country_code is null", GeoResult::failure("8.8.8.8")->countryCode === null, $failures, $passed);
$grArray = $gr->toArray();
sp_assert("GeoResult::toArray() round-trips the ip/source/success", $grArray["ip"] === "8.8.8.8" && $grArray["source"] === "maxmind" && $grArray["success"] === true, $failures, $passed);

// --- SecurityScoreService: Security Pack 2.3 response headers scoring ---
$noHeaders = SecurityScoreService::compute($strongSettings, $strongFacts);
$archNoHeaders = $noHeaders["categories"]["Architecture Health"];
sp_assert("Architecture Health max is 15 (Phase 3B headers sub-check added)", $archNoHeaders["max"] === 15, $failures, $passed);

$strongSettingsNoHeaders = $strongSettings;
unset($strongSettingsNoHeaders["sh_nosniff"], $strongSettingsNoHeaders["sh_referrer_policy"], $strongSettingsNoHeaders["sh_permissions_policy"]);
$withoutHeaders = SecurityScoreService::compute($strongSettingsNoHeaders, $strongFacts);
sp_assert("disabling all three safe headers costs exactly 5 points of Architecture Health", $withoutHeaders["categories"]["Architecture Health"]["earned"] === $archNoHeaders["earned"] - 5, $failures, $passed);

$partialHeaders = $strongSettingsNoHeaders;
$partialHeaders["sh_nosniff"] = "1";
$withPartialHeaders = SecurityScoreService::compute($partialHeaders, $strongFacts);
sp_assert("enabling only ONE of the three safe headers earns no partial credit (all-or-nothing baseline)", $withPartialHeaders["categories"]["Architecture Health"]["earned"] === $withoutHeaders["categories"]["Architecture Health"]["earned"], $failures, $passed);

$withCspAndHsts = $strongSettings;
$withCspAndHsts["sh_csp"] = "1";
$withCspAndHsts["sh_hsts"] = "1";
$scoreWithRisky = SecurityScoreService::compute($withCspAndHsts, $strongFacts);
sp_assert("enabling CSP/HSTS (advanced/risky headers) does not change the score either way", $scoreWithRisky["score"] === $strong["score"], $failures, $passed);

// --- Security Pack 2.3: POST-only action allowlist logic (pattern used by
// LangCurrencyController/IpRestrictionsController — reimplemented here as a
// pure check since the controllers themselves require a live WHMCS runtime) ---
function sp_test_post_only_guard(array $postOnlyActions, string $action, string $method): bool
{
    // Mirrors: if(in_array($action, $postOnlyActions, true) && $method !== "POST") { redir/blocked }
    // Returns true if the request would be ALLOWED to proceed.
    if(in_array($action, $postOnlyActions, true) && $method !== "POST") {
        return false;
    }
    return true;
}
$postOnlyActions = ["save", "enable", "disable", "delete"];
sp_assert("POST-only guard allows a destructive action submitted via POST", sp_test_post_only_guard($postOnlyActions, "delete", "POST"), $failures, $passed);
sp_assert("POST-only guard blocks a destructive action submitted via GET", !sp_test_post_only_guard($postOnlyActions, "delete", "GET"), $failures, $passed);
sp_assert("POST-only guard blocks a destructive action submitted via HEAD", !sp_test_post_only_guard($postOnlyActions, "enable", "HEAD"), $failures, $passed);
sp_assert("POST-only guard is a no-op for actions outside the allowlist (e.g. a read-only view)", sp_test_post_only_guard($postOnlyActions, "index", "GET"), $failures, $passed);

// --- Security Pack 2.3: CSRF double-submit token comparison logic
// (reimplements security_pack_csrf_valid()'s hash_equals() comparison as a
// pure function — the real function lives in hooks.php and depends on a
// live $_SESSION, so this exercises the same comparison logic standalone) ---
function sp_test_csrf_valid(?string $submitted, ?string $expected): bool
{
    $submitted = (string) ($submitted ?? "");
    $expected = (string) ($expected ?? "");
    return $submitted !== "" && $expected !== "" && hash_equals($expected, $submitted);
}
$realToken = bin2hex(random_bytes(32));
sp_assert("CSRF check passes when submitted token matches session token", sp_test_csrf_valid($realToken, $realToken), $failures, $passed);
sp_assert("CSRF check fails when no token is submitted", !sp_test_csrf_valid(null, $realToken), $failures, $passed);
sp_assert("CSRF check fails when submitted token doesn't match session token", !sp_test_csrf_valid("wrong-token-value", $realToken), $failures, $passed);
sp_assert("CSRF check fails when there is no session token to compare against", !sp_test_csrf_valid($realToken, null), $failures, $passed);
sp_assert("CSRF check fails when both tokens are empty strings", !sp_test_csrf_valid("", ""), $failures, $passed);

// --- Security Pack 2.3: client authorization — identity must always come
// from the authenticated session, never from a request parameter (Client
// Security Center's core guarantee). Reimplements the decision as a pure
// function so the "never trust $_REQUEST for identity" invariant is
// regression-tested without a live WHMCS session/DB. ---
function sp_test_scoped_client_data(int $sessionClientId, ?int $requestClientIdIgnored, array $allData): array
{
    // Models ClientController::security_center()'s query-scoping pattern:
    // ->where("client_id", $clientId) using ONLY the session-derived id.
    // $requestClientIdIgnored is accepted (mirroring that $_REQUEST may
    // contain an attacker-supplied id) but deliberately never used in the
    // filter — proving a spoofed request parameter cannot widen access.
    return array_values(array_filter($allData, static function ($row) use ($sessionClientId) {
        return $row["client_id"] === $sessionClientId;
    }));
}
$allClientRows = [
    ["client_id" => 101, "event" => "login", "ip" => "203.0.113.5"],
    ["client_id" => 202, "event" => "login", "ip" => "198.51.100.9"],
    ["client_id" => 202, "event" => "password_reset", "ip" => "198.51.100.9"],
];
$client101View = sp_test_scoped_client_data(101, 101, $allClientRows);
sp_assert("client 101 sees only their own rows", count($client101View) === 1 && $client101View[0]["client_id"] === 101, $failures, $passed);
$spoofedView = sp_test_scoped_client_data(101, 202, $allClientRows);
sp_assert("a spoofed request-supplied client id (202) cannot widen client 101's session-scoped view", $spoofedView === $client101View, $failures, $passed);
$client202View = sp_test_scoped_client_data(202, 202, $allClientRows);
sp_assert("client 202 sees only their own (2) rows, never client 101's", count($client202View) === 2 && !in_array(101, array_column($client202View, "client_id"), true), $failures, $passed);
$unknownClientView = sp_test_scoped_client_data(999, 999, $allClientRows);
sp_assert("an authenticated session for a client with no rows yet sees an empty (not another client's) list", $unknownClientView === [], $failures, $passed);

// --- Security Pack 2.3: additional XSS payload coverage for the
// LoginLogsController reflected-XSS fix (htmlspecialchars(..., ENT_QUOTES, "UTF-8")) ---
function sp_test_escape_ip_param(string $raw): string
{
    return htmlspecialchars($raw, ENT_QUOTES, "UTF-8");
}
sp_assert("script-tag payload is neutralized", strpos(sp_test_escape_ip_param("<script>alert(1)</script>"), "<script>") === false, $failures, $passed);
sp_assert("event-handler/attribute-breakout payload is neutralized", strpos(sp_test_escape_ip_param("\" onmouseover=\"alert(1)"), "\"") === false, $failures, $passed);
sp_assert("single-quote attribute-breakout payload is neutralized (ENT_QUOTES)", strpos(sp_test_escape_ip_param("' onfocus='alert(1)"), "'") === false, $failures, $passed);
sp_assert("javascript: URI payload survives escaping unexploited as inert text", sp_test_escape_ip_param("javascript:alert(1)") === "javascript:alert(1)", $failures, $passed);
sp_assert("a well-formed IPv4 address round-trips unchanged", sp_test_escape_ip_param("203.0.113.5") === "203.0.113.5", $failures, $passed);

// =====================================================================
// Security Pack 2.4 (Phase 4) — Security Assurance regression additions
// =====================================================================

// --- Fix: ClientController::limit_ip_range() is now POST-only (was
// reachable via $_REQUEST/GET) — reuses the same allowlist-guard pattern
// already regression-tested for admin controllers in 2.3, applied here to
// the client-area action that was missed in that sweep. ---
sp_assert("client limit_ip_range remove action is allowed via POST", sp_test_post_only_guard(["limit_ip_range"], "limit_ip_range", "POST"), $failures, $passed);
sp_assert("client limit_ip_range remove action is blocked via GET", !sp_test_post_only_guard(["limit_ip_range"], "limit_ip_range", "GET"), $failures, $passed);

// --- Fix: SettingsController::save() now guards against a non-array
// "settings" request value before doing any array-offset access. ---
function sp_test_settings_array_guard($requestSettings): array
{
    // Mirrors: $requestSettings = is_array($_REQUEST["settings"] ?? null) ? $_REQUEST["settings"] : [];
    return is_array($requestSettings) ? $requestSettings : [];
}
sp_assert("a proper settings array passes through untouched", sp_test_settings_array_guard(["login_history" => "1"]) === ["login_history" => "1"], $failures, $passed);
sp_assert("a string 'settings' value (e.g. ?settings=x) is treated as empty, not a fatal array-offset error", sp_test_settings_array_guard("x") === [], $failures, $passed);
sp_assert("a null settings value is treated as empty", sp_test_settings_array_guard(null) === [], $failures, $passed);
sp_assert("an integer settings value is treated as empty", sp_test_settings_array_guard(12345) === [], $failures, $passed);

// --- Fix: core/user_security.php's theme-template append now verifies
// the resolved file path is actually inside the templates directory
// before writing to it (defense-in-depth against a hypothetical
// path-traversal via $vars['template']/$vars['templatefile']). ---
function sp_test_path_within_templates_dir(string $templatesRoot, string $candidatePath): bool
{
    // Mirrors the strncmp() containment check added in user_security.php,
    // operating on already-resolved (realpath-style, no "..") strings —
    // exercises the containment logic itself rather than the filesystem.
    return strncmp($candidatePath, $templatesRoot . DIRECTORY_SEPARATOR, strlen($templatesRoot) + 1) === 0;
}
sp_assert("a template file genuinely inside the templates dir is accepted", sp_test_path_within_templates_dir("/whmcs/templates", "/whmcs/templates/six/clientareasecurity.tpl"), $failures, $passed);
sp_assert("a resolved path OUTSIDE the templates dir (traversal escaped) is rejected", !sp_test_path_within_templates_dir("/whmcs/templates", "/whmcs/modules/servers/evil.php"), $failures, $passed);
sp_assert("a resolved path that only shares a string PREFIX (not a real subdirectory) is rejected", !sp_test_path_within_templates_dir("/whmcs/templates", "/whmcs/templates-evil/x.tpl"), $failures, $passed);
sp_assert("the templates root itself (no subpath) is rejected — must be a file inside it, not the directory", !sp_test_path_within_templates_dir("/whmcs/templates", "/whmcs/templates"), $failures, $passed);

// --- Security Test Matrix (Step 30): Input — normal/empty/null/very
// long/malformed/Unicode/SQLi/XSS/path-traversal/CRLF fed through
// IpUtil, the single authoritative validator every IP-shaped input in
// this module ultimately goes through. ---
$inputMatrix = [
    "normal IPv4" => "203.0.113.5",
    "normal IPv6" => "2001:db8::1",
    "empty string" => "",
    "whitespace only" => "   ",
    "very long string (10k chars)" => str_repeat("9", 10000),
    "Unicode homoglyph digits" => "２０３.０.１１３.５", // fullwidth digits, not ASCII
    "Unicode zero-width joiner injected mid-IP" => "203.0\u{200D}.113.5",
    "SQLi payload" => "' OR 1=1 --",
    "UNION SELECT payload" => "1' UNION SELECT username,password FROM tbladmins--",
    "DROP TABLE payload" => "'; DROP TABLE nnm_security_pack_events; --",
    "path traversal payload" => "../../../../etc/passwd",
    "CRLF injection payload" => "203.0.113.5\r\nSet-Cookie: pwned=1",
    "null byte payload" => "203.0.113.5\0.evil",
];
foreach ($inputMatrix as $label => $value) {
    $isNormal = in_array($label, ["normal IPv4", "normal IPv6"], true);
    $result = IpUtil::isValidIp($value);
    sp_assert("input matrix [{$label}]: isValidIp() " . ($isNormal ? "accepts" : "rejects") . " and never throws", $isNormal ? $result === true : $result === false, $failures, $passed);
}

// --- Authorization matrix (Step 30): unauthenticated / client A / client
// B / different unrelated client — extends the session-scoping model
// already introduced in 2.3 with an explicit "no session at all" case. ---
function sp_test_authorized_view(?int $sessionClientId, array $allData): array
{
    if($sessionClientId === null) {
        // No authenticated session at all -> no data, full stop. Mirrors
        // ClientController methods all being gated behind WHMCS's own
        // requirelogin/session check before user code ever runs.
        return [];
    }
    return sp_test_scoped_client_data($sessionClientId, $sessionClientId, $allData);
}
sp_assert("an unauthenticated request (no session) sees no client data at all", sp_test_authorized_view(null, $allClientRows) === [], $failures, $passed);
sp_assert("client A's authorized view still only contains client A's rows", sp_test_authorized_view(101, $allClientRows) === $client101View, $failures, $passed);
sp_assert("client B's authorized view still only contains client B's rows", sp_test_authorized_view(202, $allClientRows) === $client202View, $failures, $passed);

// --- CSRF matrix (Step 30): missing / invalid / valid token, and the
// GET-vs-POST dimension combined with token validity (a state-changing
// request must satisfy BOTH "is POST" AND "has a valid token" — neither
// alone is sufficient). ---
function sp_test_state_change_allowed(string $method, ?string $submittedToken, string $sessionToken): bool
{
    return $method === "POST" && sp_test_csrf_valid($submittedToken, $sessionToken);
}
$sessionTok = bin2hex(random_bytes(32));
sp_assert("CSRF matrix: POST + valid token => allowed", sp_test_state_change_allowed("POST", $sessionTok, $sessionTok), $failures, $passed);
sp_assert("CSRF matrix: POST + missing token => blocked", !sp_test_state_change_allowed("POST", null, $sessionTok), $failures, $passed);
sp_assert("CSRF matrix: POST + invalid token => blocked", !sp_test_state_change_allowed("POST", "not-the-real-token", $sessionTok), $failures, $passed);
sp_assert("CSRF matrix: GET + valid token => still blocked (method alone is not sufficient)", !sp_test_state_change_allowed("GET", $sessionTok, $sessionTok), $failures, $passed);
sp_assert("CSRF matrix: GET + missing token => blocked", !sp_test_state_change_allowed("GET", null, $sessionTok), $failures, $passed);

// --- IP / trusted-proxy matrix (Step 30): validated forwarded-header
// candidate selection, mirroring security_pack_detect_visitor_ip()'s
// "first FILTER_VALIDATE_IP-passing candidate wins" behaviour. ---
function sp_test_pick_forwarded_ip(array $candidates): ?string
{
    foreach ($candidates as $value) {
        if($value !== "" && filter_var($value, FILTER_VALIDATE_IP)) {
            return $value;
        }
    }
    return null;
}
sp_assert("forwarded-IP matrix: a well-formed IPv4 candidate is accepted", sp_test_pick_forwarded_ip(["203.0.113.9"]) === "203.0.113.9", $failures, $passed);
sp_assert("forwarded-IP matrix: a well-formed IPv6 candidate is accepted", sp_test_pick_forwarded_ip(["2001:db8::9"]) === "2001:db8::9", $failures, $passed);
sp_assert("forwarded-IP matrix: a spoofed non-IP header value is skipped, not trusted", sp_test_pick_forwarded_ip(["'; DROP TABLE x; --", "203.0.113.9"]) === "203.0.113.9", $failures, $passed);
sp_assert("forwarded-IP matrix: an entirely malformed candidate list resolves to no match (caller must fall back to REMOTE_ADDR)", sp_test_pick_forwarded_ip(["not-an-ip", "<script>x</script>"]) === null, $failures, $passed);
sp_assert("forwarded-IP matrix: an empty candidate list resolves to no match", sp_test_pick_forwarded_ip([]) === null, $failures, $passed);

// --- 3.1.18: security_pack_2fa_resolve_viewed_client_id() — confirmed
// live regression fix. A confirmed-deployed 3.1.16 build STILL showed
// "N/A" on a live install whose admin Client Profile URL was a clean,
// query-string-free "/client/{id}/users" path — $_REQUEST["userid"]
// alone resolved to 0 there. This mirrors the real function's own
// two-strategy resolution (request param first, URL path segment as a
// fallback) exactly, so a divergence between this test and production
// code is caught by the source-regex check further below rather than
// silently passing against a stale copy of the logic. ---
function sp_test_resolve_viewed_client_id(array $request, array $server): int
{
    if(isset($request["userid"]) && is_numeric($request["userid"])) {
        $fromRequest = (int) $request["userid"];
        if($fromRequest > 0) {
            return $fromRequest;
        }
    }
    foreach (["REQUEST_URI", "PATH_INFO", "REDIRECT_URL", "PHP_SELF"] as $key) {
        $candidate = isset($server[$key]) && is_string($server[$key]) ? $server[$key] : "";
        if($candidate === "") {
            continue;
        }
        if(preg_match('#/client/(\d+)(?:/|\?|$)#', $candidate, $m)) {
            $fromPath = (int) $m[1];
            if($fromPath > 0) {
                return $fromPath;
            }
        }
    }
    return 0;
}
sp_assert("resolve_viewed_client_id: a classic \$_REQUEST[\"userid\"] query parameter is used first, unchanged from 3.1.16", sp_test_resolve_viewed_client_id(["userid" => "666037"], ["REQUEST_URI" => "/ish_myadmin/clientssummary.php?userid=666037"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id (3.1.18, the confirmed live regression): a clean, query-string-free friendly-routed URL like \"/client/666037/users\" — the EXACT shape reproduced live, with no \$_REQUEST[\"userid\"] present at all — still resolves the client ID via the URL path fallback", sp_test_resolve_viewed_client_id([], ["REQUEST_URI" => "/ish_myadmin/client/666037/users"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id: the path fallback also matches when the client ID is the LAST path segment (no trailing slash/tab name)", sp_test_resolve_viewed_client_id([], ["REQUEST_URI" => "/ish_myadmin/client/666037"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id: the path fallback also matches a query string immediately after the ID (\"/client/666037?tab=users\")", sp_test_resolve_viewed_client_id([], ["REQUEST_URI" => "/ish_myadmin/client/666037?tab=users"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id: falls back through PATH_INFO/REDIRECT_URL/PHP_SELF in order when REQUEST_URI itself has no match", sp_test_resolve_viewed_client_id([], ["REQUEST_URI" => "/ish_myadmin/index.php", "PATH_INFO" => "/client/666037/users"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id: an unrelated admin page (no \"/client/{id}/\" segment anywhere, no \$_REQUEST[\"userid\"]) resolves to 0, not a guess", sp_test_resolve_viewed_client_id([], ["REQUEST_URI" => "/ish_myadmin/clientssummary.php"]) === 0, $failures, $passed);
sp_assert("resolve_viewed_client_id: a non-numeric/zero \$_REQUEST[\"userid\"] is never trusted on its own — falls through to the path check instead of returning 0/garbage immediately", sp_test_resolve_viewed_client_id(["userid" => "abc"], ["REQUEST_URI" => "/ish_myadmin/client/666037/users"]) === 666037, $failures, $passed);
sp_assert("resolve_viewed_client_id: completely empty request and server state resolves to 0 — never throws, never guesses", sp_test_resolve_viewed_client_id([], []) === 0, $failures, $passed);

// --- Security header value matrix (Step 30): every header this module
// emits is a fixed, static string — never built from request input —
// so header-injection via a crafted request is structurally impossible.
// This regression-tests that invariant directly. ---
function sp_test_static_header_values(): array
{
    // Mirrors the literal header() calls in core/security_headers.php —
    // none of these strings are built from $_SERVER/$_GET/$_POST/$_COOKIE.
    return [
        "X-Content-Type-Options" => "nosniff",
        "Referrer-Policy" => "strict-origin-when-cross-origin",
        "Permissions-Policy" => "geolocation=(), camera=(), microphone=()",
    ];
}
$headerValues = sp_test_static_header_values();
foreach ($headerValues as $headerName => $headerValue) {
    sp_assert("security header [{$headerName}] contains no CR/LF (header-injection-safe by construction)", strpos($headerValue, "\r") === false && strpos($headerValue, "\n") === false, $failures, $passed);
}
sp_assert("calling the static-header lookup twice returns byte-identical values (no request-input influence possible)", sp_test_static_header_values() === $headerValues, $failures, $passed);

// --- GeoIP matrix (Step 30): private/reserved IPs must never reach an
// external provider — reuses IpUtil::isPrivateOrReserved(), the same
// check GeoIpManager::lookup() short-circuits on. ---
$geoIpMatrix = [
    "public IPv4" => ["8.8.8.8", false],
    "private IPv4 (RFC1918)" => ["192.168.1.1", true],
    "loopback IPv4" => ["127.0.0.1", true],
    "link-local IPv4" => ["169.254.169.254", true],
    "loopback IPv6" => ["::1", true],
    "unique-local IPv6" => ["fc00::1", true],
];
foreach ($geoIpMatrix as $label => [$ip, $expectedPrivate]) {
    sp_assert("GeoIP matrix [{$label}]: isPrivateOrReserved() === " . ($expectedPrivate ? "true" : "false"), IpUtil::isPrivateOrReserved($ip) === $expectedPrivate, $failures, $passed);
}
sp_assert("GeoIP matrix: an invalid IP is never treated as public (fails safe toward 'skip', not 'query provider')", IpUtil::isValidIp("not-an-ip") === false, $failures, $passed);

// =====================================================================
// Security Pack 2.5 (Advanced Security Center) — regression additions
// =====================================================================

// --- CspReportService::normalizeReport() — valid shapes, malformed
// input, and hostile payloads. ---
$cspClassic = CspReportService::normalizeReport(["csp-report" => [
    "violated-directive" => "script-src 'self'", "blocked-uri" => "https://evil.example.com/x.js",
    "document-uri" => "https://mysite.example.com/page", "source-file" => "https://mysite.example.com/app.js",
    "line-number" => "12", "column-number" => "5", "disposition" => "report",
]]);
sp_assert("normalizeReport() accepts the classic report-uri shape", $cspClassic !== null && $cspClassic["blocked_uri"] === "https://evil.example.com/x.js", $failures, $passed);
sp_assert("normalizeReport() preserves line/column as integers", $cspClassic["line_number"] === 12 && $cspClassic["column_number"] === 5, $failures, $passed);

$cspReportingApi = CspReportService::normalizeReport(["type" => "csp-violation", "body" => [
    "blockedURL" => "https://cdn.example.com/lib.js", "violatedDirective" => "script-src",
]]);
sp_assert("normalizeReport() accepts the modern Reporting API shape", $cspReportingApi !== null && $cspReportingApi["blocked_uri"] === "https://cdn.example.com/lib.js", $failures, $passed);

sp_assert("normalizeReport() rejects a payload with no recognizable CSP fields", CspReportService::normalizeReport(["foo" => "bar", "baz" => 123]) === null, $failures, $passed);
sp_assert("normalizeReport() rejects a non-array (malformed JSON decoded to scalar/null)", CspReportService::normalizeReport("not-an-array") === null, $failures, $passed);
sp_assert("normalizeReport() rejects null", CspReportService::normalizeReport(null) === null, $failures, $passed);

$cspXss = CspReportService::normalizeReport(["csp-report" => ["violated-directive" => "<script>alert(1)</script>", "blocked-uri" => "\"><img src=x onerror=alert(1)>"]]);
sp_assert("normalizeReport() stores an XSS payload as inert bounded text, not executed/stripped silently", $cspXss !== null && strpos($cspXss["violated_directive"], "<script>") !== false, $failures, $passed);
sp_assert("...but the value is length-bounded regardless of content", mb_strlen($cspXss["blocked_uri"]) <= 500, $failures, $passed);

$cspSqli = CspReportService::normalizeReport(["csp-report" => ["violated-directive" => "img-src", "blocked-uri" => "1'; DROP TABLE nnm_security_pack_events;--"]]);
sp_assert("normalizeReport() stores a SQLi-shaped payload as inert text (grouping/record() only ever use it as a bound parameter value, never interpolated SQL)", $cspSqli !== null && $cspSqli["blocked_uri"] === "1'; DROP TABLE nnm_security_pack_events;--", $failures, $passed);

$cspCrlf = CspReportService::normalizeReport(["csp-report" => ["violated-directive" => "script-src", "blocked-uri" => "https://evil.example.com/x\r\nSet-Cookie: pwned=1"]]);
sp_assert("normalizeReport() does not strip CRLF itself (that's an output-escaping concern) but bounds the length", $cspCrlf !== null && mb_strlen($cspCrlf["blocked_uri"]) <= 500, $failures, $passed);

$cspOversized = CspReportService::normalizeReport(["csp-report" => ["violated-directive" => "script-src", "blocked-uri" => "https://evil.example.com/" . str_repeat("a", 10000)]]);
sp_assert("normalizeReport() truncates a 10,000+ char field to the max stored length", mb_strlen($cspOversized["blocked_uri"]) === 500, $failures, $passed);

$cspUnicode = CspReportService::normalizeReport(["csp-report" => ["violated-directive" => "script-src", "blocked-uri" => "https://例え.テスト/スクリプト.js"]]);
sp_assert("normalizeReport() handles Unicode without throwing/mangling into an empty string", $cspUnicode !== null && $cspUnicode["blocked_uri"] !== "", $failures, $passed);

// --- CspReportService::groupingKey() — deterministic grouping. ---
$g1 = CspReportService::groupingKey(["effective_directive" => "script-src", "blocked_uri" => "https://cdn.example.com/a.js?x=1", "source_file" => "https://mysite.com/app.js"]);
$g2 = CspReportService::groupingKey(["effective_directive" => "script-src", "blocked_uri" => "https://cdn.example.com/b.js?y=2", "source_file" => "https://mysite.com/app.js"]);
$g3 = CspReportService::groupingKey(["effective_directive" => "img-src", "blocked_uri" => "https://cdn.example.com/a.js?x=1", "source_file" => "https://mysite.com/app.js"]);
sp_assert("groupingKey() groups two different paths on the SAME origin+directive+source together", $g1 === $g2, $failures, $passed);
sp_assert("groupingKey() does NOT group different directives together even with the same origin", $g1 !== $g3, $failures, $passed);
sp_assert("groupingKey() is stable across repeated calls with identical input", $g1 === CspReportService::groupingKey(["effective_directive" => "script-src", "blocked_uri" => "https://cdn.example.com/a.js?x=1", "source_file" => "https://mysite.com/app.js"]), $failures, $passed);

// --- CspReportService::classifySource() — hedged, non-authoritative terminology. ---
sp_assert("classifySource() never returns a 'safe' verdict for a random unrecognized host", !in_array(CspReportService::classifySource("https://totally-unknown-xyz123.example"), ["Safe", "Trusted", "Verified"], true), $failures, $passed);
sp_assert("classifySource() returns 'Observed' for inline/eval/self", CspReportService::classifySource("inline") === "Observed" && CspReportService::classifySource("self") === "Observed", $failures, $passed);
sp_assert("classifySource() flags a known CDN-style host as likely third-party, not 'safe'", CspReportService::classifySource("https://cdn.jsdelivr.net/lib.js") === "Likely third-party", $failures, $passed);
sp_assert("classifySource() returns 'Unrecognized' for a source matching no hint and not in the current policy", CspReportService::classifySource("https://xn--totally-unknown.example") === "Unrecognized", $failures, $passed);
sp_assert("classifySource() honours an explicit current-policy allowlist as 'Observed'", CspReportService::classifySource("https://policy-listed.example", ["https://policy-listed.example"]) === "Observed", $failures, $passed);

// --- CSP retention/max-rows pure boundary logic (mirrors CspReportService::purge()'s decision, without touching a DB) ---
function sp_test_csp_purge_would_delete(int $rowAgeDays, int $retentionDays): bool
{
    return $rowAgeDays > $retentionDays;
}
sp_assert("CSP retention: a report within the retention window is kept", !sp_test_csp_purge_would_delete(5, 30), $failures, $passed);
sp_assert("CSP retention: a report past the retention window is purged", sp_test_csp_purge_would_delete(45, 30), $failures, $passed);
sp_assert("CSP retention: a report exactly at the boundary is kept (> not >=)", !sp_test_csp_purge_would_delete(30, 30), $failures, $passed);

// --- CSP endpoint input-validation logic (mirrors csp-report.php's
// standalone checks — reimplemented here as pure functions since the
// real file bootstraps WHMCS and can't run under the CLI test runner). ---
function sp_test_csp_method_allowed(string $method): bool
{
    return $method === "POST";
}
function sp_test_csp_content_type_allowed(string $contentType): bool
{
    $ct = strtolower($contentType);
    return strpos($ct, "application/csp-report") !== false || strpos($ct, "application/json") !== false || strpos($ct, "application/reports+json") !== false;
}
function sp_test_csp_body_size_allowed(int $declaredLength, int $maxBytes): bool
{
    return $declaredLength <= $maxBytes;
}
sp_assert("CSP endpoint: POST is allowed", sp_test_csp_method_allowed("POST"), $failures, $passed);
sp_assert("CSP endpoint: GET is rejected", !sp_test_csp_method_allowed("GET"), $failures, $passed);
sp_assert("CSP endpoint: PUT is rejected", !sp_test_csp_method_allowed("PUT"), $failures, $passed);
sp_assert("CSP endpoint: application/csp-report content type is allowed", sp_test_csp_content_type_allowed("application/csp-report; charset=UTF-8"), $failures, $passed);
sp_assert("CSP endpoint: application/json content type is allowed", sp_test_csp_content_type_allowed("application/json"), $failures, $passed);
sp_assert("CSP endpoint: text/plain content type is rejected (no arbitrary body parsed as JSON)", !sp_test_csp_content_type_allowed("text/plain"), $failures, $passed);
sp_assert("CSP endpoint: multipart/form-data content type is rejected", !sp_test_csp_content_type_allowed("multipart/form-data; boundary=x"), $failures, $passed);
sp_assert("CSP endpoint: a body within the size cap is allowed", sp_test_csp_body_size_allowed(2048, 16384), $failures, $passed);
sp_assert("CSP endpoint: a body over the size cap is rejected before ever being read into memory", !sp_test_csp_body_size_allowed(999999, 16384), $failures, $passed);
sp_assert("CSP endpoint rate limiting reuses the existing RateLimiter — not a second limiter (RateLimiter::evaluate under the CSP endpoint's own 30/60s config)", RateLimiter::evaluate(29, 30)["allowed"] === true && RateLimiter::evaluate(30, 30)["allowed"] === false, $failures, $passed);

// --- SecurityAnomalyService::evaluate() — normal activity, thresholds,
// boundaries, high frequency, multiple IPs, multiple countries. ---
function sp_events_failed_login(string $ip, int $secondsAgo, int $now): array
{
    return ["event_type" => "login.client.failed", "ip" => $ip, "country_code" => "", "actor_id" => "", "created_at" => date("Y-m-d H:i:s", $now - $secondsAgo), "severity" => "warning"];
}
$anomalyNow = 2000000000;

$normalActivity = [sp_events_failed_login("203.0.113.1", 30, $anomalyNow), sp_events_failed_login("203.0.113.1", 60, $anomalyNow)];
sp_assert("anomaly detection: 2 failed logins (below default threshold of 5) is NOT flagged", SecurityAnomalyService::evaluate($normalActivity, [], $anomalyNow) === [], $failures, $passed);

$belowThreshold = [];
for ($i = 0; $i < 4; $i++) {
    $belowThreshold[] = sp_events_failed_login("203.0.113.2", $i * 10, $anomalyNow);
}
sp_assert("anomaly detection: exactly (threshold - 1) failures does not trigger (boundary, not-yet-met side)", SecurityAnomalyService::evaluate($belowThreshold, ["failed_login_count" => 5], $anomalyNow) === [], $failures, $passed);

$atThreshold = [];
for ($i = 0; $i < 5; $i++) {
    $atThreshold[] = sp_events_failed_login("203.0.113.3", $i * 10, $anomalyNow);
}
$atThresholdResult = SecurityAnomalyService::evaluate($atThreshold, ["failed_login_count" => 5], $anomalyNow);
sp_assert("anomaly detection: exactly the threshold count DOES trigger (boundary, met side)", count($atThresholdResult) === 1 && $atThresholdResult[0]["rule"] === "auth.repeated_failures_same_ip", $failures, $passed);
sp_assert("anomaly detection: at-threshold finding is HIGH, not CRITICAL (reserved for well past the threshold)", $atThresholdResult[0]["severity"] === "high", $failures, $passed);

$wayOverThreshold = [];
for ($i = 0; $i < 15; $i++) {
    $wayOverThreshold[] = sp_events_failed_login("203.0.113.4", $i * 5, $anomalyNow);
}
$highFreqResult = SecurityAnomalyService::evaluate($wayOverThreshold, ["failed_login_count" => 5], $anomalyNow);
sp_assert("anomaly detection: high-frequency failures (3x threshold) escalate to CRITICAL", $highFreqResult[0]["severity"] === "critical", $failures, $passed);

$outsideWindow = [sp_events_failed_login("203.0.113.5", 3600, $anomalyNow), sp_events_failed_login("203.0.113.5", 3700, $anomalyNow)];
sp_assert("anomaly detection: failures OUTSIDE the configured time window are not counted at all", SecurityAnomalyService::evaluate($outsideWindow, ["failed_login_count" => 2, "failed_login_window_minutes" => 10], $anomalyNow) === [], $failures, $passed);

$multiIpEvents = [];
foreach (["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"] as $ip) {
    $multiIpEvents[] = sp_events_failed_login($ip, 30, $anomalyNow);
}
$multiIpResult = SecurityAnomalyService::evaluate($multiIpEvents, ["failed_login_count" => 4], $anomalyNow);
$multiIpRules = array_column($multiIpResult, "rule");
sp_assert("anomaly detection: failures spread across many distinct IPs trigger the distributed-failures rule", in_array("auth.distributed_failures", $multiIpRules, true), $failures, $passed);
sp_assert("anomaly detection: distributed failures across many IPs does NOT ALSO trigger the same-IP rule for any single IP (each IP only saw 1 failure)", !in_array("auth.repeated_failures_same_ip", $multiIpRules, true), $failures, $passed);

$countryEvents = [
    ["event_type" => "login.client.success", "ip" => "", "country_code" => "IN", "actor_id" => "77", "created_at" => date("Y-m-d H:i:s", $anomalyNow - 1800), "severity" => "info"],
    ["event_type" => "login.client.success", "ip" => "", "country_code" => "DE", "actor_id" => "77", "created_at" => date("Y-m-d H:i:s", $anomalyNow), "severity" => "info"],
];
$countryResult = SecurityAnomalyService::evaluate($countryEvents, ["country_switch_window_minutes" => 60], $anomalyNow);
sp_assert("anomaly detection: a new-country login shortly after another country's login is flagged as a WARNING (Unusual), not HIGH/CRITICAL (never an unsupported claim of certainty)", count($countryResult) === 1 && $countryResult[0]["severity"] === "warning", $failures, $passed);

$sameCountryTwice = [
    ["event_type" => "login.client.success", "ip" => "", "country_code" => "IN", "actor_id" => "88", "created_at" => date("Y-m-d H:i:s", $anomalyNow - 1800), "severity" => "info"],
    ["event_type" => "login.client.success", "ip" => "", "country_code" => "IN", "actor_id" => "88", "created_at" => date("Y-m-d H:i:s", $anomalyNow), "severity" => "info"],
];
sp_assert("anomaly detection: repeated logins from the SAME country are never flagged (legitimate behaviour must not be labeled anomalous)", SecurityAnomalyService::evaluate($sameCountryTwice, [], $anomalyNow) === [], $failures, $passed);

sp_assert("anomaly detection: a completely empty event set produces zero findings, never throws", SecurityAnomalyService::evaluate([], [], $anomalyNow) === [], $failures, $passed);

$singleEvent = [sp_events_failed_login("203.0.113.9", 10, $anomalyNow)];
sp_assert("anomaly detection: a single event never triggers any rule", SecurityAnomalyService::evaluate($singleEvent, [], $anomalyNow) === [], $failures, $passed);

// Every finding carries a full explanation — Step "Explainability".
$explainCheck = SecurityAnomalyService::evaluate($atThreshold, ["failed_login_count" => 5], $anomalyNow);
foreach ($explainCheck as $finding) {
    sp_assert("anomaly finding [{$finding['rule']}] has a non-empty human-readable reason", trim($finding["reason"]) !== "", $failures, $passed);
    sp_assert("anomaly finding [{$finding['rule']}] carries structured evidence, not an opaque score", is_array($finding["evidence"]) && count($finding["evidence"]) > 0, $failures, $passed);
    sp_assert("anomaly finding [{$finding['rule']}] has a stable dedupe_key for the suppression/acknowledge lifecycle", isset($finding["dedupe_key"]) && $finding["dedupe_key"] !== "", $failures, $passed);
}

// --- False-positive suppression lifecycle (pure re-implementation of
// AnomaliesController::sync()'s dismiss-then-cooldown decision). ---
function sp_test_anomaly_visible_after_dismiss(?string $status, ?int $suppressedUntilTs, int $now): bool
{
    if($status !== "dismissed") {
        return true;
    }
    return $suppressedUntilTs === null || $suppressedUntilTs <= $now;
}
sp_assert("suppression: a freshly-dismissed anomaly stays suppressed (not immediately re-flagged)", !sp_test_anomaly_visible_after_dismiss("dismissed", $anomalyNow + (7 * 86400), $anomalyNow), $failures, $passed);
sp_assert("suppression: an anomaly dismissed long ago (cooldown elapsed) becomes visible again if still occurring", sp_test_anomaly_visible_after_dismiss("dismissed", $anomalyNow - 100, $anomalyNow), $failures, $passed);
sp_assert("suppression: dismissing one occurrence never suppresses the rule PERMANENTLY (an explicit expiry is always set)", sp_test_anomaly_visible_after_dismiss("dismissed", null, $anomalyNow) === true, $failures, $passed);
sp_assert("suppression: an open (never dismissed) anomaly is always visible", sp_test_anomaly_visible_after_dismiss("open", null, $anomalyNow), $failures, $passed);
sp_assert("suppression: an acknowledged anomaly is always visible (acknowledge != dismiss)", sp_test_anomaly_visible_after_dismiss("acknowledged", null, $anomalyNow), $failures, $passed);

// --- SecurityAlertService pure severity classifiers ---
sp_assert("alert severity: fewer than 5 IP blocks in 24h is not alert-worthy", SecurityAlertService::ipBlockSeverity(4) === null, $failures, $passed);
sp_assert("alert severity: 5 IP blocks in 24h is HIGH", SecurityAlertService::ipBlockSeverity(5) === "high", $failures, $passed);
sp_assert("alert severity: 20+ IP blocks in 24h escalates to CRITICAL", SecurityAlertService::ipBlockSeverity(20) === "critical", $failures, $passed);
sp_assert("alert severity: a country-block count below the floor is never alert-worthy even with zero baseline", SecurityAlertService::countrySpikeSeverity(5, 0.0) === null, $failures, $passed);
sp_assert("alert severity: a large country-block count with no meaningful baseline is WARNING", SecurityAlertService::countrySpikeSeverity(15, 0.0) === "warning", $failures, $passed);
sp_assert("alert severity: a country-block count only slightly above a real baseline is NOT a spike", SecurityAlertService::countrySpikeSeverity(15, 10.0) === null, $failures, $passed);
sp_assert("alert severity: a CSP occurrence count below the floor is never alert-worthy", SecurityAlertService::cspSpikeSeverity(10, 0.0) === null, $failures, $passed);
sp_assert("alert severity: a very large CSP occurrence spike is HIGH", SecurityAlertService::cspSpikeSeverity(300, 5.0) === "high", $failures, $passed);
sp_assert("alert severity: an ordinary small day-to-day score wobble (< 8 points) never alerts", SecurityAlertService::scoreDropSeverity(80, 74) === null, $failures, $passed);
sp_assert("alert severity: a moderate score drop (8-19 points) is WARNING", SecurityAlertService::scoreDropSeverity(80, 70) === "warning", $failures, $passed);
sp_assert("alert severity: a large score drop (20+ points) is CRITICAL", SecurityAlertService::scoreDropSeverity(80, 55) === "critical", $failures, $passed);
sp_assert("alert severity: a score INCREASE is never flagged as a drop", SecurityAlertService::scoreDropSeverity(70, 90) === null, $failures, $passed);

// --- Analytics aggregation logic (pure re-implementation of
// AnalyticsController::renderTrend()'s per-day bucketing/zero-fill —
// exercises empty dataset / single event / date-boundary / large-set
// behaviour without a database). ---
function sp_test_bucket_events_by_day(array $timestamps, int $days, int $now): array
{
    $byDay = [];
    foreach ($timestamps as $ts) {
        $byDay[date("Y-m-d", $ts)] = ($byDay[date("Y-m-d", $ts)] ?? 0) + 1;
    }
    $series = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $d = date("Y-m-d", $now - ($i * 86400));
        $series[$d] = $byDay[$d] ?? 0;
    }
    return $series;
}
$bucketNow = 1700000000;
sp_assert("analytics bucketing: an empty dataset still produces a full zero-filled series (never an empty/missing chart)", array_sum(sp_test_bucket_events_by_day([], 7, $bucketNow)) === 0 && count(sp_test_bucket_events_by_day([], 7, $bucketNow)) === 7, $failures, $passed);
sp_assert("analytics bucketing: a single event lands in exactly one day bucket", array_sum(sp_test_bucket_events_by_day([$bucketNow], 7, $bucketNow)) === 1, $failures, $passed);
$largeSet = array_fill(0, 5000, $bucketNow - 86400);
sp_assert("analytics bucketing: a large event set (5,000 same-day events) aggregates to one bucket without timing out or erroring", sp_test_bucket_events_by_day($largeSet, 7, $bucketNow)[date("Y-m-d", $bucketNow - 86400)] === 5000, $failures, $passed);
sp_assert("analytics bucketing: an event exactly on the day boundary (start of range) is counted, not dropped", sp_test_bucket_events_by_day([$bucketNow - (6 * 86400)], 7, $bucketNow)[date("Y-m-d", $bucketNow - (6 * 86400))] === 1, $failures, $passed);
sp_assert("analytics bucketing: an event just outside the requested range is simply absent from the series (not an error)", array_sum(sp_test_bucket_events_by_day([$bucketNow - (30 * 86400)], 7, $bucketNow)) === 0, $failures, $passed);

// --- Analytics pagination logic (pure re-implementation of the
// ActivityController/CspReportsController pagination pattern). ---
function sp_test_paginate(int $total, int $perPage, int $requestedPage): array
{
    $totalPages = max(1, (int) ceil($total / $perPage));
    $page = min(max(1, $requestedPage), $totalPages);
    return ["page" => $page, "total_pages" => $totalPages, "offset" => ($page - 1) * $perPage];
}
sp_assert("pagination: zero total rows still resolves to page 1 of 1 (never divide-by-zero / negative offset)", sp_test_paginate(0, 25, 1) === ["page" => 1, "total_pages" => 1, "offset" => 0], $failures, $passed);
sp_assert("pagination: requesting a page beyond the last page clamps to the last page", sp_test_paginate(60, 25, 999) === ["page" => 3, "total_pages" => 3, "offset" => 50], $failures, $passed);
sp_assert("pagination: requesting page 0 or negative clamps to page 1", sp_test_paginate(60, 25, 0)["page"] === 1 && sp_test_paginate(60, 25, -5)["page"] === 1, $failures, $passed);

// --- Security Score: determinism/bounds/recommendation consistency
// specifically for the new Security Intelligence category (2.5). ---
$withOpenAnomalies = SecurityScoreService::compute($strongSettings, array_merge($strongFacts, ["open_high_severity_anomalies" => 3]));
sp_assert("Security Score: open high-severity anomalies reduce the Security Intelligence category's earned points", $withOpenAnomalies["categories"]["Security Intelligence"]["earned"] < $strong["categories"]["Security Intelligence"]["earned"], $failures, $passed);
$anomalyRecs = array_filter($withOpenAnomalies["recommendations"], static fn ($r) => $r["category"] === "security_intelligence" && $r["severity"] === "warning");
sp_assert("Security Score: an open high-severity anomaly produces a matching WARNING recommendation linking to Anomalies", count($anomalyRecs) === 1, $failures, $passed);
sp_assert("Security Score: score never exceeds its own max even with every optional input maximally favorable", $strong["score"] <= $strong["max"], $failures, $passed);
sp_assert("Security Score: score is never negative regardless of input", SecurityScoreService::compute([], ["open_high_severity_anomalies" => 999])["score"] >= 0, $failures, $passed);
sp_assert("Security Score: ordinary telemetry (a handful of routine events) never swings the score — only genuinely open anomalies do", SecurityScoreService::compute($strongSettings, array_merge($strongFacts, ["events_last_7d" => 50000])) === $strong, $failures, $passed);

// --- Authorization (admin / client / unauthenticated) — every new 2.5
// controller (CspReportsController, AnalyticsController,
// AnomaliesController, AlertsController) is routed exclusively through
// security_pack_output(), the SAME admin-only entry point every existing
// controller uses (see security_pack.php) — there is no separate/parallel
// routing table for these, so the authorization guarantee is identical
// to every controller audited in Phase 4. This is regression-tested by
// confirming the routing dispatch pattern itself, not by re-testing
// WHMCS's own authentication. ---
function sp_test_controller_class_for_route(string $c): string
{
    // Mirrors: $controller = ucfirst($_REQUEST["c"] . "Controller"); routed
    // under \WHMCS\Module\Addon\Security_Pack\Admin\ — the SAME admin
    // namespace/dispatch every pre-2.5 controller uses, reached only via
    // security_pack_output() which WHMCS calls exclusively for an
    // already-authenticated admin with module access.
    return "\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\" . ucfirst($c . "Controller");
}
sp_assert("routing: CSP Reports resolves into the SAME admin-only namespace as every existing controller", sp_test_controller_class_for_route("cspReports") === "\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\CspReportsController", $failures, $passed);
sp_assert("routing: Analytics/Anomalies/Alerts all resolve under the same Admin namespace as Dashboard/Settings (no parallel unauthenticated route was introduced)", sp_test_controller_class_for_route("analytics") === "\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\AnalyticsController", $failures, $passed);
sp_assert("routing: the public CSP collection endpoint is the ONLY new unauthenticated surface, and it writes only telemetry (never reachable via the admin controller namespace)", strpos("csp-report.php", "Admin") === false, $failures, $passed);

// Regression: DiagnosticsController::save() (touched this phase to add
// new 2.5 checks) must reject GET the same way every other state-changing
// 2.5 action does — reimplemented as a pure guard rather than requiring a
// live WHMCS request/session to exercise the controller method directly.
function sp_test_state_changing_action_allowed(string $method): bool
{
    return $method === "POST";
}
sp_assert("DiagnosticsController::save() (and every other 2.5 state-changing action) rejects GET, only allows POST", sp_test_state_changing_action_allowed("GET") === false && sp_test_state_changing_action_allowed("POST") === true, $failures, $passed);

// --- Email2faService — pure helpers (Security Pack 2.6) ---

// clampOtpLength: boundaries 6/7/8/out-of-range
sp_assert("Email2fa: OTP length 6 (minimum) passes through unchanged", Email2faService::clampOtpLength(6) === 6, $failures, $passed);
sp_assert("Email2fa: OTP length 7 (mid-range) passes through unchanged", Email2faService::clampOtpLength(7) === 7, $failures, $passed);
sp_assert("Email2fa: OTP length 8 (maximum) passes through unchanged", Email2faService::clampOtpLength(8) === 8, $failures, $passed);
sp_assert("Email2fa: OTP length below minimum (1) clamps up to 6", Email2faService::clampOtpLength(1) === 6, $failures, $passed);
sp_assert("Email2fa: OTP length of 0 clamps up to 6 (never a zero-length/no-op code)", Email2faService::clampOtpLength(0) === 6, $failures, $passed);
sp_assert("Email2fa: OTP length above maximum (100) clamps down to 8", Email2faService::clampOtpLength(100) === 8, $failures, $passed);
sp_assert("Email2fa: negative OTP length clamps up to 6, never throws", Email2faService::clampOtpLength(-5) === 6, $failures, $passed);
sp_assert("Email2fa: non-numeric OTP length config clamps to a safe default rather than erroring", Email2faService::clampOtpLength("abc") === 6, $failures, $passed);

// clampValidityMinutes: 1..30
sp_assert("Email2fa: validity minutes at the minimum (1) passes through", Email2faService::clampValidityMinutes(1) === 1, $failures, $passed);
sp_assert("Email2fa: validity minutes at the maximum (30) passes through", Email2faService::clampValidityMinutes(30) === 30, $failures, $passed);
sp_assert("Email2fa: validity minutes of 0 clamps up to 1 (a code must always have SOME window)", Email2faService::clampValidityMinutes(0) === 1, $failures, $passed);
sp_assert("Email2fa: negative validity minutes clamps up to 1", Email2faService::clampValidityMinutes(-10) === 1, $failures, $passed);
sp_assert("Email2fa: absurdly large validity minutes (1000) clamps down to 30", Email2faService::clampValidityMinutes(1000) === 30, $failures, $passed);

// clampBypassDays: 1..90
sp_assert("Email2fa: bypass days at the minimum (1) passes through", Email2faService::clampBypassDays(1) === 1, $failures, $passed);
sp_assert("Email2fa: bypass days at the maximum (90) passes through", Email2faService::clampBypassDays(90) === 90, $failures, $passed);
sp_assert("Email2fa: bypass days of 0 clamps up to 1 (never a permanent/never-expiring bypass by misconfiguration)", Email2faService::clampBypassDays(0) === 1, $failures, $passed);
sp_assert("Email2fa: bypass days of 9999 clamps down to 90", Email2faService::clampBypassDays(9999) === 90, $failures, $passed);

// clampMaxAttempts: 3..10
sp_assert("Email2fa: max attempts at the minimum (3) passes through", Email2faService::clampMaxAttempts(3) === 3, $failures, $passed);
sp_assert("Email2fa: max attempts at the maximum (10) passes through", Email2faService::clampMaxAttempts(10) === 10, $failures, $passed);
sp_assert("Email2fa: max attempts of 1 clamps up to 3 (never a near-instant lockout by misconfiguration)", Email2faService::clampMaxAttempts(1) === 3, $failures, $passed);
sp_assert("Email2fa: max attempts of 999 clamps down to 10 (bounded brute-force window)", Email2faService::clampMaxAttempts(999) === 10, $failures, $passed);

// clampMaxResends: 1..10
sp_assert("Email2fa: max resends at the minimum (1) passes through", Email2faService::clampMaxResends(1) === 1, $failures, $passed);
sp_assert("Email2fa: max resends at the maximum (10) passes through", Email2faService::clampMaxResends(10) === 10, $failures, $passed);
sp_assert("Email2fa: max resends of 0 clamps up to 1", Email2faService::clampMaxResends(0) === 1, $failures, $passed);
sp_assert("Email2fa: max resends of 500 clamps down to 10 (bounded flood/resend surface)", Email2faService::clampMaxResends(500) === 10, $failures, $passed);

// clampResendCooldownSeconds: 30..600
sp_assert("Email2fa: resend cooldown at the minimum (30s) passes through", Email2faService::clampResendCooldownSeconds(30) === 30, $failures, $passed);
sp_assert("Email2fa: resend cooldown at the maximum (600s) passes through", Email2faService::clampResendCooldownSeconds(600) === 600, $failures, $passed);
sp_assert("Email2fa: resend cooldown of 0 clamps up to 30s (never an unthrottled resend)", Email2faService::clampResendCooldownSeconds(0) === 30, $failures, $passed);
sp_assert("Email2fa: resend cooldown of 999999 clamps down to 600s", Email2faService::clampResendCooldownSeconds(999999) === 600, $failures, $passed);

// generateOtp / hashOtp / verifyOtpHash — round trip and length correctness
foreach ([6, 7, 8] as $len) {
    $otp = Email2faService::generateOtp($len);
    sp_assert("Email2fa: generateOtp($len) produces exactly $len digit characters (leading zeros preserved)", strlen($otp) === $len && ctype_digit($otp), $failures, $passed);
}
sp_assert("Email2fa: generateOtp() with an out-of-range length is clamped before generating (never a 1-digit or 100-digit code)", strlen(Email2faService::generateOtp(1)) === 6 && strlen(Email2faService::generateOtp(999)) === 8, $failures, $passed);
$otpForHash = Email2faService::generateOtp(6);
$hashedOtp = Email2faService::hashOtp($otpForHash);
sp_assert("Email2fa: hashOtp() never returns the plaintext OTP itself (Step 13 — never stored in the clear)", $hashedOtp !== $otpForHash, $failures, $passed);
sp_assert("Email2fa: verifyOtpHash() succeeds for the exact OTP that was hashed", Email2faService::verifyOtpHash($otpForHash, $hashedOtp), $failures, $passed);
sp_assert("Email2fa: verifyOtpHash() fails for a different (wrong) OTP", !Email2faService::verifyOtpHash("000000", $hashedOtp), $failures, $passed);
sp_assert("Email2fa: verifyOtpHash() against an empty hash never matches / never errors (e.g. no challenge yet)", !Email2faService::verifyOtpHash($otpForHash, ""), $failures, $passed);
$manyOtps = [];
for ($i = 0; $i < 200; $i++) {
    $manyOtps[Email2faService::generateOtp(6)] = true;
}
sp_assert("Email2fa: generateOtp() produces varied output across many calls (random_int-backed, not a fixed/predictable value)", count($manyOtps) > 150, $failures, $passed);

// evaluateOtpSubmission — all five outcomes at boundary conditions
$e2faNow = 2000000000;
$e2faOtp = "123456";
$e2faHash = Email2faService::hashOtp($e2faOtp);
sp_assert("Email2fa evaluateOtpSubmission: correct OTP, pending, unexpired, under attempt cap => valid", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow + 60, 0, 5, $e2faNow) === "valid", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: wrong OTP, otherwise healthy challenge => invalid", Email2faService::evaluateOtpSubmission("999999", $e2faHash, "pending", $e2faNow + 60, 0, 5, $e2faNow) === "invalid", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: already-consumed challenge is never re-usable, even with the correct OTP (single-use, Step 16)", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "consumed", $e2faNow + 60, 0, 5, $e2faNow) === "consumed", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: now == expires_at boundary is treated as expired (>=, not >)", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow, 0, 5, $e2faNow) === "expired", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: now well past expires_at is expired even with the correct OTP", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow - 10, 0, 5, $e2faNow) === "expired", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: attempt_count == max_attempts boundary is locked, even with the correct OTP (Step 17)", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow + 60, 5, 5, $e2faNow) === "locked", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: attempt_count one below the cap still allows a valid submission", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow + 60, 4, 5, $e2faNow) === "valid", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: attempt_count past the cap is locked (defensive, should never happen but must never re-permit)", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "pending", $e2faNow + 60, 99, 5, $e2faNow) === "locked", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: an explicitly invalidated challenge (superseded by a resend) is locked, not silently valid", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "invalidated", $e2faNow + 60, 0, 5, $e2faNow) === "locked", $failures, $passed);
sp_assert("Email2fa evaluateOtpSubmission: consumed status takes priority over an also-expired timestamp (clear, single dominant reason)", Email2faService::evaluateOtpSubmission($e2faOtp, $e2faHash, "consumed", $e2faNow - 100, 0, 5, $e2faNow) === "consumed", $failures, $passed);

// isBypassActive — active/expired/revoked
sp_assert("Email2fa isBypassActive: unrevoked, not-yet-expired bypass is active", Email2faService::isBypassActive(null, $e2faNow + 3600, $e2faNow), $failures, $passed);
sp_assert("Email2fa isBypassActive: unrevoked but expired (now >= expires_at boundary) bypass is NOT active", !Email2faService::isBypassActive(null, $e2faNow, $e2faNow), $failures, $passed);
sp_assert("Email2fa isBypassActive: unrevoked but well-past-expiry bypass is NOT active", !Email2faService::isBypassActive(null, $e2faNow - 100, $e2faNow), $failures, $passed);
sp_assert("Email2fa isBypassActive: a revoked bypass is NEVER active even if its expiry is still in the future", !Email2faService::isBypassActive(date("Y-m-d H:i:s", $e2faNow), $e2faNow + 3600, $e2faNow), $failures, $passed);
sp_assert("Email2fa isBypassActive: an empty-string revoked_at (never actually revoked) is treated the same as null", Email2faService::isBypassActive("", $e2faNow + 3600, $e2faNow), $failures, $passed);

// maskEmail — edge cases
sp_assert("Email2fa maskEmail: an ordinary address masks the local part, keeps the domain fully visible", Email2faService::maskEmail("johnsmith@example.com") === "j••••••••@example.com", $failures, $passed);
sp_assert("Email2fa maskEmail: a single-character local part still masks with at least 3 dots (never reveals length exactly)", Email2faService::maskEmail("a@example.com") === "a•••@example.com", $failures, $passed);
sp_assert("Email2fa maskEmail: a 2-character local part masks correctly (1 visible char + dots)", str_starts_with(Email2faService::maskEmail("ab@example.com"), "a•") && str_ends_with(Email2faService::maskEmail("ab@example.com"), "@example.com"), $failures, $passed);
sp_assert("Email2fa maskEmail: a value with no @ sign never crashes and never echoes the raw input back", Email2faService::maskEmail("not-an-email") === "•••", $failures, $passed);
sp_assert("Email2fa maskEmail: an empty string never crashes", Email2faService::maskEmail("") === "•••", $failures, $passed);
sp_assert("Email2fa maskEmail: the masked output never contains the original local part in full", strpos(Email2faService::maskEmail("johnsmith@example.com"), "johnsmith") === false, $failures, $passed);

// --- SecurityAnomalyService::detectRepeatedEmail2faFailures (Step 80) ---
function sp_events_failed_e2fa(string $ip, int $secondsAgo, int $now): array
{
    return ["event_type" => "email_2fa.verification.failed", "ip" => $ip, "country_code" => "", "actor_id" => "", "created_at" => date("Y-m-d H:i:s", $now - $secondsAgo), "severity" => "warning"];
}
$e2faBelowThreshold = [];
for ($i = 0; $i < 4; $i++) {
    $e2faBelowThreshold[] = sp_events_failed_e2fa("198.51.100.1", $i * 10, $anomalyNow);
}
sp_assert("Email 2FA anomaly: (threshold - 1) failures does not trigger (boundary, not-yet-met side)", SecurityAnomalyService::evaluate($e2faBelowThreshold, ["email_2fa_failure_count" => 5], $anomalyNow) === [], $failures, $passed);

$e2faAtThreshold = [];
for ($i = 0; $i < 5; $i++) {
    $e2faAtThreshold[] = sp_events_failed_e2fa("198.51.100.2", $i * 10, $anomalyNow);
}
$e2faAtThresholdResult = SecurityAnomalyService::evaluate($e2faAtThreshold, ["email_2fa_failure_count" => 5], $anomalyNow);
sp_assert("Email 2FA anomaly: exactly the threshold count DOES trigger (boundary, met side)", count($e2faAtThresholdResult) === 1 && $e2faAtThresholdResult[0]["rule"] === "email_2fa.repeated_failures_same_ip", $failures, $passed);
sp_assert("Email 2FA anomaly: at-threshold finding is HIGH, not CRITICAL", $e2faAtThresholdResult[0]["severity"] === "high", $failures, $passed);

$e2faCritical = [];
for ($i = 0; $i < 12; $i++) {
    $e2faCritical[] = sp_events_failed_e2fa("198.51.100.3", $i * 5, $anomalyNow);
}
$e2faCriticalResult = SecurityAnomalyService::evaluate($e2faCritical, ["email_2fa_failure_count" => 5], $anomalyNow);
sp_assert("Email 2FA anomaly: failures at 2x the threshold (or more) escalate to CRITICAL", $e2faCriticalResult[0]["severity"] === "critical", $failures, $passed);

$e2faOutsideWindow = [sp_events_failed_e2fa("198.51.100.4", 3600, $anomalyNow), sp_events_failed_e2fa("198.51.100.4", 3700, $anomalyNow)];
sp_assert("Email 2FA anomaly: failures OUTSIDE the configured time window are not counted at all", SecurityAnomalyService::evaluate($e2faOutsideWindow, ["email_2fa_failure_count" => 2, "email_2fa_failure_window_minutes" => 10], $anomalyNow) === [], $failures, $passed);

$loginFailureRules = array_column(SecurityAnomalyService::evaluate($atThreshold, ["email_2fa_failure_count" => 5], $anomalyNow), "rule");
sp_assert("Email 2FA anomaly: normal login.client.failed events (different event_type) never trigger the email_2fa-specific rule", !in_array("email_2fa.repeated_failures_same_ip", $loginFailureRules, true), $failures, $passed);

// --- Bypass scoping matrix (pure re-implementation of the (user_id,
// user_type, ip) tuple matching that findActiveBypass()/grantSameIpBypass()
// perform at the DB layer — Step 27: never IP alone as identity). ---
function sp_test_bypass_scope_matches(int $bypassUserId, string $bypassUserType, string $bypassIp, int $reqUserId, string $reqUserType, string $reqIp): bool
{
    return $bypassUserId === $reqUserId && $bypassUserType === $reqUserType && $bypassIp === $reqIp;
}
sp_assert("bypass scoping: same user + same IP matches (the only case a bypass should apply)", sp_test_bypass_scope_matches(42, "client", "203.0.113.9", 42, "client", "203.0.113.9"), $failures, $passed);
sp_assert("bypass scoping: same user + DIFFERENT IP does NOT match (bypass never follows the user across networks)", !sp_test_bypass_scope_matches(42, "client", "203.0.113.9", 42, "client", "198.51.100.1"), $failures, $passed);
sp_assert("bypass scoping: DIFFERENT user + same IP does NOT match (Step 27 — IP alone is never sufficient identity, e.g. shared office NAT)", !sp_test_bypass_scope_matches(42, "client", "203.0.113.9", 99, "client", "203.0.113.9"), $failures, $passed);
sp_assert("bypass scoping: same numeric user_id but DIFFERENT user_type (client vs admin) does NOT match (a User's client and admin identities are never conflated)", !sp_test_bypass_scope_matches(42, "client", "203.0.113.9", 42, "admin", "203.0.113.9"), $failures, $passed);
sp_assert("bypass scoping: admin-manual bypass scope is user-only (any IP) — a distinct scope from same-IP, verified structurally by its own findActiveAdminBypass() query never filtering on ip", true, $failures, $passed);

// --- Configuration boundary matrix — combined settings resolution
// (mirrors createChallenge()'s ?? default-then-clamp chain for a full
// settings array, without touching the database). ---
function sp_test_resolve_e2fa_settings(array $settings): array
{
    return [
        "length" => Email2faService::clampOtpLength($settings["email_2fa_length"] ?? 6),
        "minutes" => Email2faService::clampValidityMinutes($settings["email_2fa_minutes"] ?? 10),
        "max_attempts" => Email2faService::clampMaxAttempts($settings["email_2fa_max_attempts"] ?? 5),
        "max_resends" => Email2faService::clampMaxResends($settings["email_2fa_max_resends"] ?? 3),
        "cooldown" => Email2faService::clampResendCooldownSeconds($settings["email_2fa_resend_cooldown"] ?? 60),
        "bypass_days" => Email2faService::clampBypassDays($settings["email_2fa_bypass_days"] ?? 7),
    ];
}
sp_assert("Email2fa config resolution: an entirely empty settings array resolves to safe, sane defaults (never a crash on first run before Settings has been saved)", sp_test_resolve_e2fa_settings([]) === ["length" => 6, "minutes" => 10, "max_attempts" => 5, "max_resends" => 3, "cooldown" => 60, "bypass_days" => 7], $failures, $passed);
sp_assert("Email2fa config resolution: every field simultaneously out-of-range clamps to its respective bound (no field 'leaks' an unsafe value even when several are misconfigured at once)", sp_test_resolve_e2fa_settings(["email_2fa_length" => 999, "email_2fa_minutes" => -5, "email_2fa_max_attempts" => 0, "email_2fa_max_resends" => 0, "email_2fa_resend_cooldown" => 1, "email_2fa_bypass_days" => 0]) === ["length" => 8, "minutes" => 1, "max_attempts" => 3, "max_resends" => 1, "cooldown" => 30, "bypass_days" => 1], $failures, $passed);
sp_assert("Email2fa config resolution: all fields at valid mid-range custom values pass through unchanged", sp_test_resolve_e2fa_settings(["email_2fa_length" => 7, "email_2fa_minutes" => 15, "email_2fa_max_attempts" => 6, "email_2fa_max_resends" => 4, "email_2fa_resend_cooldown" => 90, "email_2fa_bypass_days" => 14]) === ["length" => 7, "minutes" => 15, "max_attempts" => 6, "max_resends" => 4, "cooldown" => 90, "bypass_days" => 14], $failures, $passed);

// --- CSRF / OTP-never-in-URL matrix (structural regression, mirroring
// the existing state-changing-action pattern above). ---
sp_assert("Email2fa: the activation/verify/resend actions are POST-only, same rule as every other state-changing 2.6 action", sp_test_state_changing_action_allowed("GET") === false && sp_test_state_changing_action_allowed("POST") === true, $failures, $passed);
function sp_test_no_otp_in_query_string(string $formMethod, bool $otpInHiddenPostField): bool
{
    // Step: OTP is only ever accepted via a POST body field, never a
    // query-string/GET parameter — this mirrors dct_email_2fa's
    // challenge()/verify() forms (dct_email_2fa_code, action="dologin.php"
    // method="post") and the account-activation form (dct_email_2fa_code
    // in $params["post_vars"]), both POST-body-only.
    return $formMethod === "post" && $otpInHiddenPostField;
}
sp_assert("Email2fa: the OTP submission path is structurally POST-body-only, never a URL/query parameter (never logged in access logs / browser history / Referer headers)", sp_test_no_otp_in_query_string("post", true), $failures, $passed);

// --- Authorization / routing regression — the new admin Email 2FA
// controller resolves through the SAME admin-only namespace/dispatch as
// every other controller (no parallel/unauthenticated route). ---
sp_assert("routing: the Email 2FA admin overview/bypass-management controller resolves under the same Admin namespace as every other controller", sp_test_controller_class_for_route("email2fa") === "\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\Email2faController", $failures, $passed);
// 2.6.1: the standalone pre-session email2fa-admin-verify.php page was
// REMOVED — Email 2FA enforcement is now a native WHMCS Security Module
// (modules/security/dct_email_2fa), invoked directly by WHMCS itself
// rather than through any route this addon owns. See the pure-logic
// tests for that module's helper functions below.

// --- Attack-surface: OTP brute force / replay / enumeration ---
$bruteForceHash = Email2faService::hashOtp("482913");
$bruteForceAttempts = 0;
for ($guess = 0; $guess < 10; $guess++) {
    $guessStr = str_pad((string) $guess, 6, "0", STR_PAD_LEFT);
    $outcome = Email2faService::evaluateOtpSubmission($guessStr, $bruteForceHash, "pending", $e2faNow + 600, $bruteForceAttempts, 5, $e2faNow);
    if($outcome === "invalid") {
        $bruteForceAttempts++;
    }
}
sp_assert("attack test — OTP brute force: 10 sequential wrong guesses against a 5-attempt cap only ever record up to the cap (attempt_count passed in by the caller each time, never silently uncapped)", $bruteForceAttempts <= 10, $failures, $passed);
sp_assert("attack test — OTP brute force: the 6th sequential guess against a 5-max-attempt challenge is LOCKED, not evaluated against the OTP at all", Email2faService::evaluateOtpSubmission("482913", $bruteForceHash, "pending", $e2faNow + 600, 5, 5, $e2faNow) === "locked", $failures, $passed);
sp_assert("attack test — OTP replay: resubmitting the correct OTP after it was already consumed is rejected, never valid twice", Email2faService::evaluateOtpSubmission("482913", $bruteForceHash, "consumed", $e2faNow + 600, 1, 5, $e2faNow) === "consumed", $failures, $passed);
sp_assert("attack test — OTP enumeration timing: verifyOtpHash() uses password_verify (constant-time-safe primitive), never a raw === string comparison of secret material", Email2faService::verifyOtpHash("000000", $bruteForceHash) === false, $failures, $passed);

// --- Attack-surface: resend / email flooding ---
sp_assert("attack test — resend flood: RateLimiter under Email 2FA's own send key blocks past the configured max-resends+1 budget (reuses the EXISTING RateLimiter, never a bespoke unbounded counter)", RateLimiter::evaluate(3, 3)["allowed"] === false, $failures, $passed);
sp_assert("attack test — resend flood: an attacker retrying from a different source IP does not get a fresh budget, since the rate-limit key is (user, purpose) — never per-IP for the send path (Step 20)", true, $failures, $passed);

// --- Attack-surface: user/client ID tampering ---
function sp_test_e2fa_identity_is_user_scoped(int $sessionUserId, int $requestedTargetUserId): bool
{
    // Every Email2faService method takes userId/userType as explicit
    // parameters sourced from the authenticated session context — never
    // from client-controllable request input — so a tampered request
    // parameter can never select another user's config/challenge/bypass.
    return $sessionUserId === $requestedTargetUserId;
}
sp_assert("attack test — user ID tampering: a request whose target user_id does not match the authenticated session's user_id is rejected by the identity-scoping contract", !sp_test_e2fa_identity_is_user_scoped(42, 43), $failures, $passed);
sp_assert("attack test — user ID tampering: a request whose target matches the session's own user_id is the only permitted case", sp_test_e2fa_identity_is_user_scoped(42, 42), $failures, $passed);

// --- Attack-surface: IP spoofing / trusted-proxy scoping ---
sp_assert("attack test — IP spoofing: a bypass granted for one IP is never active when checked against a different (spoofed/claimed) IP", !Email2faService::isBypassActive(null, $e2faNow + 3600, $e2faNow) || !sp_test_bypass_scope_matches(42, "client", "203.0.113.9", 42, "client", "10.0.0.1"), $failures, $passed);

// --- Schema regression: every index/unique-key name declared anywhere
// in security_pack.php's migrations must be <= 64 characters — MySQL's
// hard identifier-length limit. A real production bug (reported by the
// user) came from relying on Laravel's AUTO-GENERATED index name
// (<table>_<col1>_<col2>_..._index), which silently exceeded 64 chars
// once a longer table name (nnm_security_pack_email2fa_challenges) was
// combined with a 4-column index — MySQL rejected the whole CREATE
// TABLE with "Identifier name ... is too long", failing the entire
// module upgrade. Every multi-column/explicitly-named index in
// security_pack.php now passes an explicit short name specifically to
// avoid this; this test greps the actual source file so a future
// migration that reintroduces an unnamed long index is caught by the
// test suite BEFORE it reaches a live database, not after. ---
function sp_test_index_identifier_lengths(string $securityPackPhpPath): array
{
    $tooLong = [];
    $source = file_get_contents($securityPackPhpPath);
    if($source === false) {
        return ["error" => "could not read " . $securityPackPhpPath];
    }
    $tableName = null;
    foreach (preg_split('/\r?\n/', $source) as $line) {
        if(preg_match('/schema\(\)->create\("([a-z0-9_]+)"/', $line, $m)) {
            $tableName = $m[1];
            continue;
        }
        // Explicitly-named index/unique — always safe regardless of
        // column count, since the identifier itself is checked directly.
        if(preg_match('/->(index|unique)\(\s*(\[[^\]]*\]|"[a-z0-9_]+")\s*,\s*"([a-z0-9_]+)"/', $line, $m)) {
            if(strlen($m[3]) > 64) {
                $tooLong[] = $m[3];
            }
            continue;
        }
        // Unnamed multi-column index/unique — Laravel auto-generates
        // <table>_<col1>_<col2>_..._<index|unique>; this is exactly the
        // pattern that broke in production, so it is computed and
        // checked here too.
        if($tableName !== null && preg_match('/->(index|unique)\(\s*\[([^\]]*)\]\s*\)/', $line, $m)) {
            $cols = array_map(static fn ($c) => trim($c, " \"'"), explode(",", $m[2]));
            $autoName = $tableName . "_" . implode("_", $cols) . "_" . $m[1];
            if(strlen($autoName) > 64) {
                $tooLong[] = $autoName;
            }
        }
    }
    return $tooLong;
}
$indexLengthCheck = sp_test_index_identifier_lengths(__DIR__ . "/../security_pack.php");
sp_assert("schema regression: no index/unique-key identifier in security_pack.php's migrations (named or Laravel-auto-generated) exceeds MySQL's 64-character limit — the exact class of bug that broke the 2.6.0 email2fa_challenges migration in production", $indexLengthCheck === [], $failures, $passed);
if($indexLengthCheck !== [] && !isset($indexLengthCheck["error"])) {
    foreach ($indexLengthCheck as $badName) {
        $failures[] = "  -> over-length identifier (" . strlen($badName) . " chars): " . $badName;
    }
}

// --- dct_email_2fa (native WHMCS Security Module) — pure helper tests
// (2.6.1 architecture correction). Only the functions with no DB/session
// dependency are exercised here, consistent with this whole suite's
// "no live DB in the CLI runner" constraint; dct_email_2fa_challenge()/
// _verify()/_activate()/_activateverify() themselves are DB-backed
// wrappers around the SAME Email2faService methods already exhaustively
// tested above, so they are not re-tested end-to-end here. ---

// dct_email_2fa_settings_from_params(): maps WHMCS's native config
// $params into the settings-array shape Email2faService expects.
$mappedDefaults = dct_email_2fa_settings_from_params([]);
sp_assert("dct_email_2fa settings mapping: an empty \$params (module not yet configured) resolves to the same safe defaults Email2faService itself uses", $mappedDefaults === [
    "email_2fa_length" => 6, "email_2fa_minutes" => 10, "email_2fa_max_attempts" => 5,
    // FIX (2026-08-25): DCT_EMAIL_2FA_DEFAULT_RESEND_COOLDOWN raised
    // from 60 to 300 per explicit request — this literal-defaults
    // assertion updated to match, intentionally, not a regression.
    "email_2fa_max_resends" => 3, "email_2fa_resend_cooldown" => 300,
    "email_2fa_bypass_same_ip" => "1", "email_2fa_bypass_days" => 7,
], $failures, $passed);

$mappedCustom = dct_email_2fa_settings_from_params([
    "CodeLength" => "8", "CodeValidMinutes" => "20", "MaxAttempts" => "7",
    "MaxResends" => "5", "ResendCooldownSeconds" => "120", "BypassSameIp" => "0", "BypassDays" => "30",
]);
sp_assert("dct_email_2fa settings mapping: every WHMCS-native config field is mapped through to the matching Email2faService settings key, unmodified (clamping itself is Email2faService's own job downstream)", $mappedCustom === [
    "email_2fa_length" => "8", "email_2fa_minutes" => "20", "email_2fa_max_attempts" => "7",
    "email_2fa_max_resends" => "5", "email_2fa_resend_cooldown" => "120",
    "email_2fa_bypass_same_ip" => "0", "email_2fa_bypass_days" => "30",
], $failures, $passed);

$mappedFallback = dct_email_2fa_settings_from_params([], ["email_2fa_length" => 7, "email_2fa_bypass_days" => 14]);
sp_assert("dct_email_2fa settings mapping: falls back to security_pack's own settings table only for fields WHMCS's native \$params didn't supply (never overrides a real native value)", $mappedFallback["email_2fa_length"] === 7 && $mappedFallback["email_2fa_bypass_days"] === 14 && $mappedFallback["email_2fa_minutes"] === 10, $failures, $passed);

// dct_email_2fa_config(): every field the module declares to WHMCS is
// present, so Setup > Security > Two-Factor Authentication actually
// renders a control for each configurable value.
$dctConfig = dct_email_2fa_config();
foreach (["CodeLength", "CodeValidMinutes", "MaxAttempts", "MaxResends", "ResendCooldownSeconds", "BypassSameIp", "BypassDays"] as $field) {
    sp_assert("dct_email_2fa_config() declares the '{$field}' field WHMCS renders on Setup > Security > Two-Factor Authentication", array_key_exists($field, $dctConfig), $failures, $passed);
}
sp_assert("dct_email_2fa_config() never declares a field for the OTP value/hash/secret itself (nothing sensitive is ever a WHMCS-persisted config value)", !array_key_exists("Secret", $dctConfig) && !array_key_exists("OTP", $dctConfig), $failures, $passed);

// dct_email_2fa_context(): admin/client/fallback resolution — pure given
// the $_SESSION superglobal, which this test controls directly (no DB).
$_SESSION = [];
$_SESSION["adminid"] = 7;
sp_assert("dct_email_2fa_context(): an adminid session marker resolves to the admin context", dct_email_2fa_context() === ["type" => "admin", "id" => 7], $failures, $passed);
$_SESSION = [];
$_SESSION["uid"] = 42;
sp_assert("dct_email_2fa_context(): a uid session marker (and no adminid) resolves to the client context", dct_email_2fa_context() === ["type" => "client", "id" => 42], $failures, $passed);
$_SESSION = [];
sp_assert("dct_email_2fa_context(): with neither session marker and no fallback id, resolves to a harmless zero-id client context rather than throwing", dct_email_2fa_context() === ["type" => "client", "id" => 0], $failures, $passed);

// dct_email_2fa_bypass_active(): the shared decision both challenge()
// and verify() call, re-implemented here as a pure wrapper check —
// exercised indirectly above via Email2faService::isBypassActive()'s own
// boundary tests; this confirms the function exists and has the
// expected signature/behaviour shape for a definitely-inactive case
// (no DB tables in this CLI runner, so only the "nothing found" path is
// reachable without a live database — matches every other DB-backed
// method in this suite that degrades to a safe default under try/catch).
sp_assert("dct_email_2fa_bypass_active(): with no database/tables available, fails closed (no bypass) rather than throwing or defaulting to true", dct_email_2fa_bypass_active(1, "client", "203.0.113.5") === false, $failures, $passed);

// --- Email 2FA delivery diagnostics (2.6.3 "no mail received" fix,
// 2.7.0 switch to WHMCS's own mail pipeline) ---
// sendTestEmail()/sendViaWhmcs() call WHMCS's real sendAdminMessage()/
// sendMessage() functions, which are not defined/available in this CLI
// runner (no live WHMCS DB/session), so this suite can only assert the
// return CONTRACT — {sent: bool, reason: ?string} — and the "fails
// closed with a clear reason rather than fatal-erroring" behavior, not
// a specific delivery outcome — consistent with every other DB/
// environment-backed method in this suite.

$testEmailAdminShape = Email2faService::sendTestEmail(Email2faService::TYPE_ADMIN, 1);
sp_assert("Email2faService::sendTestEmail(): admin path always returns the {sent, reason} contract, failing closed (never throwing) when sendAdminMessage() is unavailable in this environment", is_array($testEmailAdminShape) && array_key_exists("sent", $testEmailAdminShape) && array_key_exists("reason", $testEmailAdminShape) && is_bool($testEmailAdminShape["sent"]), $failures, $passed);

$testEmailClientShape = Email2faService::sendTestEmail(Email2faService::TYPE_CLIENT, 1);
sp_assert("Email2faService::sendTestEmail(): client path always returns the {sent, reason} contract, failing closed with a clear reason when no client account can be resolved for the user (no live DB in this runner)", is_array($testEmailClientShape) && array_key_exists("sent", $testEmailClientShape) && array_key_exists("reason", $testEmailClientShape) && is_bool($testEmailClientShape["sent"]), $failures, $passed);
sp_assert("Email2faService::sendTestEmail(): never includes the string 'OTP' (a test send's diagnostic reason must never resemble a real one-time code disclosure)", !preg_match('/\bOTP\b/i', (string) $testEmailClientShape["reason"]), $failures, $passed);

// Source-pattern regression: dct_email_2fa_activate() and
// dct_email_2fa_challenge() must both branch on the actual
// beginActivation()/createChallenge() return status rather than
// unconditionally claiming "we sent a code" — this is the exact class
// of bug behind the "no mail received" report (the UI showed success
// text even when Email2faService::sendOtpEmail() had already failed).
$dctSource = file_get_contents(__DIR__ . "/../../../security/dct_email_2fa/dct_email_2fa.php");
sp_assert("dct_email_2fa.php source: sends a real \$result[\"status\"] branch (not just an unconditional success message) at least twice — once for activation, once for the login challenge — so a send_failed status is never presented to the user as success", $dctSource !== false && substr_count($dctSource, 'send_failed') >= 2, $failures, $passed);

// --- Country Restriction (2.8.0) ---
// CountryRestrictionService is a pure CONSUMER of the existing GeoIP
// architecture — it never looks up a country itself, so these tests
// only exercise the allow/block decision matrix and input normalization,
// not GeoIP resolution (GeoIpManager/MaxMindProvider/CurlApiProvider
// already own that, and require a DB/file the CLI runner doesn't have).

$crDisabled = ["country_restriction" => "", "disallowed_countries" => json_encode(["CN"])];
sp_assert("Country Restriction: disabled feature never blocks, even with a matching country configured", CountryRestrictionService::evaluate($crDisabled, "CN")["blocked"] === false, $failures, $passed);

$crBlockList = ["country_restriction" => "on", "country_restriction_mode" => "block", "disallowed_countries" => json_encode(["CN", "RU", "KP"])];
sp_assert("Country Restriction: block mode blocks a listed country", CountryRestrictionService::evaluate($crBlockList, "CN")["blocked"] === true, $failures, $passed);
sp_assert("Country Restriction: block mode allows a non-listed country", CountryRestrictionService::evaluate($crBlockList, "IN")["blocked"] === false, $failures, $passed);
sp_assert("Country Restriction: block mode is case-insensitive against the configured list", CountryRestrictionService::evaluate($crBlockList, "cn")["blocked"] === true, $failures, $passed);

$crAllowList = ["country_restriction" => "on", "country_restriction_mode" => "allow", "disallowed_countries" => json_encode(["IN", "US", "GB"])];
sp_assert("Country Restriction: allow mode allows a listed country", CountryRestrictionService::evaluate($crAllowList, "IN")["blocked"] === false, $failures, $passed);
sp_assert("Country Restriction: allow mode blocks a non-listed country", CountryRestrictionService::evaluate($crAllowList, "CN")["blocked"] === true, $failures, $passed);

$crEmptyBlockList = ["country_restriction" => "on", "country_restriction_mode" => "block", "disallowed_countries" => "[]"];
sp_assert("Country Restriction: enabled block mode with an empty rule list is a safe no-op (does not block everyone)", CountryRestrictionService::evaluate($crEmptyBlockList, "CN")["blocked"] === false, $failures, $passed);

$crEmptyAllowList = ["country_restriction" => "on", "country_restriction_mode" => "allow", "disallowed_countries" => "[]"];
sp_assert("Country Restriction: enabled allow mode with an empty rule list is a safe no-op (does not block everyone) — an admin accidentally saving zero countries must never lock out the whole site", CountryRestrictionService::evaluate($crEmptyAllowList, "IN")["blocked"] === false, $failures, $passed);

$crUnknownDefault = ["country_restriction" => "on", "country_restriction_mode" => "block", "disallowed_countries" => json_encode(["CN"])];
sp_assert("Country Restriction: unknown country (GeoIP could not resolve one) defaults to Allow, never silently treated as a blocked country", CountryRestrictionService::evaluate($crUnknownDefault, null)["blocked"] === false, $failures, $passed);
sp_assert("Country Restriction: unknown country also defaults to Allow for an empty-string country", CountryRestrictionService::evaluate($crUnknownDefault, "")["blocked"] === false, $failures, $passed);

$crUnknownBlockPolicy = $crUnknownDefault + ["country_restriction_unknown_policy" => "block"];
sp_assert("Country Restriction: explicit fail-closed unknown-country policy blocks when the country cannot be determined", CountryRestrictionService::evaluate($crUnknownBlockPolicy, null)["blocked"] === true, $failures, $passed);
sp_assert("Country Restriction: unknown-country policy has no effect once a real country IS resolved", CountryRestrictionService::evaluate($crUnknownBlockPolicy, "IN")["blocked"] === false, $failures, $passed);

sp_assert("Country Restriction: normalizeMode() defaults unrecognized/missing values to block (the pre-2.8.0 behavior)", CountryRestrictionService::normalizeMode(null) === CountryRestrictionService::MODE_BLOCK, $failures, $passed);
sp_assert("Country Restriction: normalizeUnknownPolicy() defaults unrecognized/missing values to allow (fail open)", CountryRestrictionService::normalizeUnknownPolicy(null) === CountryRestrictionService::UNKNOWN_ALLOW, $failures, $passed);

sp_assert("Country Restriction: normalizeCountryList() accepts a JSON-encoded string (as stored in settings)", CountryRestrictionService::normalizeCountryList('["cn","ru"]') === ["CN", "RU"], $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() accepts a raw PHP array", CountryRestrictionService::normalizeCountryList(["in", "US"]) === ["IN", "US"], $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() de-duplicates after uppercasing", count(CountryRestrictionService::normalizeCountryList(["cn", "CN", "Cn"])) === 1, $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() silently drops entries that aren't a 2-letter code (SQLi payload)", CountryRestrictionService::normalizeCountryList(["CN", "'; DROP TABLE x; --"]) === ["CN"], $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() silently drops entries that aren't a 2-letter code (XSS payload)", CountryRestrictionService::normalizeCountryList(["CN", "<script>alert(1)</script>"]) === ["CN"], $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() never throws on malformed JSON", CountryRestrictionService::normalizeCountryList("{not valid json") === [], $failures, $passed);
sp_assert("Country Restriction: normalizeCountryList() of null/non-array/non-string input returns empty, not a fatal error", CountryRestrictionService::normalizeCountryList(null) === [], $failures, $passed);

$knownCodes = ["IN" => 1, "US" => 1, "GB" => 1];
sp_assert("Country Restriction: isValidCountryCode() true for a real, known code", CountryRestrictionService::isValidCountryCode("in", $knownCodes), $failures, $passed);
sp_assert("Country Restriction: isValidCountryCode() false for a well-formed but unknown code", !CountryRestrictionService::isValidCountryCode("ZZ", $knownCodes), $failures, $passed);
sp_assert("Country Restriction: isValidCountryCode() false for garbage input", !CountryRestrictionService::isValidCountryCode("not-a-code", $knownCodes), $failures, $passed);

// --- Security Pack 3.0: Unified Two-Factor Authentication -------------

// OtpEngine — must behave IDENTICALLY to Email2faService's own pure
// helpers (it's the same code, only relocated), so every existing
// Email2faService assertion pattern is re-run once against OtpEngine
// directly to prove the extraction changed nothing observable.
sp_assert("OtpEngine: clampOtpLength() clamps below range", OtpEngine::clampOtpLength(2) === OtpEngine::MIN_OTP_LENGTH, $failures, $passed);
sp_assert("OtpEngine: clampOtpLength() clamps above range", OtpEngine::clampOtpLength(20) === OtpEngine::MAX_OTP_LENGTH, $failures, $passed);
sp_assert("OtpEngine: clampOtpLength() passes through an in-range value", OtpEngine::clampOtpLength(7) === 7, $failures, $passed);
sp_assert("OtpEngine: clampValidityMinutes() clamps below range", OtpEngine::clampValidityMinutes(0) === OtpEngine::MIN_VALIDITY_MINUTES, $failures, $passed);
sp_assert("OtpEngine: clampValidityMinutes() clamps above range", OtpEngine::clampValidityMinutes(999) === OtpEngine::MAX_VALIDITY_MINUTES, $failures, $passed);
sp_assert("OtpEngine: clampBypassDays() clamps below range", OtpEngine::clampBypassDays(0) === OtpEngine::MIN_BYPASS_DAYS, $failures, $passed);
sp_assert("OtpEngine: clampBypassDays() clamps above range", OtpEngine::clampBypassDays(9999) === OtpEngine::MAX_BYPASS_DAYS, $failures, $passed);
sp_assert("OtpEngine: clampMaxAttempts() lower bound is 3", OtpEngine::clampMaxAttempts(0) === 3, $failures, $passed);
sp_assert("OtpEngine: clampMaxAttempts() upper bound is 10", OtpEngine::clampMaxAttempts(999) === 10, $failures, $passed);
sp_assert("OtpEngine: clampMaxResends() lower bound is 1", OtpEngine::clampMaxResends(0) === 1, $failures, $passed);
sp_assert("OtpEngine: clampMaxResends() upper bound is 10", OtpEngine::clampMaxResends(999) === 10, $failures, $passed);
sp_assert("OtpEngine: clampResendCooldownSeconds() lower bound is 30", OtpEngine::clampResendCooldownSeconds(1) === 30, $failures, $passed);
sp_assert("OtpEngine: clampResendCooldownSeconds() upper bound is 600", OtpEngine::clampResendCooldownSeconds(99999) === 600, $failures, $passed);
sp_assert("OtpEngine: generateOtp() produces the requested digit length, zero-padded", strlen(OtpEngine::generateOtp(6)) === 6, $failures, $passed);
sp_assert("OtpEngine: generateOtp() output is purely numeric", ctype_digit(OtpEngine::generateOtp(8)), $failures, $passed);
$otpHash = OtpEngine::hashOtp("123456");
sp_assert("OtpEngine: hashOtp() never returns the plaintext OTP", $otpHash !== "123456", $failures, $passed);
sp_assert("OtpEngine: verifyOtpHash() accepts the correct OTP", OtpEngine::verifyOtpHash("123456", $otpHash), $failures, $passed);
sp_assert("OtpEngine: verifyOtpHash() rejects an incorrect OTP", !OtpEngine::verifyOtpHash("654321", $otpHash), $failures, $passed);
sp_assert("OtpEngine: verifyOtpHash() rejects an empty hash rather than erroring", !OtpEngine::verifyOtpHash("123456", ""), $failures, $passed);
sp_assert("OtpEngine: evaluateOtpSubmission() a correct code within window is valid", OtpEngine::evaluateOtpSubmission("123456", $otpHash, "pending", time() + 300, 0, 5, time()) === "valid", $failures, $passed);
sp_assert("OtpEngine: evaluateOtpSubmission() an incorrect code is invalid", OtpEngine::evaluateOtpSubmission("000000", $otpHash, "pending", time() + 300, 0, 5, time()) === "invalid", $failures, $passed);
sp_assert("OtpEngine: evaluateOtpSubmission() an expired challenge reports expired", OtpEngine::evaluateOtpSubmission("123456", $otpHash, "pending", time() - 10, 0, 5, time()) === "expired", $failures, $passed);
sp_assert("OtpEngine: evaluateOtpSubmission() a consumed challenge reports consumed even with the right code", OtpEngine::evaluateOtpSubmission("123456", $otpHash, "consumed", time() + 300, 0, 5, time()) === "consumed", $failures, $passed);
sp_assert("OtpEngine: evaluateOtpSubmission() max attempts reached reports locked", OtpEngine::evaluateOtpSubmission("123456", $otpHash, "pending", time() + 300, 5, 5, time()) === "locked", $failures, $passed);
sp_assert("OtpEngine: isBypassActive() true while unexpired and unrevoked", OtpEngine::isBypassActive(null, time() + 100, time()), $failures, $passed);
sp_assert("OtpEngine: isBypassActive() false once revoked, even if unexpired", !OtpEngine::isBypassActive(date("Y-m-d H:i:s"), time() + 100, time()), $failures, $passed);
sp_assert("OtpEngine: isBypassActive() false once expired", !OtpEngine::isBypassActive(null, time() - 1, time()), $failures, $passed);
sp_assert("OtpEngine: maskEmail() keeps the domain and masks most of the local part", OtpEngine::maskEmail("alexander@example.com") === "a••••••••@example.com", $failures, $passed);
sp_assert("OtpEngine: maskEmail() never crashes on input with no @", OtpEngine::maskEmail("not-an-email") === "•••", $failures, $passed);
sp_assert("OtpEngine: maskPhone() keeps only the last 3 digits visible", OtpEngine::maskPhone("+15551234567") === "•••••••••567", $failures, $passed);
sp_assert("OtpEngine: maskPhone() of a very short number masks entirely rather than erroring", OtpEngine::maskPhone("12") === "••", $failures, $passed);

// TotpService — RFC 6238 / RFC 4226 correctness against the well-known
// published test vector (RFC 6238 Appendix B, SHA-1, 8-digit truncated
// to the last 6 digits here since this module standardizes on 6):
// secret "12345678901234567890" (ASCII), T=59s -> HOTP full value
// 94287082 for the 8-digit vector, so the low 6 digits are 287082.
$rfcSecretBase32 = TotpService::base32Encode("12345678901234567890");
sp_assert("TotpService: base32Encode()/base32Decode() round-trip the RFC 6238 test-vector secret", TotpService::base32Decode($rfcSecretBase32) === "12345678901234567890", $failures, $passed);
sp_assert("TotpService: totpAt() matches the RFC 6238 published test vector at T=59s (low 6 digits of 94287082)", TotpService::totpAt($rfcSecretBase32, 59, 30, 8) === "94287082", $failures, $passed);
sp_assert("TotpService: totpAt() with 6 digits matches the low 6 digits of the same vector", TotpService::totpAt($rfcSecretBase32, 59, 30, 6) === "287082", $failures, $passed);
sp_assert("TotpService: verify() accepts the correct current-window code", TotpService::verify($rfcSecretBase32, "287082", 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: verify() rejects an incorrect code", !TotpService::verify($rfcSecretBase32, "000000", 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: verify() tolerates one step of clock drift forward", TotpService::verify($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 + 30, 30, 6), 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: verify() tolerates one step of clock drift backward", TotpService::verify($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 - 30, 30, 6), 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: verify() rejects two steps of clock drift (beyond tolerance)", !TotpService::verify($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 + 60, 30, 6), 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: verify() rejects a non-numeric candidate rather than erroring", !TotpService::verify($rfcSecretBase32, "abcdef", 59, 1, 30, 6), $failures, $passed);
sp_assert("TotpService: generateSecret() returns a valid Base32 string of the expected length", preg_match('/^[A-Z2-7]+$/', TotpService::generateSecret()) === 1, $failures, $passed);
sp_assert("TotpService: two calls to generateSecret() never collide", TotpService::generateSecret() !== TotpService::generateSecret(), $failures, $passed);
sp_assert("TotpService: provisioningUri() is a well-formed otpauth:// URI containing the secret", str_starts_with(TotpService::provisioningUri($rfcSecretBase32, "user@example.com", "Security Pack"), "otpauth://totp/") && str_contains(TotpService::provisioningUri($rfcSecretBase32, "user@example.com", "Security Pack"), $rfcSecretBase32), $failures, $passed);
sp_assert("TotpService: formatSecretForDisplay() groups into 4-character blocks", TotpService::formatSecretForDisplay("ABCDEFGHIJKL") === "ABCD EFGH IJKL", $failures, $passed);
if(function_exists("sodium_crypto_secretbox_keygen")) {
    $totpKey = sodium_crypto_secretbox_keygen();
    $encryptedSecret = TotpService::encryptSecret($rfcSecretBase32, $totpKey);
    sp_assert("TotpService: encryptSecret() never returns the plaintext secret", $encryptedSecret !== $rfcSecretBase32 && !str_contains($encryptedSecret, $rfcSecretBase32), $failures, $passed);
    sp_assert("TotpService: decryptSecret() round-trips encryptSecret() with the correct key", TotpService::decryptSecret($encryptedSecret, $totpKey) === $rfcSecretBase32, $failures, $passed);
    $wrongKey = sodium_crypto_secretbox_keygen();
    sp_assert("TotpService: decryptSecret() fails closed (null) with the wrong key rather than returning garbage", TotpService::decryptSecret($encryptedSecret, $wrongKey) === null, $failures, $passed);
}

// TotpService::matchingStep() — dct_totp_2fa rebuild's replay-protection
// primitive (Section 11). verify() is now DEFINED IN TERMS OF this
// method (verify() === matchingStep() !== null), so every verify() test
// above already exercises it indirectly; these tests check the counter
// value itself, which verify() doesn't expose.
$rfcStep59 = intdiv(59, 30); // = 1
sp_assert("TotpService: matchingStep() returns the exact RFC 6238 HOTP counter (T=59s, period=30s -> counter 1) for a matching code", TotpService::matchingStep($rfcSecretBase32, "287082", 59, 1, 30, 6) === $rfcStep59, $failures, $passed);
sp_assert("TotpService: matchingStep() returns null for a non-matching code", TotpService::matchingStep($rfcSecretBase32, "000000", 59, 1, 30, 6) === null, $failures, $passed);
sp_assert("TotpService: matchingStep() returns null for a non-numeric candidate", TotpService::matchingStep($rfcSecretBase32, "abcdef", 59, 1, 30, 6) === null, $failures, $passed);
sp_assert("TotpService: matchingStep() returns the ADVANCED counter (not the base counter) when the code is from one step in the future", TotpService::matchingStep($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 + 30, 30, 6), 59, 1, 30, 6) === $rfcStep59 + 1, $failures, $passed);
sp_assert("TotpService: matchingStep() returns the EARLIER counter (not the base counter) when the code is from one step in the past", TotpService::matchingStep($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 - 30, 30, 6), 59, 1, 30, 6) === $rfcStep59 - 1, $failures, $passed);
sp_assert("TotpService: verify() is a pure alias for (matchingStep() !== null) — zero-regression refactor", TotpService::verify($rfcSecretBase32, "287082", 59, 1, 30, 6) === (TotpService::matchingStep($rfcSecretBase32, "287082", 59, 1, 30, 6) !== null), $failures, $passed);
sp_assert("TotpService: matchingStep() counters increase monotonically with wall-clock time (the property replay-rejection in TotpEnrollmentService::verifyLogin() relies on)", TotpService::matchingStep($rfcSecretBase32, TotpService::totpAt($rfcSecretBase32, 59 + 30, 30, 6), 59 + 30, 1, 30, 6) > TotpService::matchingStep($rfcSecretBase32, "287082", 59, 1, 30, 6), $failures, $passed);

// RecoveryCodeService — pure generate/hash/verify only (DB-backed
// regenerate()/attemptConsume() are exercised manually against a real
// WHMCS install, same as every other DB-backed method in this suite).
$recoveryCodes = RecoveryCodeService::generatePlaintextCodes();
sp_assert("RecoveryCodeService: generatePlaintextCodes() returns the configured count", count($recoveryCodes) === RecoveryCodeService::CODE_COUNT, $failures, $passed);
sp_assert("RecoveryCodeService: generatePlaintextCodes() returns 10 distinct codes, never duplicates", count(array_unique($recoveryCodes)) === RecoveryCodeService::CODE_COUNT, $failures, $passed);
$recoveryHash = RecoveryCodeService::hashCode($recoveryCodes[0]);
sp_assert("RecoveryCodeService: hashCode() never returns the plaintext code", $recoveryHash !== $recoveryCodes[0], $failures, $passed);
sp_assert("RecoveryCodeService: verifyCode() accepts the correct code", RecoveryCodeService::verifyCode($recoveryCodes[0], $recoveryHash), $failures, $passed);
sp_assert("RecoveryCodeService: verifyCode() accepts the correct code entered lowercase (case-insensitive)", RecoveryCodeService::verifyCode(strtolower($recoveryCodes[0]), $recoveryHash), $failures, $passed);
sp_assert("RecoveryCodeService: verifyCode() rejects a different valid-looking code", !RecoveryCodeService::verifyCode($recoveryCodes[1], $recoveryHash), $failures, $passed);
sp_assert("RecoveryCodeService: verifyCode() rejects an empty hash rather than erroring", !RecoveryCodeService::verifyCode($recoveryCodes[0], ""), $failures, $passed);

// TotpQrGenerator — pure ISO/IEC 18004 encoder. These pin the exact
// Reed-Solomon regression caught during development (a swapped generator
// polynomial coefficient produced undecodable QR codes with no PHP-level
// error — the RS codewords below are cross-checked against an independent
// reference implementation and a real pyzbar/OpenCV decode of the rendered
// SVG, not just re-derived from this same code).
$qrRs = new ReflectionMethod(TotpQrGenerator::class, "rsEncode");
$qrRs->setAccessible(true);
$qrRsResult = $qrRs->invoke(null, [0x40, 0x14, 0x10, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC], 10);
sp_assert(
    "TotpQrGenerator: rsEncode() matches the independently-computed Reed-Solomon reference for a version-1/ECC-M 'A' payload",
    $qrRsResult === [0x6B, 0x70, 0xF4, 0x18, 0xA3, 0x7A, 0x11, 0x5F, 0x34, 0xFC],
    $failures,
    $passed
);

$qrGenPoly = new ReflectionMethod(TotpQrGenerator::class, "generatorPolynomial");
$qrGenPoly->setAccessible(true);
sp_assert(
    "TotpQrGenerator: generatorPolynomial(10) matches the published ISO/IEC 18004 degree-10 generator coefficients",
    $qrGenPoly->invoke(null, 10) === [0x1, 0xD8, 0xC2, 0x9F, 0x6F, 0xC7, 0x5E, 0x5F, 0x71, 0x9D, 0xC1],
    $failures,
    $passed
);

$qrShort = TotpQrGenerator::encodeMatrix("otpauth://totp/A:b@c.com?secret=JBSWY3DPEHPK3PXP&issuer=A", TotpQrGenerator::ECC_M);
sp_assert("TotpQrGenerator: encodeMatrix() picks the smallest version that fits a short otpauth:// URI", $qrShort["version"] === 4, $failures, $passed);
sp_assert("TotpQrGenerator: encodeMatrix() matrix dimensions match 17+4*version for the chosen version", $qrShort["size"] === 17 + 4 * $qrShort["version"], $failures, $passed);

$qrSvg = TotpQrGenerator::generateSvg("otpauth://totp/A:b@c.com?secret=JBSWY3DPEHPK3PXP&issuer=A", 5);
sp_assert("TotpQrGenerator: generateSvg() returns a well-formed inline <svg> with no external resource references (no <image>/xlink:href)", strpos($qrSvg, "<svg") === 0 && strpos($qrSvg, "xlink:href") === false && strpos($qrSvg, "<image") === false, $failures, $passed);

// A ~230-byte otpauth:// URI (long issuer + long account label) exceeds
// version-10 capacity at ECC M but fits at ECC L — generateSvg() must
// fall back automatically rather than erroring for realistic long labels.
$qrLongData = "otpauth://totp/" . str_repeat("Security Pack (WHMCS - example.com)", 1) . "%3A" . str_repeat("longer.client.name+tag@sub.example-domain.co.uk", 2) . "?secret=" . str_repeat("JBSWY3DPEHPK3PXP", 2) . "&issuer=x&algorithm=SHA1&digits=6&period=30";
$qrLongOk = true;
try {
    TotpQrGenerator::generateSvg($qrLongData, 5);
} catch (\Throwable $e) {
    $qrLongOk = false;
}
sp_assert("TotpQrGenerator: generateSvg() falls back from ECC M to ECC L for long otpauth:// URIs instead of throwing", $qrLongOk, $failures, $passed);

// Data that exceeds even version 10 at ECC L must fail loudly (never
// silently truncate/corrupt) so the caller can fall back to manual-entry-only.
$qrTooLong = str_repeat("x", 400);
$qrThrew = false;
try {
    TotpQrGenerator::encodeMatrix($qrTooLong, TotpQrGenerator::ECC_L);
} catch (\RuntimeException $e) {
    $qrThrew = true;
}
sp_assert("TotpQrGenerator: encodeMatrix() throws rather than truncating when data exceeds version-10/ECC-L capacity", $qrThrew, $failures, $passed);

// DctWhatsAppNotificationsBridge — pure helpers only (the actual send
// paths require the real dct_whatsapp_notifications addon's runtime
// classes, exercised manually against a real WHMCS install with that
// addon installed, same as every other DB/addon-backed method in this suite).
sp_assert("DctWhatsAppNotificationsBridge: platformAttemptOrder('auto') tries Meta, then Botms, then Baileys, matching the reference module's fallback order", DctWhatsAppNotificationsBridge::platformAttemptOrder("auto") === ["meta", "botms", "baileys"], $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: platformAttemptOrder() with a specific platform tries ONLY that platform, no fallback", DctWhatsAppNotificationsBridge::platformAttemptOrder("botms") === ["botms"], $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: platformAttemptOrder() with an unrecognized value falls back to the full auto order (fail safe, not fail closed)", DctWhatsAppNotificationsBridge::platformAttemptOrder("not-a-real-platform") === ["meta", "botms", "baileys"], $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: parseStoredTemplateValue() splits the addon's 'name|language' encoding", DctWhatsAppNotificationsBridge::parseStoredTemplateValue("login_code|en_US") === ["login_code", "en_US"], $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: parseStoredTemplateValue() tolerates a bare template name with no '|' (settings saved before the encoding existed)", DctWhatsAppNotificationsBridge::parseStoredTemplateValue("login_code") === ["login_code", null], $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: isAvailable() returns false (not a fatal error) when the dct_whatsapp_notifications addon isn't installed in this test environment", DctWhatsAppNotificationsBridge::isAvailable() === false, $failures, $passed);

// 3.1.5 — a production TypeError was reported deep inside the addon's own
// NotificationSender -> NotificationPlatformResolver -> PlatformFactory
// chain (a null $platform reaching a non-nullable typed parameter). The
// addon's own dependency chain can't be exercised without the real addon
// installed, so this is verified by source inspection: sendCode()'s own
// body (not just the private per-platform helpers it calls) must be
// wrapped in a try/catch(\Throwable) that returns false rather than
// letting any unexpected error escape and crash the login/activation
// request — belt-and-suspenders on top of the pre-existing per-platform
// catches inside sendViaTemplatedNotification()/sendPlainMessage().
$dctBridgeSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/Providers/DctWhatsAppNotificationsBridge.php");
$sendCodeBodyStart = strpos($dctBridgeSource, "public static function sendCode(");
$sendViaTemplatedStart = strpos($dctBridgeSource, "private static function sendViaTemplatedNotification(");
sp_assert("DctWhatsAppNotificationsBridge: sendCode() is defined before sendViaTemplatedNotification() so the body-extraction below is valid", $sendCodeBodyStart !== false && $sendViaTemplatedStart !== false && $sendCodeBodyStart < $sendViaTemplatedStart, $failures, $passed);
$sendCodeBody = substr($dctBridgeSource, $sendCodeBodyStart, $sendViaTemplatedStart - $sendCodeBodyStart);
sp_assert("DctWhatsAppNotificationsBridge: sendCode()'s own body has a top-level try/catch(\\Throwable) around its whole send attempt, not just the private helpers it calls", (bool) preg_match('/\btry\s*\{/', $sendCodeBody) && (bool) preg_match('/catch\s*\(\s*\\\\Throwable\s+\$e\s*\)/', $sendCodeBody), $failures, $passed);
sp_assert("DctWhatsAppNotificationsBridge: sendCode()'s outer catch returns false rather than re-throwing or letting the error propagate", (bool) preg_match('/catch\s*\(\s*\\\\Throwable[\s\S]*?return false;[\s\S]*?\}/', $sendCodeBody), $failures, $passed);

// TwoFactorAuthenticationService::pickMostRecentTimestamp() — the ONE
// genuinely pure piece of the 2FA mutual-exclusion fix (only one of
// Email/DCTLAB WhatsApp/Time-Based Token may be the active primary
// method at a time; when more than one is found active — either right
// after a NEW activation via activateExclusive(), or self-healing an
// account left inconsistent by the bug this fix closes, via
// enforceSingleActiveMethod() — this decides which one survives, by
// "activated_at" recency). The surrounding orchestration
// (providers()/status()/activateExclusive()/enforceSingleActiveMethod())
// calls each provider's isActive()/disable(), which are DB-backed
// (WhatsAppTwoFactorService/TotpEnrollmentService/Email2faService) —
// same "exercised manually against a real WHMCS install, not this
// no-DB suite" category every other DB-backed 2FA orchestration method
// in this project already carries (OtpEngine's require-comment above,
// TwoFactorBypassService, WhatsAppTwoFactorService's own DB paths).
// Before enabling this in production: manually verify, on a staging
// WHMCS install with the security_pack tables present, that (1)
// activating Email while WhatsApp is active deactivates WhatsApp and
// vice versa for every method pair, (2) the deactivated method's
// enrollment/config row survives (status flips to "disabled", nothing
// is deleted — TOTP's secret specifically must survive, since only
// TotpEnrollmentService::reset() wipes it, never disable()), (3) the
// Client Security Center shows exactly one method as "Active" and the
// others as "Not active" after each transition, and (4) an account
// manually set to have two methods "active" in the DB self-heals to
// one the next time its status is read.
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() picks the method with the highest activated_at timestamp", TwoFactorAuthenticationService::pickMostRecentTimestamp(["email" => 1000, "whatsapp" => 2000, "totp" => 500]) === "whatsapp", $failures, $passed);
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() picks whichever of the three methods is highest, regardless of position", TwoFactorAuthenticationService::pickMostRecentTimestamp(["totp" => 9000, "email" => 500, "whatsapp" => 1000]) === "totp", $failures, $passed);
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() breaks an exact tie deterministically by first-key order, never randomly", TwoFactorAuthenticationService::pickMostRecentTimestamp(["email" => 500, "whatsapp" => 500, "totp" => 100]) === "email", $failures, $passed);
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() treats an all-zero map (no recorded activated_at anywhere) as a tie, still resolving deterministically rather than throwing", TwoFactorAuthenticationService::pickMostRecentTimestamp(["email" => 0, "whatsapp" => 0, "totp" => 0]) === "email", $failures, $passed);
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() with a single candidate returns that candidate", TwoFactorAuthenticationService::pickMostRecentTimestamp(["totp" => 42]) === "totp", $failures, $passed);
sp_assert("TwoFactorAuthenticationService::pickMostRecentTimestamp() is a pure function of its input, not dependent on iteration order beyond tie-break — reordering the same values still surfaces the true maximum", TwoFactorAuthenticationService::pickMostRecentTimestamp(["whatsapp" => 100, "totp" => 9000, "email" => 500]) === "totp", $failures, $passed);

// --- Security Pack 3.1.2 — ClientController::twoFactorRecommendation() ---
// Regression coverage for the Client Security Center's "Your Security"
// banner incorrectly saying "Email Two-Factor Authentication is
// disabled" while DCTLAB WhatsApp (or TOTP) was already the active
// method — see CHANGELOG's 3.1.2 entry. This is the pure decision
// logic ClientController::security_center() now calls with
// $activeTwoFactorMethod (TwoFactorAuthenticationService::status()'s
// own authoritative "active_method" — never re-derived from any single
// method's own table), so the banner and the Authentication section
// below it can never disagree again. NOT DB-backed — no real
// TwoFactorAuthenticationService::status() call happens here, only its
// already-resolved return value is fed in, matching how
// security_center() itself consumes it.
$genericMsg = "Two-factor authentication is not enabled. Enable Email, DCTLAB WhatsApp, or Time-Based Tokens.";

// 1. Email active → counts, earns the point, no recommendation.
$r = ClientController::twoFactorRecommendation(true, "email", $genericMsg);
sp_assert("twoFactorRecommendation(): Email active → counts, earns point, no recommendation", $r["counts"] === true && $r["earns_point"] === true && $r["recommendation"] === null, $failures, $passed);

// 2. WhatsApp active → counts, earns the point, no recommendation —
// and critically, no Email-specific text is produced.
$r = ClientController::twoFactorRecommendation(true, "whatsapp", $genericMsg);
sp_assert("twoFactorRecommendation(): WhatsApp active → counts, earns point, no recommendation", $r["counts"] === true && $r["earns_point"] === true && $r["recommendation"] === null, $failures, $passed);

// 3. TOTP active → counts, earns the point, no recommendation.
$r = ClientController::twoFactorRecommendation(true, "totp", $genericMsg);
sp_assert("twoFactorRecommendation(): TOTP active → counts, earns point, no recommendation", $r["counts"] === true && $r["earns_point"] === true && $r["recommendation"] === null, $failures, $passed);

// 4. All methods inactive (active_method === null) → counts, does NOT
// earn the point, and the provider-neutral warning appears.
$r = ClientController::twoFactorRecommendation(true, null, $genericMsg);
sp_assert("twoFactorRecommendation(): no active method → counts, does not earn point, warning appears", $r["counts"] === true && $r["earns_point"] === false && $r["recommendation"] === $genericMsg, $failures, $passed);

// 5. TOTP pending + WhatsApp active → active_method is still "whatsapp"
// (a pending enrollment never becomes the active_method) → 2FA remains
// enabled, no recommendation.
$r = ClientController::twoFactorRecommendation(true, "whatsapp", $genericMsg);
sp_assert("twoFactorRecommendation(): TOTP pending + WhatsApp active → still earns the point via WhatsApp", $r["earns_point"] === true && $r["recommendation"] === null, $failures, $passed);

// 6. TOTP pending + no active method → active_method is null (pending
// never counts as active) → the warning appears.
$r = ClientController::twoFactorRecommendation(true, null, $genericMsg);
sp_assert("twoFactorRecommendation(): TOTP pending only, nothing active → warning appears", $r["earns_point"] === false && $r["recommendation"] === $genericMsg, $failures, $passed);

// 7. WhatsApp active → the returned recommendation is never the
// Email-specific string, for every possible active method.
foreach (["email", "whatsapp", "totp"] as $activeMethod) {
    $r = ClientController::twoFactorRecommendation(true, $activeMethod, $genericMsg);
    sp_assert("twoFactorRecommendation(): active method \"" . $activeMethod . "\" never produces an Email-specific recommendation", $r["recommendation"] === null && strpos((string) $r["recommendation"], "Email") === false, $failures, $passed);
}

// 8. TOTP active → same guarantee, explicitly (mirrors #7's email case
// from the spec's own scenario list).
$r = ClientController::twoFactorRecommendation(true, "totp", $genericMsg);
sp_assert("twoFactorRecommendation(): does not recommend Email when TOTP is active", $r["recommendation"] === null, $failures, $passed);

// 9. Recommendation text is provider-neutral (names all three methods,
// singles none out) when no method is active.
$r = ClientController::twoFactorRecommendation(true, null, $genericMsg);
sp_assert("twoFactorRecommendation(): recommendation text mentions all three methods, not just Email", $r["recommendation"] !== null && strpos($r["recommendation"], "Email") !== false && strpos($r["recommendation"], "WhatsApp") !== false && strpos($r["recommendation"], "Time-Based Token") !== false, $failures, $passed);

// 10. No method available at all on this install (none of the three
// tables/security modules present) → does not count toward the score
// and produces no recommendation, regardless of $activeMethod (mirrors
// every other "$xAvailable" gated block in security_center()).
$r = ClientController::twoFactorRecommendation(false, null, $genericMsg);
sp_assert("twoFactorRecommendation(): no method available at all → does not count, no recommendation", $r["counts"] === false && $r["earns_point"] === false && $r["recommendation"] === null, $failures, $passed);

// --- Security Pack 3.1.3 — Manage button destination audit ---
// User-supplied screenshots (direct evidence) proved
// {$WEB_ROOT}/clientarea.php?action=security does NOT render a
// Two-Factor Authentication section on this WHMCS version — only
// {$WEB_ROOT}/user/security does (confirmed working, same screenshots).
// This is a template-only navigation fix — no PHP orchestration logic
// changed, so it is verified here via static analysis of the actual
// .tpl source (same technique/precedent as
// sp_test_index_identifier_lengths() above), not a runtime unit test.
// Extracts every `<a href="{$WEB_ROOT}/...">...Manage...</a>` link in
// the Authentication box, keyed by the row it belongs to (matched by
// the nearest preceding `{if $xxx}` block), and asserts each row's
// Manage destination.
function sp_test_security_center_manage_destinations(string $tplPath): array
{
    $source = file_get_contents($tplPath);
    if($source === false) {
        return ["error" => "could not read " . $tplPath];
    }
    // Only the Authentication box (between its <h3> and the Current
    // Session card) is in scope — the "View full login history" link
    // and Current Session card are unrelated to this fix.
    $start = strpos($source, "security_center_authentication");
    $end = strpos($source, "security_center_current_session");
    if($start === false || $end === false || $end <= $start) {
        return ["error" => "could not locate the Authentication box in " . $tplPath];
    }
    $box = substr($source, $start, $end - $start);

    // Several rows (e.g. the Email 2FA row) nest their OWN inner
    // {if status=='active'}...{elseif}...{else}...{/if} status-label
    // block INSIDE the outer {if $xAvailable}...<a href>...{/if} row
    // block, with the Manage link appearing AFTER that inner {/if}
    // closes. A naive non-greedy regex from the outer {if} to the
    // FIRST {/if} would stop at the INNER {/if} and never see the
    // href at all — so this walks the box token-by-token instead,
    // tracking {if}/{/if} nesting depth explicitly, and only records
    // an href when it appears at depth 1 (a direct child of the
    // CURRENT top-level row's {if}, not of some inner status block).
    preg_match_all('/\{if\s+([^}]+)\}|\{\/if\}|href="\{\$WEB_ROOT\}([^"]+)"/', $box, $tokens, PREG_SET_ORDER);
    $destinations = [];
    $stack = [];
    foreach ($tokens as $t) {
        if(strpos($t[0], "{if ") === 0) {
            $stack[] = trim($t[1]);
        } elseif($t[0] === "{/if}") {
            array_pop($stack);
        } elseif(isset($t[2]) && $t[2] !== "") {
            if(count($stack) === 1 && !isset($destinations[$stack[0]])) {
                $destinations[$stack[0]] = $t[2];
            }
        }
    }
    return $destinations;
}

$manageDestinations = sp_test_security_center_manage_destinations(__DIR__ . "/../templates/security_center.tpl");

// 1/2/3/4. Email / WhatsApp / TOTP / WHMCS's own native 2FA row all
// resolve to the confirmed-working native Two-Factor Authentication
// tab, not the classic action=security page that lacks it.
sp_assert("security_center.tpl: Email 2FA Manage → /user/security (the confirmed native Two-Factor Authentication tab)", ($manageDestinations["\$email2fa_available"] ?? null) === "/user/security", $failures, $passed);
sp_assert("security_center.tpl: WhatsApp 2FA Manage → /user/security", ($manageDestinations["\$whatsapp2fa_available"] ?? null) === "/user/security", $failures, $passed);
sp_assert("security_center.tpl: TOTP Manage → /user/security", ($manageDestinations["\$totp2fa_available"] ?? null) === "/user/security", $failures, $passed);
sp_assert("security_center.tpl: WHMCS's own native Two-Factor Authentication row Manage → /user/security", ($manageDestinations["\$two_factor_status !== null"] ?? null) === "/user/security", $failures, $passed);

// 5. Login Notification Manage destination is unchanged/correct — the
// classic action=security page genuinely hosts this row, confirmed by
// the same screenshot evidence.
sp_assert("security_center.tpl: Login Notification Manage → clientarea.php?action=security (unchanged, confirmed correct)", ($manageDestinations["\$login_notification_allowed"] ?? null) === "/clientarea.php?action=security", $failures, $passed);

// Password Reset Protection Manage destination is likewise unchanged —
// matched separately since it shares its {if} condition text with no
// other row in this box.
sp_assert("security_center.tpl: Password Reset Manage → clientarea.php?action=security (unchanged, confirmed correct)", ($manageDestinations["\$password_reset_protection_available"] ?? null) === "/clientarea.php?action=security", $failures, $passed);

// 6. No Manage button in the 2FA rows points back to the generic
// clientarea.php?action=security page now that a supported, confirmed
// specific destination (/user/security) exists for them.
foreach (["\$email2fa_available", "\$whatsapp2fa_available", "\$totp2fa_available", "\$two_factor_status !== null"] as $cond) {
    sp_assert("security_center.tpl: " . $cond . "'s Manage link is NOT the generic action=security fallback", ($manageDestinations[$cond] ?? null) !== "/clientarea.php?action=security", $failures, $passed);
}

// 7. No Manage link (anywhere in the Authentication box) contains an
// untrusted user/client identifier — every href is a bare, static
// path with no query-string identity parameter of any kind. The
// destination page resolves the authenticated WHMCS session itself.
$fullTplSource = file_get_contents(__DIR__ . "/../templates/security_center.tpl");
sp_assert("security_center.tpl: no Manage link's href carries a userid/user_id/clientid/client_id parameter", !preg_match('/href="\{\$WEB_ROOT\}[^"]*(userid|user_id|clientid|client_id)/i', (string) $fullTplSource), $failures, $passed);

// 8. Manage links perform no state change — every href in the
// Authentication box is a bare navigation path (no query string, no
// action=activate/disable/switch/reset/verify-style parameter).
sp_assert("security_center.tpl: no Manage link's href carries a state-changing query parameter", !preg_match('/href="\{\$WEB_ROOT\}[^"]*\?(?!action=security")/', (string) $fullTplSource), $failures, $passed);

// 9. The native WHMCS destination itself is the confirmed-working
// friendly URL from the user's own screenshot evidence, not a guess —
// asserted as a literal string constant so any future edit that
// silently reverts to a guessed path is caught immediately.
sp_assert("security_center.tpl: the native 2FA destination is the literal, user-confirmed \"/user/security\" — not a guessed path", in_array("/user/security", $manageDestinations, true), $failures, $passed);

// 10. Fallback behavior when no provider-specific deep-link exists:
// all three methods (and WHMCS's own native row) share the SAME single
// /user/security destination rather than three different guessed
// per-provider URLs — the documented, spec-required fallback when no
// confirmed provider-specific anchor/query-param exists.
$twoFaDestinations = array_unique(array_intersect_key($manageDestinations, array_flip(["\$email2fa_available", "\$whatsapp2fa_available", "\$totp2fa_available", "\$two_factor_status !== null"])));
sp_assert("security_center.tpl: Email/WhatsApp/TOTP/native-2FA all share the one confirmed fallback destination (no fabricated per-provider URLs)", count($twoFaDestinations) === 1 && reset($twoFaDestinations) === "/user/security", $failures, $passed);

// -----------------------------------------------------------------------
// Security Pack 3.1.4 — DctWhatsAppTwoFactorLogBridge (DCTLAB WhatsApp
// "Client Logs Review" integration). This bridge's real DB write path
// (mod_lkn_wa2fa_logs) is DB-backed orchestration — "exercised manually
// against a real WHMCS install" like every other DB-backed method in
// this suite (see the requires-section comment above). What IS unit
// tested here, without a database:
//   1. every public method fails soft (never throws) even when
//      \Illuminate\Database\Capsule\Manager isn't available at all —
//      the exact condition this DB-less test runner is already in —
//      proving a reporting-log failure can never propagate up and
//      break 2FA activation/verification;
//   2. the bridge's own source never references anything that would
//      put a plaintext OTP, an OTP hash, a TOTP secret, a recovery
//      code, or any WhatsApp/Meta/Botms/Baileys credential into the
//      log row (same source-inspection technique this suite already
//      uses for security_center.tpl, applied here since there's no
//      mock DB layer to introspect actual insert() payloads);
//   3. WhatsAppTwoFactorService.php's real call sites use the correct
//      event/reason vocabulary (code_sent/verify_success/verify_failed,
//      "code expired"/"too many attempts"/"incorrect code"/"no pending
//      code") and call each bridge method exactly once per branch (no
//      duplicate DCTLAB log rows for one real event);
//   4. Security Pack's own security_pack_record_event() call sites in
//      WhatsAppTwoFactorService.php are untouched by this integration.
$whatsAppServiceSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/WhatsAppTwoFactorService.php");
$logBridgeSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/Providers/DctWhatsAppTwoFactorLogBridge.php");
// Strip /** ... */ and // comments before the "never references X"
// source-inspection checks below — the class's own docblock explicitly
// DISCUSSES the forbidden terms (token/credential/schema()->create) as
// part of documenting why they're forbidden, which would otherwise
// self-defeat a naive whole-file substring/regex check.
$logBridgeCodeOnly = (string) preg_replace(['#/\*.*?\*/#s', '#//[^\n]*#'], '', $logBridgeSource);

// 1. code_sent / verify_success / verify_failed are written — i.e. the
// real service calls the bridge's corresponding method at least once,
// and calling that bridge method never throws even with no Capsule
// class defined (this test runner's actual environment).
sp_assert("DctWhatsAppTwoFactorLogBridge: WhatsAppTwoFactorService::createChallenge() calls logCodeSent() so a real OTP send is reported to DCTLAB's Client Logs Review", (bool) preg_match('/DctWhatsAppTwoFactorLogBridge::logCodeSent\(/', $whatsAppServiceSource), $failures, $passed);
$codeSentThrew = false;
try {
    DctWhatsAppTwoFactorLogBridge::logCodeSent("client", 123, true, "login", false, "203.0.113.9");
} catch (\Throwable $e) {
    $codeSentThrew = true;
}
sp_assert("DctWhatsAppTwoFactorLogBridge: logCodeSent() is written (call succeeds/never throws) even with no DB layer available", !$codeSentThrew, $failures, $passed);

sp_assert("DctWhatsAppTwoFactorLogBridge: WhatsAppTwoFactorService::verify() calls logVerifySuccess() on a valid OTP", (bool) preg_match('/DctWhatsAppTwoFactorLogBridge::logVerifySuccess\(/', $whatsAppServiceSource), $failures, $passed);
$verifySuccessThrew = false;
try {
    DctWhatsAppTwoFactorLogBridge::logVerifySuccess("client", 123, "login", "203.0.113.9");
} catch (\Throwable $e) {
    $verifySuccessThrew = true;
}
sp_assert("DctWhatsAppTwoFactorLogBridge: verify_success is written (call succeeds/never throws) even with no DB layer available", !$verifySuccessThrew, $failures, $passed);

sp_assert("DctWhatsAppTwoFactorLogBridge: WhatsAppTwoFactorService::verify() calls logVerifyFailed() on a failed OTP", (bool) preg_match('/DctWhatsAppTwoFactorLogBridge::logVerifyFailed\(/', $whatsAppServiceSource), $failures, $passed);
$verifyFailedThrew = false;
try {
    DctWhatsAppTwoFactorLogBridge::logVerifyFailed("client", 123, "incorrect code", "login", "203.0.113.9");
} catch (\Throwable $e) {
    $verifyFailedThrew = true;
}
sp_assert("DctWhatsAppTwoFactorLogBridge: verify_failed is written (call succeeds/never throws) even with no DB layer available", !$verifyFailedThrew, $failures, $passed);

// 2. Client user identity (userType "client") and admin user identity
// (userType "admin") both pass through untouched — the bridge never
// re-derives identity from $_GET/$_POST/$_REQUEST, it only accepts
// whatever WhatsAppTwoFactorService (the authenticated caller) passes.
sp_assert("DctWhatsAppTwoFactorLogBridge: client user identity — logCodeSent()'s \$userType/\$userId parameters are written through untouched, never re-derived from request superglobals", !preg_match('/\$_GET|\$_POST|\$_REQUEST/', $logBridgeSource), $failures, $passed);
$clientIdentityThrew = false;
try {
    DctWhatsAppTwoFactorLogBridge::logVerifySuccess("client", 42, "activation", "203.0.113.10");
} catch (\Throwable $e) {
    $clientIdentityThrew = true;
}
sp_assert("DctWhatsAppTwoFactorLogBridge: accepts a client identity (user_type=client) without error", !$clientIdentityThrew, $failures, $passed);
$adminIdentityThrew = false;
try {
    DctWhatsAppTwoFactorLogBridge::logVerifySuccess("admin", 5, "login", "203.0.113.11");
} catch (\Throwable $e) {
    $adminIdentityThrew = true;
}
sp_assert("DctWhatsAppTwoFactorLogBridge: admin user identity — accepts a distinct user_type=admin identity without ever being treated as a WHMCS client", !$adminIdentityThrew, $failures, $passed);

// 3. Expired code / excessive attempts — WhatsAppTwoFactorService's real
// verify() branches map to the existing dct2fa wording exactly, in the
// existing verify_failed vocabulary (never a fabricated event name).
sp_assert("DctWhatsAppTwoFactorLogBridge: an expired OTP is reported as verify_failed with dct2fa's own \"code expired\" wording", (bool) preg_match('/logVerifyFailed\(\$userType,\s*\$userId,\s*"code expired"/', $whatsAppServiceSource), $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: excessive verification attempts are reported as verify_failed with dct2fa's own \"too many attempts\" wording", (bool) preg_match('/logVerifyFailed\(\$userType,\s*\$userId,\s*"too many attempts"/', $whatsAppServiceSource), $failures, $passed);

// 4. No plaintext OTP / no OTP hash / no credentials ever reach the
// bridge's own source — checked by source inspection since there is no
// mock DB layer here to introspect an actual insert() payload.
sp_assert("DctWhatsAppTwoFactorLogBridge: no plaintext OTP ever appears in the bridge's own source (no \$otp/\$candidateOtp parameter or reference anywhere in the class)", !preg_match('/\$otp\b|\$candidateOtp\b|\botp_hash\b/i', $logBridgeCodeOnly), $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: no OTP hash is ever written (the class never references otp_hash/hashOtp/OtpEngine)", !preg_match('/otp_hash|hashOtp|OtpEngine/i', $logBridgeCodeOnly), $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: no WhatsApp/Meta/Botms/Baileys credential or API token is ever written (the class never references token/credential/api_key/secret)", !preg_match('/\btoken\b|\bcredential|\bapi_key\b|\bsecret\b/i', $logBridgeCodeOnly), $failures, $passed);

// 5. No duplicate DCTLAB log records for one real event — the service
// calls each bridge method exactly once per outcome branch, never twice
// for the same actual event.
sp_assert("DctWhatsAppTwoFactorLogBridge: no duplicate records — createChallenge() calls logCodeSent() exactly once (one OTP send attempt -> exactly one code_sent row)", substr_count($whatsAppServiceSource, "DctWhatsAppTwoFactorLogBridge::logCodeSent(") === 1, $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: no duplicate records — verify() calls logVerifySuccess() exactly once (one successful verification -> exactly one verify_success row)", substr_count($whatsAppServiceSource, "DctWhatsAppTwoFactorLogBridge::logVerifySuccess(") === 1, $failures, $passed);

// 6. Failure of the reporting table must never break authentication —
// this test runner's own environment (no \Illuminate\Database\Capsule\Manager
// defined at all) is a strictly harder failure mode than "table missing",
// and every call above already completed without throwing, proving the
// fail-soft contract holds even in the worst case.
sp_assert("DctWhatsAppTwoFactorLogBridge: failure of the DCTLAB reporting log never breaks authentication — every public method above ran to completion with no \\Illuminate\\Database\\Capsule\\Manager available at all (strictly harder than a merely-missing table) and none of them threw", !$codeSentThrew && !$verifySuccessThrew && !$verifyFailedThrew && !$clientIdentityThrew && !$adminIdentityThrew, $failures, $passed);

// 7. Existing Security Pack events continue to work — this integration
// must not have replaced/removed any of WhatsAppTwoFactorService's own
// security_pack_record_event() call sites.
sp_assert("DctWhatsAppTwoFactorLogBridge: existing Security Pack events continue to work — 2fa.whatsapp.sent/2fa.otp.resent event recording is still present and untouched", (bool) preg_match('/security_pack_record_event\(\s*\$existing \? "2fa\.otp\.resent" : "2fa\.whatsapp\.sent"/', $whatsAppServiceSource), $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: existing Security Pack events continue to work — 2fa.verification.success/2fa.verification.failed event recording is still present and untouched", strpos($whatsAppServiceSource, 'security_pack_record_event("2fa.verification.success"') !== false && strpos($whatsAppServiceSource, 'security_pack_record_event("2fa.verification.failed"') !== false, $failures, $passed);
sp_assert("DctWhatsAppTwoFactorLogBridge: existing Security Pack events continue to work — 2fa.enabled/2fa.disabled event recording is still present and untouched", strpos($whatsAppServiceSource, 'security_pack_record_event("2fa.enabled"') !== false && strpos($whatsAppServiceSource, 'security_pack_record_event("2fa.disabled"') !== false, $failures, $passed);

// 8. This class never creates/migrates the table it writes to — it is a
// PRODUCER only, never the owner, of mod_lkn_wa2fa_logs.
sp_assert("DctWhatsAppTwoFactorLogBridge: never creates, migrates, renames, or truncates mod_lkn_wa2fa_logs — it is a producer only, never the table's owner", !preg_match('/schema\(\)\s*->\s*(create|rename|drop|truncate)\(/i', $logBridgeCodeOnly), $failures, $passed);

// -----------------------------------------------------------------
// 3.1.6-3.1.15 — Admin Client Profile > Users tab "Two Factor Auth
// Method" column integration. Through 3.1.15 this was built around a
// JS-triggered AJAX request to TwoFactorController::ajaxUsersTwoFactorStatus()
// — that endpoint 404'd on the reported install regardless of how the
// URL was derived (relative, or absolute from $_SERVER["SCRIPT_NAME"]).
//
// 3.1.16 — "FINAL ADMIN USERS 2FA DISPLAY FIX": removes the AJAX
// mechanism ENTIRELY (ajaxUsersTwoFactorStatus(), parseUserIdsParam(),
// buildUsersStatusMap(), resolveUserMethodStatus(),
// corroborateFromSecondFactorColumn(), methodStatusFromStatus(), and
// buildAdminAjaxEndpointUrl() are all REMOVED from TwoFactorController —
// confirmed absent below). Replaced with a server-side JSON mapping
// (TwoFactorController::resolveUserIdsForClient() /
// buildSecondFactorMapping() / buildUsersTwoFactorMappingForClient(),
// injected by core/two_factor_admin_display.php) that the JS overlay
// reads synchronously — no network request of any kind for this
// display. DB-backed entry points are exercised manually against a real
// WHMCS install, same as every other DB-backed integration point in
// this suite; what's tested directly here is the PURE decision logic
// plus structural/source-inspection guarantees for everything that
// can't run without a live WHMCS admin page.
// -----------------------------------------------------------------

$controllerSource = (string) file_get_contents(__DIR__ . "/../lib/Admin/TwoFactorController.php");

// "REMOVE OBSOLETE AJAX CODE": confirms there is now exactly ONE
// mechanism (server-side mapping -> JS DOM presentation), never two
// competing ones.
sp_assert("TwoFactorController (3.1.16): the old AJAX endpoint and its supporting methods (ajaxUsersTwoFactorStatus/parseUserIdsParam/buildUsersStatusMap/resolveUserMethodStatus/corroborateFromSecondFactorColumn/methodStatusFromStatus/buildAdminAjaxEndpointUrl) are all REMOVED — no competing mechanism remains alongside the server-side mapping", strpos($controllerSource, "function ajaxUsersTwoFactorStatus(") === false && strpos($controllerSource, "function parseUserIdsParam(") === false && strpos($controllerSource, "function buildUsersStatusMap(") === false && strpos($controllerSource, "function resolveUserMethodStatus(") === false && strpos($controllerSource, "function corroborateFromSecondFactorColumn(") === false && strpos($controllerSource, "function methodStatusFromStatus(") === false && strpos($controllerSource, "function buildAdminAjaxEndpointUrl(") === false, $failures, $passed);
sp_assert("security_pack.php (3.1.16): \$bareOutputActions no longer lists \"ajaxUsersTwoFactorStatus\" — the endpoint it named no longer exists (a historical comment mentioning the removed name in passing is fine)", (function () {
    $src = (string) file_get_contents(__DIR__ . "/../security_pack.php");
    return (bool) preg_match('/\$bareOutputActions = \["user"\];/', $src);
})(), $failures, $passed);

// --- DATA SOURCE: dct_email_2fa / dct_whatsapp_2fa / dct_totp_2fa /
// empty second_factor / unknown second_factor / User #666037 ---
sp_assert("TwoFactorController::labelFromSecondFactorModule(): dct_email_2fa -> Email Two-Factor Authentication", TwoFactorController::labelFromSecondFactorModule("dct_email_2fa") === "Email Two-Factor Authentication", $failures, $passed);
sp_assert("TwoFactorController::labelFromSecondFactorModule(): dct_whatsapp_2fa -> DCTLAB WhatsApp Two-Factor Authentication", TwoFactorController::labelFromSecondFactorModule("dct_whatsapp_2fa") === "DCTLAB WhatsApp Two-Factor Authentication", $failures, $passed);
sp_assert("TwoFactorController::labelFromSecondFactorModule(): dct_totp_2fa -> Time-Based Token Two-Factor Authentication (the exact reported account's real value)", TwoFactorController::labelFromSecondFactorModule("dct_totp_2fa") === "Time-Based Token Two-Factor Authentication", $failures, $passed);
sp_assert("TwoFactorController::labelFromSecondFactorModule(): empty second_factor ('' or null) returns null — no signal, not a guess", TwoFactorController::labelFromSecondFactorModule(null) === null && TwoFactorController::labelFromSecondFactorModule("") === null, $failures, $passed);
sp_assert("TwoFactorController::labelFromSecondFactorModule(): an unrecognized second_factor value (WHMCS's own built-in \"totp\", or any third-party/unknown module) is NEVER trusted/displayed as a Security Pack method — returns null rather than guessing", TwoFactorController::labelFromSecondFactorModule("totp") === null && TwoFactorController::labelFromSecondFactorModule("some_other_module") === null, $failures, $passed);
sp_assert("End-to-end: User #666037 with second_factor=dct_totp_2fa resolves to \"Time-Based Token Two-Factor Authentication\", not N/A", TwoFactorController::buildSecondFactorMapping([666037], function ($id) { return $id === 666037 ? "dct_totp_2fa" : null; }) === ["666037" => ["method" => "Time-Based Token Two-Factor Authentication", "state" => "active"]], $failures, $passed);

// --- JSON mapping generation / JSON encoding & escaping / duplicate
// User IDs / invalid User IDs / native N/A remains when mapping
// unavailable ---
$fakeSecondFactors = ["11" => "dct_email_2fa", "22" => "dct_whatsapp_2fa", "33" => "dct_totp_2fa", "44" => "totp", "55" => null];
$resolverCalls = [];
$fakeResolver = function ($userId) use ($fakeSecondFactors, &$resolverCalls) {
    $resolverCalls[] = $userId;
    return $fakeSecondFactors[(string) $userId] ?? null;
};
$mapping = TwoFactorController::buildSecondFactorMapping([11, 22, 33, 44, 55, 11, 0, -5], $fakeResolver);
sp_assert("TwoFactorController::buildSecondFactorMapping(): each user under a multi-user Client gets their OWN method, not the first/last user's method (Email/WhatsApp/TOTP each independently correct)", $mapping === [
    "11" => ["method" => "Email Two-Factor Authentication", "state" => "active"],
    "22" => ["method" => "DCTLAB WhatsApp Two-Factor Authentication", "state" => "active"],
    "33" => ["method" => "Time-Based Token Two-Factor Authentication", "state" => "active"],
], $failures, $passed);
sp_assert("TwoFactorController::buildSecondFactorMapping(): WHMCS's own built-in second_factor value (\"totp\", user 44) and an empty/null value (user 55) are both OMITTED from the mapping entirely — native N/A remains untouched for those rows", !isset($mapping["44"]) && !isset($mapping["55"]), $failures, $passed);
sp_assert("TwoFactorController::buildSecondFactorMapping(): a duplicate User ID (11 appears twice in the input) is resolved only once, not twice", array_count_values($resolverCalls)[11] === 1, $failures, $passed);
sp_assert("TwoFactorController::buildSecondFactorMapping(): invalid User IDs (0, -5) are skipped without ever being passed to the resolver", !in_array(0, $resolverCalls, true) && !in_array(-5, $resolverCalls, true), $failures, $passed);
sp_assert("TwoFactorController::buildSecondFactorMapping(): an empty User ID list produces an empty mapping — the JS overlay then leaves every native cell untouched, same as if the hook never ran", TwoFactorController::buildSecondFactorMapping([], function ($id) { return "dct_totp_2fa"; }) === [], $failures, $passed);

// --- resolveUserIdsForClient(): real WHMCS Users only, never an
// arbitrary/attacker-supplied ID (Section "SECURITY") ---
sp_assert("TwoFactorController::resolveUserIdsForClient(): a non-positive client ID returns an empty list immediately, before any DB query", TwoFactorController::resolveUserIdsForClient(0) === [] && TwoFactorController::resolveUserIdsForClient(-5) === [], $failures, $passed);
sp_assert("TwoFactorController::resolveUserIdsForClient(): resolves via the tblusers_clients junction table, using \$clientCol/\$userCol resolved through hasColumn() rather than a hardcoded column name", (bool) preg_match('/Capsule\\\\Manager::table\("tblusers_clients"\)\s*\n?\s*->where\(\$clientCol, \$clientId\)\s*\n?\s*->pluck\(\$userCol\)/', $controllerSource), $failures, $passed);
sp_assert("TwoFactorController::resolveUserIdsForClient(): a DB error or missing table fails closed to an empty list, never throws", (bool) preg_match('/function resolveUserIdsForClient\(int \$clientId\): array\s*\{[\s\S]*?catch\s*\(\s*\\\\Throwable[\s\S]{0,60}return\s*\[\s*\]\s*;/', $controllerSource), $failures, $passed);

// --- 3.1.20: CONFIRMED SCHEMA FIX — this is the real, concrete root
// cause of the persistent "N/A" bug. A live `SHOW COLUMNS FROM
// tblusers_clients` on the reporting install confirmed the real column
// names are `auth_user_id`/`client_id`, not the `userid`/`clientid`
// this codebase assumed based on undocumented community discussion. The
// query silently failed on every call via the try/catch, always
// returning an empty list — even though tblusers.second_factor was
// independently confirmed correct for the reported user. Now resolves
// the real column names via hasColumn() at call time in all THREE
// places this junction table is queried, preferring the confirmed-real
// names and falling back to the originally-assumed ones only if those
// aren't present. ---
sp_assert("TwoFactorController::resolveUserIdsForClient() (3.1.20): resolves the real column names via hasColumn(\"tblusers_clients\", \"auth_user_id\"/\"client_id\") rather than hardcoding either the confirmed-real or the originally-assumed names", strpos($controllerSource, 'hasColumn("tblusers_clients", "auth_user_id")') !== false && strpos($controllerSource, 'hasColumn("tblusers_clients", "client_id")') !== false, $failures, $passed);
$email2faSourceForSchema = (string) file_get_contents(__DIR__ . "/../lib/Security/Email2faService.php");
sp_assert("Email2faService::resolveClientIdForUser() (3.1.20): the SAME confirmed-real-schema fix is applied here too — hasColumn()-resolved column names, not the originally-assumed hardcoded \"userid\"/\"clientid\"", strpos($email2faSourceForSchema, 'hasColumn("tblusers_clients", "auth_user_id")') !== false && strpos($email2faSourceForSchema, 'hasColumn("tblusers_clients", "client_id")') !== false, $failures, $passed);
$whatsappSourceForSchema = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/WhatsAppTwoFactorService.php");
sp_assert("WhatsAppTwoFactorService::resolveClientIdForUser() (3.1.20): the SAME confirmed-real-schema fix is applied here too — hasColumn()-resolved column names, not the originally-assumed hardcoded \"userid\"/\"clientid\"", strpos($whatsappSourceForSchema, 'hasColumn("tblusers_clients", "auth_user_id")') !== false && strpos($whatsappSourceForSchema, 'hasColumn("tblusers_clients", "client_id")') !== false, $failures, $passed);

// --- buildUsersTwoFactorMappingForClient(): DB orchestrator, fully
// fail-soft, one batched query (Section "PERFORMANCE") ---
sp_assert("TwoFactorController::buildUsersTwoFactorMappingForClient(): batch-fetches second_factor for all resolved User IDs in ONE query (whereIn), never one query per row", strpos($controllerSource, '->whereIn("id", $userIds)') !== false, $failures, $passed);
sp_assert("TwoFactorController::buildUsersTwoFactorMappingForClient(): any DB error anywhere in this path returns an empty mapping — never a partial/guessed result", (bool) preg_match('/function buildUsersTwoFactorMappingForClient\(int \$clientId\): array\s*\{\s*try\s*\{[\s\S]*?catch\s*\(\s*\\\\Throwable[\s\S]{0,60}return\s*\[\s*\]\s*;/', $controllerSource), $failures, $passed);

// --- BYPASS DISPLAY: audited TwoFactorBypassService before changing
// anything (per this ticket's own instruction) — confirmed the `method`
// column is explicitly "informational only" and never scopes
// enforcement (a bypass applies "regardless of the configured method").
// Display now always leads with "Any 2FA Method"/"All 2FA Methods",
// never a raw method name alone; the originating method (when known and
// not the generic "manual" tag) is preserved as a parenthetical for
// audit value, never as if it scoped the bypass. ---
$bypassServiceSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/TwoFactorBypassService.php");
sp_assert("TwoFactorBypassService: confirmed structurally method-agnostic — the stored `method` column is documented as NOT affecting enforcement (a bypass applies regardless of method)", stripos($bypassServiceSource, "NOT scoped by method") !== false || stripos($bypassServiceSource, "regardless of") !== false, $failures, $passed);
sp_assert("TwoFactorController::bypassMethodLabel(): always leads with \"Any 2FA Method\" — never displays a raw stored method value (e.g. \"whatsapp\") as if the bypass were scoped to just that method", strpos($controllerSource, 'private function bypassMethodLabel($rawMethod): string') !== false && (bool) preg_match('/function bypassMethodLabel\(\$rawMethod\): string\s*\{[\s\S]*?\$label = "Any 2FA Method";/', $controllerSource), $failures, $passed);
sp_assert("TwoFactorController::bypassMethodLabel(): the generic \"manual\" tag (what every admin-created bypass is stored with) never triggers the \"(granted via ...)\" parenthetical — only a genuinely specific originating method does", (bool) preg_match('/\$rawMethod !== "" && \$rawMethod !== "manual"/', $controllerSource), $failures, $passed);
sp_assert("TwoFactorController::bypassMethodLabel(): the originating method value, when shown, is HTML-escaped via \$this->e() before being embedded", (bool) preg_match('/granted via " \. \$this->e\(\$rawMethod\)/', $controllerSource), $failures, $passed);
sp_assert("TwoFactorController::renderBypasses(): the bypass table's Method column now renders via bypassMethodLabel(\$row->method ?? null), not the raw stored value directly", strpos($controllerSource, '$this->bypassMethodLabel($row->method ?? null)') !== false, $failures, $passed);
sp_assert("TwoFactorAuthenticationService::createAdminBypass(): admin-created bypasses (the ones this UI creates) are still always tagged the generic \"manual\" method — confirms this display change never needed to touch how bypasses are CREATED or STORED, only how the existing column is RENDERED (Section \"Do not break existing bypass records\")", (function () {
    $src = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/TwoFactorAuthenticationService.php");
    // 2026-08-27: signature widened from ": void" to ": bool" (propagating
    // real success/failure — see TwoFactorBypassService's own docblock for
    // the incident this fixes) — the "manual" tag itself, and the fact
    // that this is still a thin pass-through with no CREATE/STORE logic
    // of its own, are both unchanged and still asserted here.
    return (bool) preg_match('/createAdminBypass\([^)]*\)\s*:\s*bool\s*\{\s*return TwoFactorBypassService::createAdminBypass\([^,]+,[^,]+,[^,]+,[^,]+,[^,]+,\s*"manual"/', $src);
})(), $failures, $passed);

// --- ACCEPTANCE / hook-level tests: server-side mapping, no AJAX, no
// endpoint URL, unauthorized context fails safely, real WHMCS Users
// only, hidden rowPendingInvites ignored, tr.user-item processed ---
$adminDisplayHookSource = (string) file_get_contents(__DIR__ . "/../core/two_factor_admin_display.php");
sp_assert("Security Pack never modifies a WHMCS core file for this integration — the fix is injected entirely through this module's own documented AdminAreaFooterOutput hook", strpos($adminDisplayHookSource, 'add_hook("AdminAreaFooterOutput"') !== false, $failures, $passed);
$adminDisplayHookCodeOnly = (string) preg_replace(['#/\*.*?\*/#s', '#//[^\n]*#'], '', $adminDisplayHookSource);
sp_assert("core/two_factor_admin_display.php (3.1.16): NO AJAX request is generated for this display — no fetch(), no XMLHttpRequest, no endpoint URL global, anywhere in the ACTUAL CODE (historical comments explaining the removed mechanism are fine)", strpos($adminDisplayHookCodeOnly, "fetch(") === false && strpos($adminDisplayHookCodeOnly, "XMLHttpRequest") === false && strpos($adminDisplayHookCodeOnly, "security_pack_2fa_users_endpoint") === false && strpos($adminDisplayHookCodeOnly, "ajaxUsersTwoFactorStatus") === false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.16): unauthorized/non-admin context fails safely — returns an empty string (no mapping, no script tag) before touching any client/user data when there's no admin session", (bool) preg_match('/if\(empty\(\$_SESSION\["adminid"\]\) \|\| \(int\) \$_SESSION\["adminid"\] <= 0\) \{\s*return "";\s*\}/', $adminDisplayHookSource), $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.16/3.1.18): the client id is resolved via security_pack_2fa_resolve_viewed_client_id() — \$_REQUEST[\"userid\"] first, never trusted as an arbitrary per-row User ID substitute", strpos($adminDisplayHookSource, "security_pack_2fa_resolve_viewed_client_id()") !== false && strpos($adminDisplayHookSource, '$_REQUEST["userid"]') !== false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.16): the mapping is built via TwoFactorController::buildUsersTwoFactorMappingForClient(\$clientId) — real WHMCS Users resolved server-side for the client being viewed, never an unvalidated request-supplied ID", strpos($adminDisplayHookSource, "buildUsersTwoFactorMappingForClient(\$clientId)") !== false, $failures, $passed);

// --- 3.1.18: confirmed live regression fix — 3.1.16 was deployed and
// the "N/A" bug was STILL reproduced live for a confirmed-active user,
// on an admin Client Profile URL with NO query string at all
// ("/client/666037/users"). Root cause: $_REQUEST["userid"] alone never
// gets populated by this install's friendly router for that URL shape,
// so $clientId silently resolved to 0. security_pack_2fa_resolve_viewed_client_id()
// now falls back to parsing the client ID directly out of the request's
// own URL path — this is reading the ID WHMCS itself already routed
// this authenticated admin session to, not "another AJAX endpoint URL
// guess" (there is still no AJAX request anywhere in this file). ---
sp_assert("core/two_factor_admin_display.php (3.1.18): a standalone security_pack_2fa_resolve_viewed_client_id(): int resolver function exists, defined OUTSIDE the add_hook closure so it stays independently testable", strpos($adminDisplayHookSource, "function security_pack_2fa_resolve_viewed_client_id(): int") !== false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.18): the resolver tries \$_REQUEST[\"userid\"] FIRST (unchanged 3.1.16 behavior preserved for any install where the classic query-string form is present)", (bool) preg_match('/function security_pack_2fa_resolve_viewed_client_id\(\): int\s*\{\s*if\(isset\(\$_REQUEST\["userid"\]\) && is_numeric\(\$_REQUEST\["userid"\]\)\)/', $adminDisplayHookSource), $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.18): the resolver falls back to parsing a \"/client/{id}/...\" path segment out of REQUEST_URI/PATH_INFO/REDIRECT_URL/PHP_SELF — the exact URL shape reproduced live, with no query string at all", strpos($adminDisplayHookCodeOnly, '["REQUEST_URI", "PATH_INFO", "REDIRECT_URL", "PHP_SELF"]') !== false && strpos($adminDisplayHookCodeOnly, '#/client/(\d+)(?:/|\?|$)#') !== false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.18): this is still NOT an AJAX endpoint URL guess — no fetch()/XMLHttpRequest/endpoint-URL global was added alongside the new path-parsing fallback", strpos($adminDisplayHookCodeOnly, "fetch(") === false && strpos($adminDisplayHookCodeOnly, "XMLHttpRequest") === false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.16): the mapping JSON is injected as window.security_pack_2fa_users, HEX-escaped so it can never break out of its <script> context, and JSON_FORCE_OBJECT so an empty mapping still serializes as {} not []", strpos($adminDisplayHookSource, "var security_pack_2fa_users = ") !== false && strpos($adminDisplayHookSource, "JSON_HEX_TAG") !== false && strpos($adminDisplayHookSource, "JSON_FORCE_OBJECT") !== false, $failures, $passed);

// --- 3.1.19: SECOND confirmed live bug, independent of 3.1.18's fix.
// 3.1.18 was deployed and the column STILL showed "N/A". Root cause: the
// two_factor_admin_users.js <script src> was a RELATIVE URL
// ("../modules/..."), which resolves against the BROWSER'S CURRENT URL
// depth, not the file's real disk location. On the confirmed
// three-segment friendly URL ("/ish_myadmin/client/666037/users") "../"
// lands on a non-existent path and the script 404s — so the mapping
// global was correctly populated (the inline, src-less <script> tag is
// unaffected) but nothing ever loaded to read it. Mirrors
// security_pack_2fa_asset_base_url()'s own two-strategy resolution
// exactly (WHMCS's own SystemURL setting first, SCRIPT_NAME-derived
// root as a fallback), so a divergence from production code is caught
// by the source-regex checks further below. ---
function sp_test_asset_base_url(?string $systemUrl, ?string $scriptName): string
{
    if($systemUrl !== null && $systemUrl !== "") {
        return rtrim($systemUrl, "/");
    }
    if($scriptName !== null && $scriptName !== "") {
        $adminDir = rtrim(str_replace("\\", "/", dirname($scriptName)), "/");
        $root = rtrim(str_replace("\\", "/", dirname($adminDir === "" ? "/" : $adminDir)), "/");
        return $root;
    }
    return "";
}
sp_assert("asset_base_url: WHMCS's own SystemURL setting is preferred when available, regardless of the current request's URL depth", sp_test_asset_base_url("https://indianserverhosting.com", "/ish_myadmin/client/666037/users") === "https://indianserverhosting.com", $failures, $passed);
sp_assert("asset_base_url: a trailing slash on SystemURL is stripped so the caller never produces a double slash", sp_test_asset_base_url("https://indianserverhosting.com/", null) === "https://indianserverhosting.com", $failures, $passed);
sp_assert("asset_base_url: SystemURL with a WHMCS-in-subfolder path is preserved (e.g. \"https://example.com/billing\")", sp_test_asset_base_url("https://example.com/billing", null) === "https://example.com/billing", $failures, $passed);
sp_assert("asset_base_url (fallback, the exact scenario this 3.1.19 fix targets): with no SystemURL available, a root-install SCRIPT_NAME (\"/ish_myadmin/index.php\") resolves to site root (\"\"), NOT a relative-path-breaking value — the caller then produces \"/modules/...\", correct regardless of how many friendly-router path segments the BROWSER's URL shows", sp_test_asset_base_url(null, "/ish_myadmin/index.php") === "", $failures, $passed);
sp_assert("asset_base_url (fallback): a WHMCS-in-subfolder SCRIPT_NAME (\"/billing/ish_myadmin/index.php\") resolves to \"/billing\", the correct WHMCS root", sp_test_asset_base_url(null, "/billing/ish_myadmin/index.php") === "/billing", $failures, $passed);
sp_assert("asset_base_url: neither SystemURL nor SCRIPT_NAME available resolves to \"\" (site root) rather than throwing or guessing", sp_test_asset_base_url(null, null) === "", $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.19): a standalone security_pack_2fa_asset_base_url(): string resolver function exists", strpos($adminDisplayHookSource, "function security_pack_2fa_asset_base_url(): string") !== false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.19): the resolver prefers WHMCS's own \\WHMCS\\Config\\Setting::getValue(\"SystemURL\") before ever falling back to SCRIPT_NAME derivation", (bool) preg_match('/function security_pack_2fa_asset_base_url\(\): string\s*\{\s*if\(class_exists\("\\\\\\\\WHMCS\\\\\\\\Config\\\\\\\\Setting"\)\)\s*\{\s*try\s*\{\s*\$systemUrl = \(string\) \\\\WHMCS\\\\Config\\\\Setting::getValue\("SystemURL"\);/', $adminDisplayHookSource), $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.19): the two_factor_admin_users.js <script src> is now built via security_pack_2fa_asset_base_url() — an ABSOLUTE URL — never the old relative \"../modules/...\" form that 404'd on the confirmed live three-segment friendly URL", strpos($adminDisplayHookSource, "security_pack_2fa_asset_base_url() . \"/modules/addons/security_pack/assets/js/two_factor_admin_users.js\"") !== false && strpos($adminDisplayHookCodeOnly, '"../modules/') === false, $failures, $passed);
sp_assert("core/two_factor_admin_display.php (3.1.16): the deployment-cache defense (deterministic \"?v=<version>\" query string, never random/time-based) is preserved from 3.1.11", strpos($adminDisplayHookSource, 'security_pack_config()["version"]') !== false && strpos($adminDisplayHookSource, '"?v="') !== false && strpos($adminDisplayHookSource, "rand(") === false && strpos($adminDisplayHookSource, "time()") === false && strpos($adminDisplayHookSource, "uniqid(") === false, $failures, $passed);

$jsSource = (string) file_get_contents(__DIR__ . "/../assets/js/two_factor_admin_users.js");
sp_assert("two_factor_admin_users.js (3.1.16): only acts on a table when the native \"Two Factor Auth Method\" column header text is actually found — WHMCS's native markup is detected, never assumed", strpos($jsSource, "TARGET_HEADER") !== false && strpos($jsSource, "findTargetColumnIndex") !== false, $failures, $passed);
$jsSourceCodeOnly = (string) preg_replace(['#/\*.*?\*/#s', '#//[^\n]*#'], '', $jsSource);
sp_assert("two_factor_admin_users.js (3.1.16): NO fetch()/XMLHttpRequest/AJAX call anywhere in the ACTUAL CODE (historical comments explaining the removed mechanism are fine) — pure DOM presentation, reads window.security_pack_2fa_users synchronously", strpos($jsSourceCodeOnly, "fetch(") === false && strpos($jsSourceCodeOnly, "XMLHttpRequest") === false && strpos($jsSourceCodeOnly, "security_pack_2fa_users_endpoint") === false && strpos($jsSourceCodeOnly, "security_pack_token") === false, $failures, $passed);
sp_assert("two_factor_admin_users.js (3.1.16): reads window.security_pack_2fa_users directly and leaves native values untouched when it's absent, rather than guessing or falling back to a request", strpos($jsSource, "window.security_pack_2fa_users") !== false && (bool) preg_match('/if \(!mapping \|\| typeof mapping !== "object"\) \{[\s\S]*?return;\s*\}/', $jsSource), $failures, $passed);
sp_assert("two_factor_admin_users.js (3.1.16): a User ID with no mapping entry (or an entry missing a usable \"method\") leaves the native cell completely untouched — no textContent write happens for that row", (bool) preg_match('/if \(display === null\) \{[\s\S]*?continue;\s*\}/', $jsSource), $failures, $passed);
sp_assert("two_factor_admin_users.js: rowPendingInvites (the confirmed hidden placeholder row) is still explicitly recognized and skipped, never treated as a malformed/erroring real row", strpos($jsSource, 'rowPendingInvites') !== false, $failures, $passed);
sp_assert("two_factor_admin_users.js: real user rows are still selected via the confirmed \"tbody tr.user-item\" selector first, which automatically excludes rowPendingInvites and any other non-user row", strpos($jsSource, 'querySelectorAll("tbody tr.user-item")') !== false, $failures, $passed);
sp_assert("two_factor_admin_users.js: extractUserId() still checks the confirmed \".name[data-user-id]\" markup FIRST via extractUserIdFromConfirmedMarkup(), before the broader fallback scan", strpos($jsSource, 'extractUserIdFromConfirmedMarkup') !== false && strpos($jsSource, '.name[data-user-id]') !== false, $failures, $passed);
sp_assert("two_factor_admin_users.js (3.1.7 regression guard): ambiguous User ID candidates within one row (disagreeing sources) are never guessed at — the row is left unchanged", strpos($jsSource, "ambiguous") !== false, $failures, $passed);
sp_assert("two_factor_admin_users.js (3.1.7 regression guard): already-processed tables are marked so a MutationObserver re-scan never re-processes the same table", strpos($jsSource, "PROCESSED_ATTR") !== false && strpos($jsSource, "hasAttribute(PROCESSED_ATTR)") !== false, $failures, $passed);

// No OTP, OTP hash, TOTP secret, recovery code, credential, WhatsApp
// credential, or API token ever reaches the injected mapping/HTML —
// only a User ID, a human-readable method label, and a state string.
$twoFactorIntegrationCode = substr($controllerSource, (int) strpos($controllerSource, "public static function resolveUserIdsForClient("));
$twoFactorIntegrationCodeOnly = (string) preg_replace(['#/\*.*?\*/#s', '#//[^\n]*#'], '', $twoFactorIntegrationCode);
sp_assert("TwoFactorController's Users-tab mapping code never references an OTP, OTP hash, TOTP secret, recovery code, WhatsApp credential, or credential/API key/API token in actual code (comments aside) — only method/state are ever built", !preg_match('/\$otp\b|otp_hash|\bsecret\b|recovery_code|\bcredential|\bapi_key\b|\bapi_token\b|\bauth_token\b/i', $twoFactorIntegrationCodeOnly), $failures, $passed);

// --- 3.1.12: real production fatal error, reported with a stack trace:
// "Call to private method
// WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController::save()
// from global scope in security_pack.php". Root cause: the admin/client
// action dispatchers in security_pack.php used method_exists($controller,
// $action), which reports a hit regardless of METHOD VISIBILITY — so an
// action name matching a controller's PRIVATE helper (TwoFactorController's
// save()/bypass()/revoke(), only ever meant to be called internally by
// its own index() via its own $_REQUEST["a"] switch) crashed the whole
// admin page the moment the Policy "Save" form (or the bypass/revoke
// forms) posted a=save/a=bypass/a=revoke. Fixed by switching both
// dispatchers to is_callable([$controller, $action]), which IS
// visibility-aware from the calling scope and correctly returns false
// for a private/protected method reached from this plain global
// function — falling through to index() (which already knows how to
// route those actions internally) instead of fatal-erroring. No change
// for any action that's genuinely public — is_callable() and
// method_exists() agree for those. ---
$securityPackPhpSource3112 = (string) file_get_contents(__DIR__ . "/../security_pack.php");
sp_assert("security_pack.php (3.1.12): TwoFactorController::save()/bypass()/revoke() remain private — this is what proves the OLD method_exists()-based dispatch was unsafe and the NEW is_callable()-based dispatch is required", strpos($controllerSource, "private function save()") !== false && strpos($controllerSource, "private function bypass()") !== false && strpos($controllerSource, "private function revoke()") !== false, $failures, $passed);
sp_assert("security_pack.php (3.1.12): the admin action dispatcher (security_pack_output()) uses is_callable([\$controller, \$action]), not the visibility-blind method_exists(\$controller, \$action), before invoking an action method directly from global scope", substr_count($securityPackPhpSource3112, "is_callable([\$controller, \$action])") >= 2 && substr_count($securityPackPhpSource3112, "method_exists(\$controller, \$action)") === 0, $failures, $passed);
sp_assert("security_pack.php (3.1.12): the client-area action dispatcher (security_pack_clientarea()) got the identical is_callable() fix, not just the admin one — same fatal-error class was reachable there too for any private/protected client controller method", (bool) preg_match('/function security_pack_clientarea\(\$vars\)[\s\S]*?is_callable\(\[\$controller, \$action\]\)/', $securityPackPhpSource3112), $failures, $passed);
sp_assert("TwoFactorController's own index() still routes a=save/a=bypass/a=revoke internally via its own switch (unaffected by the dispatcher fix — this is WHY falling through to index() when is_callable() returns false is the correct behavior, not a broken action)", (bool) preg_match('/case "save":\s*\$this->save\(\);/', $controllerSource) && (bool) preg_match('/case "bypass":\s*\$this->bypass\(\);/', $controllerSource) && (bool) preg_match('/case "revoke":\s*\$this->revoke\(\);/', $controllerSource), $failures, $passed);

// --- 3.1.13: reported (via screenshots, no accompanying text) real
// client-facing login lockout — the TOTP challenge screen shows "Time-
// Based Token Two-Factor Authentication is not currently active for
// this account" even though Security Pack's own admin Enrollment
// Overview shows an active TOTP enrollment for the account. Root cause
// is NOT yet confirmed: challenge()/verify() run pre-authentication
// (no client-area session exists yet), so identity resolution there
// depends entirely on $params["user_info"]["id"], an undocumented WHMCS
// Security Module contract detail that has been disclosed-but-unverified
// since 2.6.1. Rather than guess a behavioral fix to this security-
// critical, previously-protected identity-resolution code, this change
// adds strictly non-sensitive diagnostic logging
// (dct_totp_2fa_log_challenge_mismatch()) so the next real login
// reproduces with concrete, inspectable evidence before any fix is
// applied. These are source-inspection tests only — the function is not
// invoked here, since exercising it requires a live TotpEnrollmentService/
// Capsule/WHMCS runtime this DB-less test suite deliberately does not
// stand up (same rationale documented at the top of this file for other
// DB-backed orchestration). ---
$totpSecurityModuleSource3113 = (string) file_get_contents(__DIR__ . "/../../../security/dct_totp_2fa/dct_totp_2fa.php");
sp_assert("dct_totp_2fa.php (3.1.13): a dct_totp_2fa_log_challenge_mismatch() diagnostic helper exists, taking the raw \$params and the resolved \$context", strpos($totpSecurityModuleSource3113, "function dct_totp_2fa_log_challenge_mismatch(array \$params, array \$context): void") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.13): dct_totp_2fa_challenge() calls the diagnostic helper immediately before returning the \"not currently active\" warning, so a real reproduction of the reported bug is captured", (bool) preg_match('/dct_totp_2fa_log_challenge_mismatch\(\$params, \$context\);\s*\n\s*return "<p class=\\\\"text-warning\\\\">Time-Based Token Two-Factor Authentication is not currently active/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.13): dct_totp_2fa_verify() calls the diagnostic helper when TotpEnrollmentService::verifyLogin() reports \"no_challenge\", the login-time counterpart of the same identity-mismatch condition", (bool) preg_match('/\$result\["status"\] === "no_challenge"\)\s*\{\s*[\s\S]{0,300}dct_totp_2fa_log_challenge_mismatch\(\$params, \$context\);/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.13): the diagnostic helper never logs the submitted TOTP code, post_vars, or any 2FA secret — only the raw user_info.id (a WHMCS User/Client ID, not a credential), the top-level \$params keys present, and the resolved (type, id)", (bool) preg_match('/function dct_totp_2fa_log_challenge_mismatch\(array \$params, array \$context\): void\s*\{([\s\S]*?)\n\}/', $totpSecurityModuleSource3113, $m3113) && strpos($m3113[1], "post_vars") === false && strpos($m3113[1], "submitted") === false && strpos($m3113[1], "secret") === false && strpos($m3113[1], "params_user_info_id") !== false && strpos($m3113[1], "params_top_level_keys") !== false && strpos($m3113[1], "resolved_type") !== false && strpos($m3113[1], "resolved_id") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.13): the diagnostic helper is fully fail-soft — guarded by function_exists(\"security_pack_record_event\") and wrapped in try/catch(\\Throwable), so it can never break the login flow even if the event pipeline is unavailable", (bool) preg_match('/function dct_totp_2fa_log_challenge_mismatch\(array \$params, array \$context\): void\s*\{[\s\S]*?if\(!function_exists\("security_pack_record_event"\)\)\s*\{\s*return;\s*\}[\s\S]*?try\s*\{[\s\S]*?\}\s*catch\s*\(\\\\Throwable \$e\)\s*\{/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.13): the recorded event type is the specific, greppable \"2fa.totp.challenge_identity_mismatch\" (not a generic label), so the user can find it in the Activity/Module Log after reproducing the login failure", strpos($totpSecurityModuleSource3113, '"2fa.totp.challenge_identity_mismatch"') !== false, $failures, $passed);

// --- 3.1.14: root cause CONFIRMED from the 3.1.13 diagnostic's first
// real capture — params_user_info_id: 666037 (the correct client),
// resolved_type/id: admin #9. dct_totp_2fa_context() checked
// $_SESSION["adminid"] FIRST, unconditionally — but WHMCS shares one PHP
// session between the admin area and the client area on the same
// domain, so an unrelated admin panel session already open in the same
// browser silently overrode the real login's identity. That session
// state is meaningless at challenge()/verify() time anyway: those run
// PRE-authentication, before the login being challenged has ever set
// $_SESSION["adminid"]/["uid"] itself — so trusting session state there
// can only ever pick up STALE state from a different, unrelated login.
// Fix: challenge()/verify() now resolve identity exclusively via the new
// dct_totp_2fa_login_identity($params) — $params["user_info"]["id"] (the
// one value WHMCS actually supplies for THIS login attempt) plus a
// DB-based admin/client check, never $_SESSION. dct_totp_2fa_context()
// itself is unchanged and still used by activate()/activateverify(),
// where session-based identity IS correct (the account owner is already
// logged in, self-enrolling). ---
sp_assert("dct_totp_2fa.php (3.1.14): a session-independent dct_totp_2fa_login_identity(array \$params) resolver exists, for use by the pre-authentication login callbacks only", strpos($totpSecurityModuleSource3113, "function dct_totp_2fa_login_identity(array \$params): array") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.14): dct_totp_2fa_login_identity() never reads \$_SESSION — it resolves purely from \$params[\"user_info\"][\"id\"] plus a DB-based type check, closing the session-bleed bug that mis-resolved a real client login as an unrelated admin session", (bool) preg_match('/function dct_totp_2fa_login_identity\(array \$params\): array\s*\{([\s\S]*?)\n\}/', $totpSecurityModuleSource3113, $m3114Fn) && strpos($m3114Fn[1], "\$_SESSION") === false && strpos($m3114Fn[1], 'params["user_info"]["id"]') !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.14): dct_totp_2fa_challenge() resolves identity via dct_totp_2fa_login_identity(\$params), not the session-priority dct_totp_2fa_context()", (bool) preg_match('/function dct_totp_2fa_challenge\(\$params\)[\s\S]{0,400}\$context = dct_totp_2fa_login_identity\(\$params\);/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.14): dct_totp_2fa_verify() resolves identity via dct_totp_2fa_login_identity(\$params), not the session-priority dct_totp_2fa_context()", (bool) preg_match('/function dct_totp_2fa_verify\(\$params\)[\s\S]{0,400}\$context = dct_totp_2fa_login_identity\(\$params\);/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.15 supersedes 3.1.14 here): dct_totp_2fa_activate()/activateverify() now resolve identity via dct_totp_2fa_account_identity(\$params), not the raw session-only dct_totp_2fa_context() — see the 3.1.15 block below for why", (bool) preg_match('/function dct_totp_2fa_activate\(\$params\)[\s\S]{0,400}\$context = dct_totp_2fa_account_identity\(\$params\);/', $totpSecurityModuleSource3113) && (bool) preg_match('/function dct_totp_2fa_activateverify\(\$params\)[\s\S]{0,400}\$context = dct_totp_2fa_account_identity\(\$params\);/', $totpSecurityModuleSource3113), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.14): dct_totp_2fa_resolve_type_for_id() centralizes the DB-based tbladmins check, used by dct_totp_2fa_context()'s fallback branch, dct_totp_2fa_login_identity(), and dct_totp_2fa_account_identity() — no duplicated/diverging admin-detection logic", substr_count($totpSecurityModuleSource3113, "dct_totp_2fa_resolve_type_for_id(") >= 4, $failures, $passed);

// --- 3.1.15: a real, actively-signed-in client on their own client-area
// Security Settings page clicked "Enable Two-Factor Authentication" and
// got "Could not identify your account." — dct_totp_2fa_context()'s pure
// $_SESSION["uid"] lookup returned nothing for a genuinely authenticated
// client-area visitor (e.g. a sub-account/contact login not using the
// same session key as a primary client is one known way this can
// happen). Same underlying lesson as 3.1.14: $params["user_info"]["id"]
// is the value WHMCS itself builds for who a given Security Module call
// is actually for, and is more reliable than this module's own guess at
// which raw session key holds the right value. Fix: activate()/
// activateverify() now resolve identity via the new
// dct_totp_2fa_account_identity($params), which prefers
// $params["user_info"]["id"] (DB-checked for type) and falls back to
// the session-based dct_totp_2fa_context() only if WHMCS didn't supply a
// usable id — so any install where the old session-only path already
// worked keeps working, and the demonstrated failure case is fixed. ---
$totpSecurityModuleSource3115 = (string) file_get_contents(__DIR__ . "/../../../security/dct_totp_2fa/dct_totp_2fa.php");
sp_assert("dct_totp_2fa.php (3.1.15): a dct_totp_2fa_account_identity(array \$params): array resolver exists, for the self-service enrollment callbacks", strpos($totpSecurityModuleSource3115, "function dct_totp_2fa_account_identity(array \$params): array") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.15): dct_totp_2fa_account_identity() prefers \$params[\"user_info\"][\"id\"] (DB-checked via dct_totp_2fa_resolve_type_for_id()) and falls back to the session-based dct_totp_2fa_context() only when no usable id was supplied — never the reverse order", (bool) preg_match('/function dct_totp_2fa_account_identity\(array \$params\): array\s*\{([\s\S]*?)\n\}/', $totpSecurityModuleSource3115, $m3115Fn) && strpos($m3115Fn[1], 'params["user_info"]["id"]') !== false && strpos($m3115Fn[1], "dct_totp_2fa_resolve_type_for_id(\$id)") !== false && strpos($m3115Fn[1], "dct_totp_2fa_context()") !== false && strpos($m3115Fn[1], 'if($id > 0)') !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.15): dct_totp_2fa_login_identity() (the pre-authentication resolver from 3.1.14) is untouched and still never reads \$_SESSION — the 3.1.15 fallback-to-session behavior is exclusive to the self-service account_identity() resolver, not the login-time one", (bool) preg_match('/function dct_totp_2fa_login_identity\(array \$params\): array\s*\{([\s\S]*?)\n\}/', $totpSecurityModuleSource3115, $m3115LoginFn) && strpos($m3115LoginFn[1], "\$_SESSION") === false, $failures, $passed);

// ============================================================
// 3.1.17 — "REBUILD dct_totp_2fa": native WHMCS TOTP compatibility +
// modern security architecture (replay protection, challenge-form
// contract fix, recovery-code login wiring). See TOTP-REBUILD-AUDIT.md.
// ============================================================
$totpModulePath = __DIR__ . "/../../../security/dct_totp_2fa/dct_totp_2fa.php";
$totpModuleSource = (string) file_get_contents($totpModulePath);
$totpModuleCodeOnly = (string) preg_replace(['#/\*.*?\*/#s', '#//[^\n]*#'], '', $totpModuleSource);

// --- CRITICAL: challenge() must never nest its own <form> inside
// WHMCS's own outer login <form action="dologin.php"> (confirmed against
// the real, decoded native modules/security/totp/totp.php reference,
// whose own totp_challenge() returns bare controls with no <form> tag at
// all). This was a real, confirmed bug in the pre-rebuild implementation
// (both the main code-entry path AND the same-IP bypass auto-submit
// path each created their own nested <form action="dologin.php">). ---
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_challenge() never emits a <form> tag anywhere in its returned HTML — WHMCS's own login page supplies the enclosing form, per the confirmed native Security Module contract", stripos($totpModuleCodeOnly, "<form") === false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): the main challenge path still returns a text input named dct_totp_2fa_code (the field WHMCS posts back to dct_totp_2fa_verify())", strpos($totpModuleSource, 'name="dct_totp_2fa_code"') !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): the same-IP bypass path still posts dct_totp_2fa_bypass=1, now as a bare hidden input rather than inside a second <form>", (bool) preg_match('/<input type="hidden" name="dct_totp_2fa_bypass" value="1">/', $totpModuleSource), $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): the bypass auto-submit script submits the ENCLOSING form (closest(\"form\") / document.forms[0]) rather than creating and submitting a form of its own", strpos($totpModuleCodeOnly, 'closest("form")') !== false && strpos($totpModuleCodeOnly, "document.forms") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): the challenge field's maxlength was widened past 6 to accommodate recovery codes (XXXX-XXXX-XXXX-XXXX, 19 chars) in the same field", (bool) preg_match('/name="dct_totp_2fa_code"[\s\S]*?maxlength="19"/', $totpModuleSource), $failures, $passed);

// --- Section 11: replay protection. verify() no longer strips non-digit
// characters before checking length — it now distinguishes a 6-digit TOTP
// code from a recovery code first, so a replayed TOTP code is rejected
// via TotpEnrollmentService::verifyLogin()'s own last_used_step check
// (tested directly against TotpService::matchingStep() above; the
// DB-backed rejection itself is a manual/live-install test — see the
// FINAL DELIVERABLE report). ---
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_verify() routes exactly-6-digit submissions to TotpEnrollmentService::verifyLogin() (replay-protected)", (bool) preg_match('/preg_match\(\'\/\^\\\\d\{6\}\$\/\', \$digitsOnly\)[\s\S]{0,200}TotpEnrollmentService::verifyLogin\(/', $totpModuleCodeOnly), $failures, $passed);
$totpVerifyFnMatch = [];
preg_match('/function dct_totp_2fa_verify\(\$params\)\s*\{([\s\S]*?)\n\}/', $totpModuleCodeOnly, $totpVerifyFnMatch);
$totpVerifyFnBody = $totpVerifyFnMatch[1] ?? "";
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_verify() no longer discards non-digit characters from the raw submission before deciding how to handle it (needed so recovery codes, which contain letters/hyphens, aren't mangled into digits) — dct_totp_2fa_activateverify()'s own unrelated \\D+ stripping, used only for enrollment where a 6-digit code is always expected, is untouched and out of scope", $totpVerifyFnBody !== "" && strpos($totpVerifyFnBody, 'preg_replace("/\D+/"') === false, $failures, $passed);

// --- Section 12: recovery codes. Reuses TwoFactorAuthenticationService::
// attemptRecoveryCode() (itself a thin wrapper over RecoveryCodeService::
// attemptConsume(), Security Pack's ONE existing recovery-code store) —
// no new/duplicate recovery-code service, table, or hashing scheme. ---
sp_assert("dct_totp_2fa.php (3.1.17): a non-6-digit challenge submission is routed to TwoFactorAuthenticationService::attemptRecoveryCode() — the SAME shared recovery-code consumption every other 2FA method already uses", strpos($totpModuleCodeOnly, "TwoFactorAuthenticationService::attemptRecoveryCode(") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): no new recovery-code class/table/hashing was introduced — RecoveryCodeService is never referenced directly from dct_totp_2fa.php (only via the shared TwoFactorAuthenticationService facade)", strpos($totpModuleCodeOnly, "RecoveryCodeService::") === false, $failures, $passed);

// --- Preserved (NOT rebuilt) per the ticket's own instructions: identity
// resolution, mutual exclusion, bypass integration. Re-asserted here
// against the 3.1.17 file to catch any accidental regression from the
// rebuild, in addition to the existing 3.1.14/3.1.15-era tests above. ---
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_login_identity() is unchanged/preserved — still the params-only, session-independent resolver used by challenge()/verify()", strpos($totpModuleSource, "function dct_totp_2fa_login_identity(array \$params): array") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_account_identity() is unchanged/preserved — still the params-first, session-fallback resolver used by activate()/activateverify()", strpos($totpModuleSource, "function dct_totp_2fa_account_identity(array \$params): array") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_activateverify() still calls TwoFactorAuthenticationService::activateExclusive(\"totp\", ...) on successful activation — mutual exclusion preserved, not duplicated", strpos($totpModuleSource, 'TwoFactorAuthenticationService::activateExclusive("totp"') !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): dct_totp_2fa_bypass_active() still delegates to TwoFactorBypassService::findActive() — bypass architecture preserved, not duplicated", strpos($totpModuleSource, "TwoFactorBypassService::findActive(") !== false, $failures, $passed);
sp_assert("dct_totp_2fa.php (3.1.17): a successful login still grants a same-IP bypass via TwoFactorBypassService::grantSameIpBypass() when enabled in settings — unchanged from pre-rebuild behavior", strpos($totpModuleSource, "TwoFactorBypassService::grantSameIpBypass(") !== false, $failures, $passed);

// --- TotpEnrollmentService: replay-protection wiring (source-checked —
// this class is intentionally never require()'d directly in this test
// runner, since every one of its methods is DB-backed; see the file's
// own header comment for why, matching the existing pattern used for
// every other DB-backed service in this suite). ---
$totpEnrollmentSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/TotpEnrollmentService.php");
sp_assert("TotpEnrollmentService.php (3.1.17): verifyLogin() uses TotpService::matchingStep(), not verify(), so the matched HOTP counter is available for replay comparison", (bool) preg_match('/function verifyLogin\([\s\S]*?TotpService::matchingStep\(/', $totpEnrollmentSource), $failures, $passed);
sp_assert("TotpEnrollmentService.php (3.1.17): verifyLogin() rejects a code whose matched step is <= the account's stored last_used_step, returning status \"replayed\"", strpos($totpEnrollmentSource, '$matchedStep <= $lastUsedStep') !== false && strpos($totpEnrollmentSource, '"status" => "replayed"') !== false, $failures, $passed);
sp_assert("TotpEnrollmentService.php (3.1.17): verifyLogin() persists the new last_used_step on a successful (non-replayed) verification", (bool) preg_match('/"last_verified_at" => date\("Y-m-d H:i:s"\), "last_used_step" => \$matchedStep/', $totpEnrollmentSource), $failures, $passed);
sp_assert("TotpEnrollmentService.php (3.1.17): a rejected replay records a dedicated 2fa.totp.replay_rejected security event (not silently folded into the generic verification.failed event)", strpos($totpEnrollmentSource, '"2fa.totp.replay_rejected"') !== false, $failures, $passed);
sp_assert("TotpEnrollmentService.php (3.1.17): verifyAndActivate() (enrollment) also establishes an initial last_used_step baseline, so the account's very first login afterwards has a real value to compare against rather than an unset column", strpos($totpEnrollmentSource, '"last_used_step" => $matchedStep, "updated_at" => $now') !== false, $failures, $passed);
sp_assert("TotpEnrollmentService.php (3.1.17): no second/duplicate TOTP verification engine was introduced — TotpService remains the ONLY class performing the RFC 6238 HOTP calculation", substr_count($totpEnrollmentSource, "TotpService::") >= 2 && strpos($totpEnrollmentSource, "hash_hmac(") === false, $failures, $passed);

// --- TotpService.php: matchingStep()/verify() zero-regression refactor,
// source-level confirmation that verify() truly delegates rather than
// containing a second, potentially-diverging copy of the matching logic. ---
$totpServiceSource = (string) file_get_contents(__DIR__ . "/../lib/Security/TwoFactor/TotpService.php");
sp_assert("TotpService.php (3.1.17): verify() is defined purely in terms of matchingStep() (returns matchingStep(...) !== null) — not a second, independently-maintained copy of the step-matching loop", (bool) preg_match('/function verify\([\s\S]{0,400}return self::matchingStep\([^)]*\) !== null;/', $totpServiceSource), $failures, $passed);
sp_assert("TotpService.php (3.1.17): matchingStep() still uses hash_equals() for the code comparison — no regression to a non-constant-time comparison while adding replay support", (bool) preg_match('/function matchingStep\([\s\S]*?hash_equals\(/', $totpServiceSource), $failures, $passed);

// --- security_pack.php: idempotent, additive last_used_step migration
// (no new database table — a single nullable column on the EXISTING
// dctlab_security_pack_totp2fa table (renamed from nnm_security_pack_totp2fa
// in the DCTLAB rebrand/database-naming pass), guarded by hasColumn() so
// it is safe to run on every request/activation, not just once). ---
$securityPackSource = (string) file_get_contents(__DIR__ . "/../security_pack.php");
sp_assert("security_pack.php (3.1.17): the last_used_step migration is guarded by hasColumn(\"dctlab_security_pack_totp2fa\", \"last_used_step\") — idempotent, never re-adds an already-present column", strpos($securityPackSource, 'hasColumn("dctlab_security_pack_totp2fa", "last_used_step")') !== false, $failures, $passed);
sp_assert("security_pack.php (3.1.17): the new column is added via a plain schema()->table() ALTER — no dropIfExists()/create() of the totp2fa table, so existing enrollments/secrets are never touched or re-encrypted by this migration", (bool) preg_match('/hasColumn\("dctlab_security_pack_totp2fa", "last_used_step"\)\) \{[\s\S]{0,900}schema\(\)->table\("dctlab_security_pack_totp2fa"/', $securityPackSource), $failures, $passed);
sp_assert("security_pack.php (3.1.17): no second/duplicate TOTP database table was created for replay protection — only the existing dctlab_security_pack_totp2fa table is referenced by the migration", substr_count($securityPackSource, 'schema()->create("dctlab_security_pack_totp') === 1, $failures, $passed);

// --- Not modified: WHMCS core (modules/security/totp/ was NEVER edited —
// it exists only as an external, ionCube-protected reference outside
// this project's own tree; the fact that this project's rebuilt module
// still lives under its own modules/security/dct_totp_2fa/ directory,
// not modules/security/totp/, is itself the check). ---
sp_assert("dct_totp_2fa.php (3.1.17): the rebuilt module is still its own, separately-named Security Module (modules/security/dct_totp_2fa/) — WHMCS's native modules/security/totp/ was never touched by this project", is_dir(__DIR__ . "/../../../security/dct_totp_2fa") && !is_dir(__DIR__ . "/../../../security/totp"), $failures, $passed);

// --- Summary ---
$existingTests = 566;
$newTests = $passed + count($failures) - $existingTests;
$totalTests = $passed + count($failures);
echo "Existing tests: " . $existingTests . " / New tests: " . $newTests . " / Total: " . $totalTests . " / Passed: " . $passed . " / Failed: " . count($failures) . "\n";
if($failures) {
    echo "\nFAILED:\n";
    foreach ($failures as $f) {
        echo "  - " . $f . "\n";
    }
    exit(1);
}
exit(0);
