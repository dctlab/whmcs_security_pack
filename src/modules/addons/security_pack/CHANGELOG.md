# Security Pack — Changelog

## 3.1.32 — Bug fix: Users / 2FA Overview showed the wrong person

**Root cause**: `TwoFactorController::resolveUserLabel()` resolved a `client`/`user` 2FA
identity's display name by querying `tblclients.id = $userId`. A client/user 2FA identity's
`$userId` is actually a WHMCS **User** ID (`tblusers.id` — the same
`$params['user_info']['id']` every `dct_*_2fa` provider's `_challenge()`/`_activate()`
receives), a completely different ID space from `tblclients.id` (see
`Email2faService::resolveClientIdForUser()`, whose whole existence documents that a Client
ID must be separately, best-effort resolved FROM a User ID). On the reporting install, User
ID 666316 (Sanitha Mary, sanitha@the-experience.com, owned by WHMCS Client ID 666310)
numerically collided with an unrelated `tblclients` row and the "Users / 2FA Overview" panel
(3.1.31) displayed "Manoj Kumar (#666316)" instead of "Sanitha Mary (#666316)".

**Fix**: `resolveUserLabel()` is now split into two pieces — `resolveUserLabelSource()`, a
PURE function deciding which table and which first/last-name column pair to use per
identity type, and `formatUserLabelFromRow()`, a PURE function formatting the name from an
already-fetched row. A `client`/`user` identity now resolves against `tblusers` using
`first_name`/`last_name` (note the underscore — `tblusers` uses different column names than
`tblclients`/`tbladmins`/`tblcontacts`'s `firstname`/`lastname`; using the wrong pair would
have silently produced an empty name and masked the mis-resolution behind the generic
fallback label instead of fixing it). Administrator (`tbladmins`) and contact/sub-account
(`tblcontacts`) resolution are unchanged — Step 7's live sub-account/contact authentication
work is still unverified and out of scope for this fix.

**Audited (not modified)**: searched the entire module (`modules/addons/security_pack` and
the sibling `modules/security/dct_*_2fa` Security Modules) for any other place a raw 2FA
`$userId` is queried directly against `tblclients.id` — `resolveUserLabel()` was the only
offender. Every other `tblclients` reference in the module (`Email2faService`,
`WhatsAppTwoFactorService`) already resolves a separately-derived `$clientId` via the
`tblusers_clients` junction table or an email match, never the raw identity `$userId`
directly.

**No schema changes.** No 2FA records/IDs were migrated or altered — the stored `user_id`
values were always correct; only how the admin display resolved a name from them was wrong.

**Testing**: 15 new regression tests (pure — `resolveUserLabelSource()`/
`formatUserLabelFromRow()` unit tests covering the exact reported case, a source-inspection
guard confirming the buggy `tblclients` literal is gone, and a module-wide automated audit
that fails if any file anywhere under `modules/` ever queries
`table("tblclients")->where("id", $userId)` again). Also added the vendor
`robthree/twofactorauth` and template/asset `require`s this CLI test harness (`tests/run.php`)
was missing for the pre-existing Step 6/TOTP tests to actually execute standalone (a
test-infrastructure gap unrelated to this bug, needed to get a real pass/fail signal from
the suite at all — see test run notes). Full suite: 638/638 passing. Full `php -l` sweep
across the entire project tree, clean.


## 3.1.31 — Step 6: Admin Reporting & 2FA Status Visibility

New "Users / 2FA Overview" reporting panel on the existing Two-Factor Authentication admin
page, built entirely on top of 3.1.28-3.1.30 — **no schema changes, no new tables/columns,
no redesigned decision architecture.**

**New panel** (`TwoFactorController::renderReporting()`): lists every `(user_id,
user_type)` identity with any 2FA history (a row in any of the three method tables),
most-recently-active first, capped at 200. Columns: User, Type, 2FA (Enabled/Disabled/Not
Configured), Method (currently active method only — never a stale/inactive one), Activated,
Last Verified, Trusted Browser, Trusted IP. Complements, and never conflicts with, the
existing admin Client Profile > Users tab "Required — Not Enrolled" badge — both read the
same `isRequiredByPolicy()` check.

**Reused, not duplicated**: `TwoFactorAuthenticationService::status()` for status/active
method (same authoritative read every other screen uses); the existing `activated_at`/
`last_verified_at` columns via two new thin wrapper methods
(`activatedAtTimestampsForIdentity()`/`lastVerifiedAtTimestampsForIdentity()`, refactored
from the existing `activatedAtTimestamp()` private helper — one shared `columnTimestamp()`
core now, no logic duplicated); `TrustedBrowserService::listForIdentity()` (Step 5) plus a
new pure `summarize()` helper (count + latest expiry — never the token/hash);
`TwoFactorIpExemptionService`'s existing table plus two new existence-only reads
(`hasActiveGlobalExemption()`/`hasActiveUserExemption()`) and a pure `reportLabel()`
(None / Global Exemption / Per-User Exemption).

**Audited, not modified**: confirmed a successful TOTP recovery-code verification (fixed in
3.1.29) still correctly reaches the same `last_verified_at` column this new reporting reads
— re-verified by source inspection for this step's explicit requirement, nothing changed
in provider behavior.

**Identity-aware, not admin/client-only**: `resolveUserLabel()` branches on the actual
`UserIdentityType` (client/admin/contact) rather than a binary ternary — a future `contact`
row resolves against `tblcontacts`, never silently misfiled as a client. No live
contact/sub-account authentication was implemented (out of scope for this step, per
instruction).

**Security**: the reporting panel never references `token_hash`, a raw trusted-browser
token, an OTP value, or a recovery code anywhere — confirmed by source-inspection test.

Testing: 717/717 (36 new this step — pure-logic tests for every new decision function,
plus source-inspection tests for the DB-backed reads and the recovery-code/no-conflict/
identity-isolation/no-sensitive-data requirements this suite has no live database to
exercise directly). Full `php -l` sweep across every file in the project, clean.

## 3.1.30 — Step 5: Trusted Browser / "Remember this browser for 30 days"

New, deliberately independent trusted-browser system (Requirements doc Section 3):
after a REAL successful 2FA verification (OTP code or recovery code — never a
bypass/IP-exemption/trusted-browser shortcut), the user may check "Remember this
browser for 30 days" to skip the 2FA challenge on that specific browser until it
expires, is revoked, or 2FA is disabled/reset.

**New class**: `TrustedBrowserService` (`lib/Security/TwoFactor/TrustedBrowserService.php`)
— a 32-byte `random_bytes()` token, base64url-encoded for an `HttpOnly`/`Secure`/
`SameSite=Lax` cookie; only `hash('sha256', $token)` is ever stored server-side, in a
new, independent table (`nnm_security_pack_trusted_browsers`), scoped by the existing
`(user_id, user_type)` identity pair with a unique index on `token_hash` and indexes on
identity and `expires_at`. Deliberately never merged with `TwoFactorBypassService` (same-IP
bypass) or `TwoFactorIpExemptionService` (company IP exemption) — three separate systems,
three separate tables, see the class's own docblock for the full rationale.

**Wired into all three live security modules** (`dct_email_2fa`, `dct_whatsapp_2fa`,
`dct_totp_2fa`): `challenge()` checks the trusted-browser cookie (read-only) before
falling through to the existing bypass/OTP flow; `verify()` independently re-checks and
consumes it — never trusting the hidden field alone, same discipline as the existing
bypass check. A genuine OTP/recovery-code success with the checkbox checked creates a new
token and sets the cookie. TOTP's recovery-code path was explicitly included: the
remember-browser check sits at the single point reached by both the TOTP-code and
recovery-code branches.

**Revocation on 2FA disable/reset**: `TwoFactorAuthenticationService::disableAllMethods()`
(admin disable) and `TotpEnrollmentService::reset()` (secret reset/re-enrollment) both now
call `TrustedBrowserService::revokeAll()`. Deliberately NOT wired into
`activateExclusive()`'s automatic method-switch disable — switching methods isn't a
protection-removed event.

**Client UI**: the existing Security Center (`ClientController::security_center()` /
`templates/security_center.tpl`) now lists the client's own trusted browsers (device
label, created/last-used/expiry dates — never the token) with per-device and revoke-all
controls, a new CSRF-protected `revoke_trusted_browser` action, ownership-checked so one
client can never revoke another's row.

**Admin UI**: the existing "Manage a User's Two-Factor Authentication" panel
(`TwoFactorController`) now also shows a looked-up user's trusted browsers with a
revoke-all control, scoped to the exact identity looked up.

Testing: 681/681 (115 new — pure-logic tests for `isRowValid()`/`hashToken()`/
`generateToken()`, plus source-level inspection tests for every DB-backed/cross-module
behavior this suite has no live database to exercise directly: creation gating,
bypass-never-auto-creates, identity isolation, recovery-code eligibility, revoke-on-disable/
reset wiring, and the IP/trusted-browser independence the interaction scenarios rely on —
each labeled `[pure]` or `[source]` in the test file). Full `php -l` sweep across every
file in the project, clean.

## 3.1.29 — Step 4 OTP security parity audit: one gap found and fixed

Inspect-first audit of Email/WhatsApp/TOTP's failed-attempt protection, rate limiting,
expiry, resend cooldown/max-resends, concurrency safety, and last-successful-verification
tracking. Email and WhatsApp were already at full parity (same `OtpEngine`/`RateLimiter`
primitives, same concurrency-safe attempt-count guard) — no changes needed there. TOTP
correctly has no resend/cooldown concept (by design — there's no OTP delivery to resend)
and already has rate limiting, replay protection, and `last_verified_at` tracking on both
enrollment and TOTP-code login.

**One real gap found**: a successful TOTP **recovery-code** login (`dct_totp_2fa.php`,
`dct_totp_2fa_verify()`) never updated `nnm_security_pack_totp2fa.last_verified_at` — the
recovery-code path is deliberately method-agnostic (`RecoveryCodeService`, shared across
all methods) so it has no way to know which provider's table to update; only the calling
module knows that. Fixed by writing `last_verified_at` directly in that module, at the
exact call site, matching the same pattern `dct_email_2fa_verify()`/
`dct_whatsapp_2fa_verify()` already use for their own successful-verification writes. This
would have under-reported real 2FA usage on the Step 6 admin reporting screen for anyone
who signs in via a recovery code.

The identical gap exists in the separate standalone `dct_totp_native` module (its own
`Enrollment.php` mirrors this same pattern) — **not fixed, per explicit instruction not to
modify that project unless clearly in scope; reported separately instead.**

Testing: 656/656 (no new test — this is a DB write in a live security module, same class
of thing as the other `last_verified_at` writes, none of which are unit tested in this
codebase's current test harness). Full `php -l` sweep across every file, clean.

## 3.1.28 — Sub-account foundation, admin "Disable 2FA for a user", dedicated 2FA IP exemptions

Steps 1–3 of the "Security Pack 2FA Requirements" doc, per explicit build order.

**1. Sub-account foundation.** New `UserIdentityType` (client/admin/contact) replaces every
`=== "admin" ? "admin" : "client"` binary coalesce in the admin controllers — those silently
downgraded any unrecognized value (including a future "contact"/sub-account identity) to
"client", which would have misfiled a sub-account's bypass/action under its parent's
identity. Every 2FA table already keys strictly off the exact `(user_id, user_type)` pair,
so a third identity type isolates cleanly with no schema change — see `UserIdentityType`'s
class docblock. **No live sub-account login/challenge wiring — that stays deferred to a
later step, pending live verification of how WHMCS actually identifies a logged-in
contact.**

**2. Admin: Disable 2FA.** New "Manage a User's Two-Factor Authentication" panel (Two-Factor
Authentication admin page): look up any WHMCS User by ID+Type, see their status across all
three methods plus recovery codes remaining, and disable an active method with one click.
Reuses each provider's own existing `disable()` (new
`TwoFactorAuthenticationService::disableAllMethods()` orchestrates, never reimplements) —
enrollment is preserved, mutual-exclusion self-heal is untouched. Emits a
`2fa.admin.disabled` audit event through the existing event pipeline.

**3. Dedicated 2FA IP/CIDR exemption.** New `TwoFactorIpExemptionService` + table
(`nnm_security_pack_2fa_ip_exemptions`) — a genuinely separate system from
`IpRestrictionService` (that one is a general allow/block gate with its own conflict-
precedence rules; this one only ever means "skip the 2FA challenge", no precedence to
resolve). Supports company-wide (global) exemptions and per-identity exemptions, both
manageable from a new "2FA IP Exemptions" panel on the admin Two-Factor Authentication page.
Wired into the actual challenge decision in all three live security modules
(`dct_email_2fa`, `dct_whatsapp_2fa`, `dct_totp_2fa`) as a third OR-condition alongside the
existing bypass check, `class_exists()`-guarded to fail closed on a partial deploy. Fails
closed on any DB error (an exemption lookup failure never silently skips a challenge that
should have run). **Admin-side only in this release** — client self-service configuration
of their own exemption is not yet built (no existing client-area 2FA page to extend); the
service itself is ready for that.

**Not touched, by design:** `dct_totp_native` (a separate standalone module/project, not
part of this addon) is not wired into the IP exemption check yet — flagged as a known gap,
not silently skipped.

Testing: 656/656 (566 existing + 90 new — includes 7 new `UserIdentityType` assertions and
7 new `TwoFactorIpExemptionService` pure-logic assertions covering bare-IP match, CIDR
match, user-scoped-only match, no-match, both-empty safe default, and cross-identity
isolation). `disableAllMethods()`/the admin panels are DB-backed and were not unit tested
directly (same constraint as `providers()`/`status()` elsewhere in this codebase) — full
`php -l` sweep across every touched file, all clean.

## 3.1.27 — Fixed duplicate "Administrator Manual Bypass" table on the merged page

Reported live: after 3.1.25 merged Email 2FA onto the Two-Factor Authentication page, the
page showed an "Enrollment Overview" panel and an "Administrator Manual Bypass" table
TWICE — once at the top (unified, all methods) and again in the embedded "Email 2FA"
section below it, with the exact same bypass rows appearing in both tables (confirmed
live: bypass #666037 listed twice).

Root cause: 3.1.25's embedded Email 2FA section called its own `renderBypasses()`, on the
documented assumption that an Email 2FA bypass was scoped separately from the unified
bypass system. That assumption was wrong — `Email2faController::renderBypasses()` and
the unified `TwoFactorBypassService` both read/write the exact same
`nnm_security_pack_email2fa_bypasses` table with no method-scoping filter on lookup; it
was never actually two systems, so showing it twice showed the same data twice.

Fix: the embedded Email 2FA section no longer renders its own bypass table — only the
unified one above it. The embedded section's own "Overview" panel IS kept, since it
genuinely shows information the unified overview above it does not track (pending-
verification counts, 24h failed-verification counts) — only the redundant part was
removed. Intro text updated to describe accurately what the section still adds.

Testing: 643/643 (no test-count change — this is a display/composition fix with no new
pure-logic branch to unit test; verified via `php -l` and a full re-run of the existing
suite).

## 3.1.26 — Policy panel "Require Two-Factor Authentication" now has a visible effect

Root cause: `TwoFactorAuthenticationService::isRequiredByPolicy()` and
`::defaultMethod()` were never called by anything — the Policy panel's
settings saved and reloaded correctly, but had zero observable effect
anywhere, which is what the reported "Policy... Not working?" was
describing.

Fix (per explicit product decision: admin Users-tab badge, not a
client-area banner or email reminder): when "Require Two-Factor
Authentication" is on, any account on the admin Client Profile > Users
tab that has not enrolled in a recognized Security Pack method now
shows a ⚠ "Required — Not Enrolled" badge in the "Two Factor Auth
Method" column, in place of the ambiguous native "N/A". Accounts that
already have an active method are untouched. This is purely a display
flag — it does not enforce anything, gate login, or retroactively lock
anyone out, matching the panel's own existing documented behavior.

New `TwoFactorController::buildSecondFactorMappingWithPolicy()` wraps
the existing (unchanged) `buildSecondFactorMapping()` — reused by
`core/two_factor_admin_display.php`'s existing server-side mapping
hook — and the JS overlay's existing forward-compatible `state`-driven
label switch (`two_factor_admin_users.js`) gained one new case for
`state: "required_not_enrolled"`. No new database table/column, no new
admin route.

Testing: 643/643 (566 existing + 77 new — includes 6 new assertions
covering policy-off no-op, an enrolled account never getting
overwritten, the required-but-unenrolled badge, WHMCS's own native
"totp" module still getting the badge under policy, duplicate/invalid
User ID handling, and a mixed enrolled+unenrolled batch).

## 3.1.25 — Email 2FA and Two-Factor Authentication merged onto one page

Per explicit request: the "Email 2FA" page (enrollment overview + its
own administrator bypass table) and the "Two-Factor Authentication"
page (cross-method overview, policy, unified bypass) previously lived
at two separate admin nav entries / URLs. They're now shown together
on one page.

**Changed:**
- `Email2faController`'s render logic was extracted into a public
  `renderContent(bool $standalone)` method so `TwoFactorController::render()`
  can embed it directly, with its own "Email 2FA" section heading, right
  after the unified overview/policy/bypass sections.
- The separate "Email 2FA" nav menu entry is removed; "Two-Factor
  Authentication" is now the only entry under the Authentication group.
- `?module=security_pack&c=email2fa` (no action, or `a=index`) now
  redirects to `c=twoFactor` instead of rendering its own page — old
  bookmarks/links still work, they just land on the merged page.

**Unchanged — nothing about the underlying features moved or was
rewritten:** `Email2faController::bypass()`/`revoke()` still POST to
and operate on exactly the same tables
(`nnm_security_pack_email2fa`, `nnm_security_pack_email2fa_bypasses`)
via the same `c=email2fa&a=bypass`/`a=revoke` CSRF-protected routes as
before — only their post-action redirect target changed (now
`c=twoFactor`, so you land back on the merged page instead of the
now-redundant standalone one). The unified cross-method bypass system
(`TwoFactorBypassService`) and Email 2FA's own bypass table remain two
separate systems, exactly as documented — the merged page makes that
explicit with its own section heading and a short note explaining the
distinction, rather than conflating them.

**Testing:** 637/637 (unchanged — this is a page-composition change,
no new pure-logic branch), `php -l` clean on all three touched files.


## 3.1.24 — Admin Users tab now recognizes dct_totp_native accounts

**Root cause:** confirmed via a live side-by-side comparison the user
ran: the same account showed "Time Based Tokens" in the admin Users
tab's "Two Factor Auth Method" column when enrolled under WHMCS's
native `totp` module, but "N/A" when enrolled under the standalone
`dct_totp_native` module instead. Native's own "Time Based Tokens"
label is painted by WHMCS core itself (unrelated to this addon);
Security Pack's own JS overlay (`two_factor_admin_users.js` +
`TwoFactorController::labelFromSecondFactorModule()`) only recognizes
`tblusers.second_factor` values it maps explicitly — and, since
`dct_totp_native` was built this session as an entirely separate,
standalone module with zero dependency on Security Pack, its module
name was never added to that map. Any third-party security module's
`second_factor` value that isn't explicitly recognized here renders as
"N/A" in this column — this is by design (see `labelFromSecondFactorModule()`'s
docblock: never guess at an unfamiliar module name), it just needed
`dct_totp_native` added to the recognized set.

**Fixed:** added `"dct_totp_native" => "Time-Based Token (Enhanced) Two-Factor Authentication"`
to `TwoFactorController::labelFromSecondFactorModule()`'s map. This is a
display-label lookup only — no functional/runtime dependency between
the two modules is introduced.

**Testing:** 2 new assertions (637 total, all passing) — direct
`labelFromSecondFactorModule("dct_totp_native")` and an end-to-end
`buildSecondFactorMapping()` check. `php -l` clean.


## 3.1.23 — Enrollment now shows the "wrong code" error, TOTP button relabeled

**Root cause:** confirmed against native `totp.php`'s own `totp_activate()`
(which reads `$params['verifyError']` and renders it in a red alert box):
WHMCS core re-invokes `_activate()` after a failed `_activateverify()`
call and passes the caught exception's message back in as
`$params["verifyError"]`. None of `dct_totp_2fa_activate()`,
`dct_email_2fa_activate()`, or `dct_whatsapp_2fa_activate()` ever read
this key, so submitting a wrong/expired code silently reset the
enrollment form back to the QR/notice screen with no explanation — the
rejection itself was working correctly (fixed in 3.1.21), it just
wasn't visible to the user, who saw what looked like nothing happening.

**Fixed:** all three `_activate()` functions now read
`$params["verifyError"]` and render it in a `.alert.alert-danger` box,
matching native's own placement and styling.

**Also changed:** `dct_totp_2fa`'s enrollment submit button now reads
"Submit" (previously "Enable Time-Based Token").

**Testing:** 635/635 (unchanged — template/rendering change, no new
pure-logic branch to unit test), `php -l` clean on all three files.


## 3.1.22 — TOTP engine now delegates to robthree/twofactorauth (vendored)

**What changed:** `TotpService`'s actual cryptographic math (secret generation, HOTP/TOTP computation, code verification) now delegates to [robthree/twofactorauth](https://github.com/RobThree/TwoFactorAuth) v3.0.3 (MIT licensed, vendored verbatim at `lib/Security/TwoFactor/vendor/robthree/twofactorauth/`, commit `85408c4e775dba7c0802f2d928efd921d530bc5b`) instead of this class's own hand-rolled implementation. RobThree/TwoFactorAuth is the most widely used standalone PHP TOTP library — no framework dependency, MIT license, actively maintained since 2014 — so the bit-twiddling that produces every login code now runs through code many other projects also depend on and have exercised.

**Scope of the vendoring:** only the core, zero-dependency files were vendored (`TwoFactorAuth`, `Algorithm`, `TwoFactorAuthException`, the CSRNG/local-time providers). Every QR-rendering provider was deliberately left out — Security Pack's own from-scratch, dependency-free `TotpQrGenerator` (no external HTTP call, ever) continues to render the actual scannable QR code; a `NullQrCodeProvider` satisfies the library constructor's required-but-unused QR provider argument.

**`TotpService`'s public API is unchanged** — every method (`generateSecret()`, `hotp()`, `totpAt()`, `verify()`, `matchingStep()`, `provisioningUri()`, `formatSecretForDisplay()`, `encryptSecret()`/`decryptSecret()`, `base32Encode()`/`base32Decode()`) keeps the exact same signature and behavior, so this was a swap of the engine underneath, not a rewrite of any call site (`TotpEnrollmentService`, the three security modules, tests).

**A real correctness bug was found and fixed during this integration:** the library's own `verifyCode()` convenience method cannot distinguish "no match" from "matched at counter 0" (both leave its by-reference `$timeslice` output at `0`, and it returns `$timeslice > 0`). Counter 0 only occurs at/before the Unix epoch and is never reachable with a real wall-clock timestamp, so this has no practical impact on this deployment — but it was caught directly by this project's own RFC 6238/4226 test-vector tests. Fixed by having `matchingStep()` call the library's `getCode()` primitive directly in its own tolerance-window loop with `hash_equals()`, rather than trusting `verifyCode()`'s boundary-buggy convenience wrapper — still 100% delegating the actual cryptographic computation to the vendored library, just not its flawed match-decision logic.

**PHP 8.2+ requirement:** robthree/twofactorauth's own `composer.json` requires PHP ≥8.2. WHMCS 9.x's own minimum is already PHP 8.2, so any WHMCS 9.x install (including this one) satisfies this automatically. Guarded explicitly in each security module's `_bootstrap()` (`PHP_VERSION_ID < 80200` throws a clear, actionable error) rather than left as an unclear fatal on an older PHP 8.1 host (still valid for WHMCS 8.x) — `_config()` never calls `_bootstrap()`, so the module stays listable in Setup > Security > Two-Factor Authentication either way.

**Testing:** 635/635 tests passing (unchanged count — this was an internal engine swap, not new features), `php -l` clean across every vendored file.


## 3.1.21 — CRITICAL: 2FA activation accepted incorrect codes (`dct_totp_2fa`, `dct_email_2fa`, `dct_whatsapp_2fa`)

**Root cause:** confirmed against the real, decoded native `modules/security/totp/totp.php`: its own `totp_activateverify()` signals failure by **throwing** `new WHMCS\Exception(...)`, and signals success by returning `['settings' => [...]]` — WHMCS core decides whether an enrollment succeeded *purely* by whether an exception was thrown, never by inspecting any returned array content. All three of this addon's `dct_*_2fa_activateverify()` functions instead returned `["msg" => "..."]` on **both** the success path *and* every failure path, with no exception thrown either way. WHMCS core therefore saw "no exception" on every single submission — including a wrong or entirely fake code — and activated 2FA at the WHMCS-core level (`tblusers.second_factor`, WHMCS's own generated backup code) regardless of whether the code was actually correct.

This was live in production. Confirmed via a real enrollment attempt on `dct_totp_2fa` with an intentionally incorrect code (`123456`): WHMCS displayed its own "Two-Factor Authentication is now enabled" success banner and generated a WHMCS backup code, while this module's own (correctly computed, but silently ignored) validation showed "That code is incorrect" at the same time. Because this module's own internal enrollment table correctly never flipped to "active" for that fake code, the affected account would then be **locked out entirely** at the next real login attempt (`challenge()` finds no active enrollment and refuses access) — a broken split state between what WHMCS core believed and what the module's own state actually was.

**Fixed:** `dct_totp_2fa_activateverify()`, `dct_email_2fa_activateverify()`, and `dct_whatsapp_2fa_activateverify()` now `throw new \WHMCS\Exception(...)` on every failure path (unavailable module, unresolved identity, missing/empty submission, and every non-"valid" verification status), and return `["settings" => []]` on success — matching native's confirmed contract exactly. `dct_totp_2fa`'s success return also drops the now-nonfunctional `"msg"` success text (WHMCS core does not display it, since native never returns one).

**Testing:** 69 new assertions (635 total, all passing) confirm every one of the three `activateverify()` functions throws on failure rather than returning a bare `"msg"` array, and returns `"settings"` on success. `php -l` clean on all three files.

**Action required if you deployed 3.1.18–3.1.20 and any client actually attempted TOTP/Email/WhatsApp 2FA enrollment with an incorrect code during that window:** check for accounts where `tblusers.second_factor` is set to one of `dct_totp_2fa`/`dct_email_2fa`/`dct_whatsapp_2fa` but the corresponding Security Pack enrollment table shows no `active` row for that user — those accounts are in the broken split state described above and are currently locked out of login. Clear `second_factor` back to empty for them (or have them re-enroll with a correct code under 3.1.21) to restore access.


## 3.1.20 — THE actual root cause: `tblusers_clients` schema mismatch (`userid`/`clientid` vs. the real `auth_user_id`/`client_id`)

3.1.18 and 3.1.19 each fixed a real, confirmed bug — but neither was the reason the Admin → Client Profile → Users "Two Factor Auth Method" column stayed "N/A". Live diagnosis (view-source on the reporting install) showed the injected mapping was well-formed but genuinely empty (`var security_pack_2fa_users = {};`), while a direct database query confirmed `tblusers.second_factor = 'dct_totp_2fa'` for the reported user — meaning the mapping *should* have included them.

### Root cause (confirmed via live `SHOW COLUMNS FROM tblusers_clients`)

Every join this codebase makes against the `tblusers_clients` junction table (`TwoFactorController::resolveUserIdsForClient()`, `Email2faService::resolveClientIdForUser()`, `WhatsAppTwoFactorService`'s own copy) was written against column names `userid`/`clientid` — based on undocumented WHMCS Community developer discussion, already flagged UNVERIFIED at the time it was written. A live `SHOW COLUMNS FROM tblusers_clients` on the reporting install (WHMCS 9.0.6) proved the real column names are **`auth_user_id`** and **`client_id`**. Every query against the assumed names has been silently failing (`#1054 - Unknown column`) and falling into this codebase's own try/catch fail-soft handling since this feature was first built — for the Admin Users display, that meant an always-empty user-ID list, hence an always-empty mapping, hence permanent "N/A" no matter how correct `tblusers.second_factor` was. For Email 2FA and WhatsApp 2FA specifically, this went unnoticed because both have a second fallback (matching `tblclients.email` directly) that kept working and silently masked the failed junction-table lookup.

### Fixed

- **`lib/Admin/TwoFactorController.php`**, **`lib/Security/Email2faService.php`**, **`lib/Security/TwoFactor/WhatsAppTwoFactorService.php`**: all three `tblusers_clients` lookups now resolve the real column names via `hasColumn()` at call time — preferring the confirmed-real `auth_user_id`/`client_id`, falling back to the originally-assumed `userid`/`clientid` only if those aren't present — rather than hardcoding either one as certain a second time.

### Testing

623/623 automated tests passing (620 + 3 new: source-level confirmation that all three call sites now resolve columns via `hasColumn()` rather than a hardcoded name, replacing the now-outdated hardcoded-column assertion). `php -l` clean across every file under `modules/`.

## 3.1.19 — SECOND confirmed live bug on the SAME page: the overlay script itself was 404ing (relative URL, wrong depth)

3.1.18 was deployed and the Admin → Client Profile → Users "Two Factor Auth Method" column STILL showed "N/A" for the same confirmed-active user. This is a second, independent bug underneath 3.1.18's fix — both had to be fixed for the feature to actually work.

### Root cause (confirmed)

The `<script src="...">` tag that loads `two_factor_admin_users.js` was built as a **relative** URL: `../modules/addons/security_pack/assets/js/two_factor_admin_users.js`. A relative URL resolves against the *browser's current address*, not the file's real location on disk. On an old-style, one-segment admin URL (`/ish_myadmin/clientssummary.php?userid=666037`), `../` happens to climb correctly to the WHMCS root. On this install's confirmed three-segment friendly URL (`/ish_myadmin/client/666037/users`), `../` only climbs out of the `users` segment, landing on a URL that doesn't exist — `.../ish_myadmin/client/modules/addons/...` — so the browser 404s loading the script and it never runs. The inline `<script>var security_pack_2fa_users = {...};</script>` tag (no `src`) is unaffected and still executed correctly — the mapping was right there in the page the whole time, but nothing ever loaded to read it and update the table. From the page's perspective this looks identical to "the hook never ran," the exact same symptom 3.1.18 fixed a different cause of. Neither this bug nor 3.1.18's was catchable by this suite's prior source-regex tests, since both are about how a **browser** resolves a URL relative to its own current address — not something visible from reading the PHP/JS text in isolation.

### Fixed

- **`core/two_factor_admin_display.php`**: added `security_pack_2fa_asset_base_url(): string`, which builds an **absolute** script `src` instead of a relative one. Prefers WHMCS's own configured `SystemURL` setting (`\WHMCS\Config\Setting::getValue("SystemURL")`) — the same authoritative base URL WHMCS itself already uses to build its own absolute asset URLs, completely independent of how many friendly-router path segments deep the current browser URL happens to be — and falls back to deriving the WHMCS root from `$_SERVER["SCRIPT_NAME"]` (the actual executing front-controller file, which stays fixed regardless of the friendly `REQUEST_URI` a rewrite rule presents to the browser) only if that setting is unavailable.

### Testing

620/620 automated tests passing (611 + 9 new: a pure mirror of the new resolver exercised against SystemURL-present, SystemURL-with-subfolder, root-install SCRIPT_NAME fallback, subfolder-install SCRIPT_NAME fallback, and fully-absent cases, plus source-level checks confirming the real function and the hook's script-src wiring match, and that the old relative `"../modules/` form is completely gone). `php -l` clean across every file under `modules/`.

## 3.1.18 — CONFIRMED LIVE REGRESSION FIX: Admin Users "Two Factor Auth Method" still showed N/A after 3.1.16 was deployed

Real, reported bug, confirmed already deployed: 3.1.16's server-side mapping (via the `AdminAreaFooterOutput` hook) shipped and was live on the reporting install, yet the Admin → Client Profile → Users column still showed "N/A" for a confirmed-active `dct_totp_2fa` user (the `Manage User` modal's native "Two-Factor Authentication: ON" toggle was on, confirming *some* module was active — just not reflected in the overlay).

### Root cause (confirmed)

The browser's address bar showed a clean, query-string-free URL: `/client/666037/users` — no `?userid=666037` anywhere. `core/two_factor_admin_display.php`'s hook resolved the viewed client ID exclusively from `$_REQUEST["userid"]`, which is only ever populated from an actual query-string/POST parameter. On this install's friendly-routed admin URLs, that parameter is never back-filled, so `$clientId` silently resolved to `0` and the mapping was always `{}` — indistinguishable, from the JS overlay's fail-soft design, from "the hook never ran at all". This is the same class of client-side-routing mismatch 3.1.9/3.1.11 already hit once for the (now-removed) AJAX endpoint URL — just resurfacing on the server side of the *replacement* mechanism instead of the client side.

### Fixed

- **`core/two_factor_admin_display.php`**: added `security_pack_2fa_resolve_viewed_client_id(): int`, a standalone resolver (kept outside the hook closure so it stays independently unit-testable) that tries `$_REQUEST["userid"]` first (unchanged — preserves any install where the classic query-string form is present) and, only if that yields nothing usable, falls back to parsing the numeric client ID directly out of the current request's own URL path (`REQUEST_URI`, then `PATH_INFO`, `REDIRECT_URL`, `PHP_SELF` in turn), matching a `/client/{id}/...` segment — the exact shape reproduced live. This is **not** "another AJAX endpoint URL guess" (there is still no AJAX request anywhere in this file, unchanged since 3.1.16) — it only reads the client ID out of the URL WHMCS itself already routed this authenticated admin session to, the same value WHMCS's own router derived to render the page in the first place. The admin-session gate (`$_SESSION["adminid"]`) is unchanged and still checked before any of this runs.

### Testing

611/611 automated tests passing (566 + 33 from 3.1.17 + 12 new: a pure mirror of the new resolver exercised against the exact live-reproduced URL shape and several edge cases — request-param-present, path-only, ID-as-last-segment, ID-followed-by-query-string, multi-superglobal fallback order, non-numeric `$_REQUEST["userid"]` falling through rather than short-circuiting, and the fully-empty/no-match case — plus source-level checks confirming the real function matches this logic and that no AJAX call was introduced alongside the fix). `php -l` clean across every file under `modules/`.

## 3.1.17 — REBUILD dct_totp_2fa: native WHMCS Security Module contract fix, OTP replay protection, recovery-code login

Full rebuild (not a patch) of `modules/security/dct_totp_2fa/`, using the real, decoded native WHMCS TOTP Security Module (`modules/security/totp/totp.php`) as the behavioral baseline, per an explicit rebuild ticket. Reuses every existing Security Pack TOTP/2FA service (`TotpService`, `TotpEnrollmentService`, `TotpKeyStore`, `TotpQrGenerator`, `RecoveryCodeService`, `TwoFactorAuthenticationService`, `TwoFactorBypassService`, `RateLimiter`) — no duplicate TOTP engine, key store, QR generator, recovery-code service, rate limiter, bypass service, or event logger was created. Full detail, native-vs-Security-Pack comparison, and honest disclosure of what was (and was not) verified live: see `TOTP-REBUILD-AUDIT.md`.

### Root cause (confirmed via the native reference)

`dct_totp_2fa_challenge()` returned its own nested `<form action="dologin.php">…</form>` — for BOTH the main code-entry path and the same-IP bypass auto-submit path — inside WHMCS's own outer login `<form>`. The real native `totp_challenge()` (deZender-decoded from WHMCS 9.0.6, confirmed genuine) proves this is wrong: a WHMCS Security Module's `challenge()` must return only bare form controls; WHMCS's own login page supplies the enclosing `<form>`, its CSRF token, its action, and its submit handling. A nested `<form>` corrupts the outer form's native behavior — the most likely true root cause of a long-reported "incorrect and not currently active simultaneously" garbled TOTP login screen.

### Fixed — challenge-form contract

- `dct_totp_2fa_challenge()` no longer emits any `<form>` tag, for either the main code-entry path or the bypass path. The main path returns a bare text input + submit button (matching the native reference's own bare `<div><input><input type="submit"></div>` shape). The bypass path returns a bare hidden `dct_totp_2fa_bypass=1` input plus a small script that submits the ENCLOSING form (`document.currentScript.closest("form")`, with a `document.forms[0]` fallback) — never a second form of its own.

### Added — OTP replay protection (previously absent)

- `TotpService::matchingStep()` — a new pure method returning the matched RFC 4226 HOTP counter (or `null`) for a submitted code, instead of a bare bool. `TotpService::verify()` is now defined purely in terms of it (`matchingStep(...) !== null`) — a zero-behavioral-regression refactor; every existing caller of `verify()` sees identical results.
- `nnm_security_pack_totp2fa.last_used_step` — one new nullable column on the EXISTING TOTP table (idempotent `hasColumn()`-guarded migration in `security_pack.php`; no new table, no re-encryption, no re-enrollment). `TotpEnrollmentService::verifyLogin()` now rejects a login code whose matched step is `<=` the account's stored `last_used_step` (status `"replayed"`, new `2fa.totp.replay_rejected` security event) and persists the new step on every accepted code. `verifyAndActivate()` (enrollment) also establishes the initial baseline, so the very first login afterwards has a real value to compare against.

### Added — recovery codes now actually usable at TOTP login (previously dead code)

- Audit finding: `TwoFactorAuthenticationService::attemptRecoveryCode()` (→ `RecoveryCodeService::attemptConsume()`) had **no caller anywhere in the codebase** — recovery codes were generable and displayable in the Client Security Center but could never actually be used to sign in.
- `dct_totp_2fa_verify()` now inspects the single challenge field: an exact 6-digit submission is tried as a TOTP code (via the now-replay-protected `TotpEnrollmentService::verifyLogin()`); anything else is tried as a recovery code via the existing, shared `TwoFactorAuthenticationService::attemptRecoveryCode()` — the same store, hashing, single-use consumption, and rate limiting every other 2FA method already relies on. No second recovery-code path was created.
- `dct_totp_2fa_verify()` no longer strips non-digit characters from the raw submission before deciding how to route it (that stripping is exactly what made recovery codes unusable here before); `dct_totp_2fa_activateverify()`'s own, separate, 6-digit-only enrollment-code parsing is untouched.

### Preserved, not rebuilt (per the rebuild ticket's own instruction)

Identity resolution (`dct_totp_2fa_login_identity()` / `dct_totp_2fa_account_identity()` / `dct_totp_2fa_resolve_type_for_id()`, 3.1.14/3.1.15), mutual exclusion (`TwoFactorAuthenticationService::activateExclusive("totp", …)` on activation), same-IP and administrator bypass (`TwoFactorBypassService::findActive()` / `grantSameIpBypass()`), the enrollment state machine (pending → active), QR/manual-secret enrollment (`TotpQrGenerator`, unchanged), and secret-at-rest encryption (`TotpKeyStore` + libsodium secretbox, unchanged) are all untouched.

### Testing

599/599 automated tests passing (566 existing + 33 new: RFC 6238 vector-based `matchingStep()`/replay tests, challenge-form bare-controls contract checks, recovery-code routing checks, `TotpEnrollmentService`/`security_pack.php` migration source checks, WHMCS-core-untouched check). Full `php -l` sweep of every `.php` file under `modules/` clean; `node --check` clean on all touched JS (none touched by this specific rebuild). **Not performed by this process**: the 18-step live acceptance test (ENROLLMENT → VERIFICATION → ACTIVATION → LOGOUT → LOGIN → TOTP CHALLENGE → VALID CODE → SUCCESSFUL LOGIN) on a real WHMCS installation — see `TOTP-REBUILD-AUDIT.md` for what this means and why it must be run by an administrator on the real install before declaring this feature complete.

## 3.1.16 — FINAL Admin Users 2FA display fix: removes the AJAX request entirely; bypass display made method-independent

Real, reported bug (with confirmed live evidence): Admin → Client Profile → Users still showed "N/A" for the Two Factor Auth Method column for User #666037, whose `tblusers.second_factor` is confirmed `dct_totp_2fa` and whose Security Pack Enrollment Overview confirms "Time-Based Token Active — 1 client(s)". The live browser Network trace showed the overlay's AJAX request (`POST /ish_myadmin/client/666037/addonmodules.php?module=security_pack&c=twoFactor&a=ajaxUsersTwoFactorStatus`) returning a 404 — the same class of failure 3.1.9/3.1.11 tried to fix by changing HOW the endpoint URL was derived. This release removes the AJAX request entirely instead.

### Root cause (final)

There was no reliable way to compute a working AJAX URL for this specific admin install's client-side-routed Client Profile page — neither a relative URL nor an absolute URL derived from `$_SERVER["SCRIPT_NAME"]` avoided the 404. Any URL-derivation strategy for this endpoint was fundamentally fragile on this install.

### Fixed — new architecture: server-side mapping, JS is pure DOM presentation

- **`core/two_factor_admin_display.php`** (`AdminAreaFooterOutput` hook): now computes the entire `{userId: {method, state}}` mapping SERVER-SIDE, for the real WHMCS Users belonging to the client currently being viewed, and injects it as a JSON page global (`window.security_pack_2fa_users`). The client is identified via `$_REQUEST["userid"]` — the same established parameter `core/loginHistory.php` already uses for the identical purpose, not a new guess. Gated on a real admin session (`$_SESSION["adminid"]`); fails closed to an empty mapping otherwise.
- **`lib/Admin/TwoFactorController.php`**: added `resolveUserIdsForClient()` (resolves real WHMCS User IDs for a client via the `tblusers_clients` junction table — the reverse direction of the existing, already-corroborated `Email2faService::resolveClientIdForUser()` lookup), `buildSecondFactorMapping()` (pure, unit-tested — builds the final mapping from an injected per-user `second_factor` resolver, omitting any user whose value isn't one of Security Pack's own three known modules), and `buildUsersTwoFactorMappingForClient()` (the DB-backed orchestrator: one batched query, fully fail-soft). **Removed**: `ajaxUsersTwoFactorStatus()`, `parseUserIdsParam()`, `buildUsersStatusMap()`, `resolveUserMethodStatus()`, `corroborateFromSecondFactorColumn()`, `methodStatusFromStatus()`, `buildAdminAjaxEndpointUrl()` — the entire AJAX mechanism, with no remaining trace in the dispatcher (`security_pack.php`'s `$bareOutputActions` no longer lists it).
- **Data source, per this ticket's explicit instruction**: the mapping is now built directly from `tblusers.second_factor` (via `labelFromSecondFactorModule()`, unchanged since 3.1.8) — not from `TwoFactorAuthenticationService::status()`. This is what the native column and WHMCS's own Manage User modal ("Two-Factor Authentication: ON") are themselves keyed on, so the display can never disagree with them. An unrecognized/empty `second_factor` value is omitted from the mapping entirely — the native "N/A" is left untouched, never overwritten with a guess.
- **`assets/js/two_factor_admin_users.js`**: now pure DOM presentation. Every row/User-ID detection selector is unchanged since 3.1.10 (already confirmed correct against the live markup) — only the final step changed: instead of `fetch()`-ing an endpoint, it reads `window.security_pack_2fa_users` synchronously. No `fetch()`, no `XMLHttpRequest`, no endpoint URL, no CSRF token, anywhere in the file. A missing mapping, or a User ID with no entry, leaves the native cell exactly as WHMCS rendered it.

### Fixed — Administrator Manual Bypass display made method-independent

Audited `TwoFactorBypassService` before changing anything, per this ticket's own instruction: confirmed the stored `method` column is explicitly "informational only" and a bypass "applies regardless of the configured method" — enforcement is NOT method-scoped. `TwoFactorAuthenticationService::createAdminBypass()` (what this UI's "Confirm Bypass" button calls) always tags bypasses `"manual"`, never a specific method; a same-IP auto-bypass tags the method that produced it, purely for audit. Displaying that raw value (e.g. "whatsapp") looked like the bypass only covered that one method, which is misleading. Added `TwoFactorController::bypassMethodLabel()`: the Method column now always leads with **"Any 2FA Method"**, with the originating method preserved as a parenthetical ("granted via whatsapp") only when it's genuinely known and isn't the generic "manual" tag. No stored bypass row is touched — this is a rendering change only.

### Testing

Replaces the entire prior AJAX-era test block (3.1.6–3.1.11's endpoint/URL-derivation tests, now testing removed code) with new coverage for the server-side mapping: `dct_email_2fa`/`dct_whatsapp_2fa`/`dct_totp_2fa`/empty/unknown `second_factor` mapping, User #666037 end-to-end, JSON mapping generation and HEX-escaping, duplicate/invalid User IDs, `rowPendingInvites` still ignored, `tr.user-item` still processed, no AJAX request/endpoint URL anywhere in the actual code (comments explaining the removed mechanism don't count), native "N/A" preserved when the mapping is unavailable, unauthorized/non-admin context failing safely, and the method-independent bypass display. **566/566 tests passing**, `php -l` and `node --check` clean across the full module tree.

### Manual verification (acceptance criteria from this ticket)

Open Admin → Client Profile → Users for User #666037 — the native column must show "Time-Based Token Two-Factor Authentication". No Network request to `/client/666037/addonmodules.php`, no 404, no "2FA endpoint request failed" console line (the whole request no longer exists). The Manage User modal must still show "Two-Factor Authentication: ON". Security Pack Authentication must still show "Time-Based Token Active — 1 client(s)". The Administrator Manual Bypass table must show "Any 2FA Method" rather than a raw method name.

## 3.1.15 — Fix: "Could not identify your account." blocking TOTP enrollment for a genuinely logged-in client

Real, reported bug (screenshot): a client, actively signed in and viewing their own client-area Security Settings page, clicked "Enable Two-Factor Authentication" and got the error modal **"Could not identify your account."** instead of the QR/secret enrollment screen.

### Root cause

`dct_totp_2fa_activate()`/`activateverify()` resolved identity purely from `dct_totp_2fa_context()` — i.e. `$_SESSION["adminid"]`/`$_SESSION["uid"]` only. For a genuinely authenticated client on their own account page, `$_SESSION["uid"]` returned nothing usable, so identity resolution failed even though WHMCS unambiguously knows who's logged in (that's the only reason the Security Settings page rendered at all). This is the same underlying lesson 3.1.14 already proved for `challenge()`/`verify()`: this module's own guess at which raw `$_SESSION` key holds the right value can miss real cases (for example, sub-account/contact logins, which don't always populate the same session key as a primary client) — while `$params["user_info"]["id"]`, which WHMCS itself builds for every Security Module call, reliably identifies who the call is actually for.

### Fixed

- Added `dct_totp_2fa_account_identity(array $params): array` — prefers `$params["user_info"]["id"]` (DB-checked for admin vs. client via the existing shared `dct_totp_2fa_resolve_type_for_id()`), and falls back to the session-based `dct_totp_2fa_context()` only when WHMCS didn't supply a usable id. Any install where the old session-only path already worked keeps working; the demonstrated failure case is fixed.
- `dct_totp_2fa_activate()` and `dct_totp_2fa_activateverify()` now use `dct_totp_2fa_account_identity($params)` instead of the raw `dct_totp_2fa_context()`.
- `dct_totp_2fa_login_identity()` (the pre-authentication resolver added in 3.1.14 for `challenge()`/`verify()`) is **unchanged** — it still never reads `$_SESSION` at all. The session-fallback behavior added here is exclusive to the new self-service resolver; reintroducing any session fallback into the login-time path would risk reopening the exact bug 3.1.14 just closed.

### Explicitly unchanged

`dct_totp_2fa_context()` itself, `dct_totp_2fa_login_identity()`, `TotpEnrollmentService`, `TwoFactorAuthenticationService`, `dct_email_2fa.php`/`dct_whatsapp_2fa.php` (same latent activate()-time session-only pattern likely exists there too, confirmed structurally similar via earlier grep, but not touched — scope stays TOTP-only, the method actually reported broken), and all 3.1.9–3.1.14 work.

### Testing

3 new source-inspection tests confirm `dct_totp_2fa_account_identity()` exists with the correct preference order (`user_info.id` first, DB type check, session fallback only when no id was supplied), that `activate()`/`activateverify()` now call it, and that `dct_totp_2fa_login_identity()` remains session-free and untouched. **587/587 tests passing**, `php -l` clean across the full module tree.

### Manual verification

As a genuinely logged-in client (including, if available, a sub-account/contact login), open Security Settings and click "Enable Two-Factor Authentication" for Time-Based Token — should show the QR/secret enrollment screen instead of "Could not identify your account." Confirm enrollment still completes and the account can log in with the resulting TOTP code afterward.

## 3.1.14 — Fix: TOTP client-login lockout caused by session bleed between the admin area and client area

Root cause **confirmed** from the first real capture of 3.1.13's diagnostic event (`2fa.totp.challenge_identity_mismatch`): a genuine client login attempt for account #666037 was resolved as **admin #9** instead — `params_user_info_id: 666037` (the exact correct client ID, and the only identity WHMCS actually supplied for that specific login request) vs. `resolved_type: "admin", resolved_id: 9`.

### Root cause

`dct_totp_2fa_context()` checked `$_SESSION["adminid"]` first, unconditionally, before ever considering the identity WHMCS actually passed for the current request. WHMCS shares a single PHP session between the admin area and the client area on the same domain — so an admin who simply had an active, unrelated admin panel session open in the same browser had `$_SESSION["adminid"]` silently override the real client login's identity at `challenge()`/`verify()` time. Trusting session state there was never sound to begin with: those two callbacks run **pre-authentication** — for a genuine admin login, 2FA is challenged *before* `$_SESSION["adminid"]` is ever set — so any session state present at that point can only be stale leftovers from a different, unrelated login, never a signal about the login actually in progress.

### Fixed

- Added `dct_totp_2fa_login_identity(array $params): array` — resolves identity **exclusively** from `$params["user_info"]["id"]` (the value WHMCS supplies specifically for the current login attempt) plus a DB-based admin/client check (`dct_totp_2fa_resolve_type_for_id()`, extracted from the existing fallback logic, now shared). It never reads `$_SESSION`.
- `dct_totp_2fa_challenge()` and `dct_totp_2fa_verify()` — the two pre-authentication login callbacks — now use `dct_totp_2fa_login_identity($params)` instead of the session-priority `dct_totp_2fa_context($userId)`.
- `dct_totp_2fa_context()` itself is **unchanged** and still used by `dct_totp_2fa_activate()`/`activateverify()` — correct there, since those run *post*-authentication, when the account owner is already logged in and enrolling their own account, so `$_SESSION["adminid"]`/`["uid"]` genuinely does identify them.
- The 3.1.13 diagnostic logging (`dct_totp_2fa_log_challenge_mismatch()` / event `2fa.totp.challenge_identity_mismatch`) is kept in place as a safety net — it should now only fire for a genuinely inactive/never-enrolled account, and remains available to catch any other identity-resolution edge case that surfaces later.

### Explicitly unchanged

`TwoFactorAuthenticationService`, `TotpEnrollmentService`'s own lookup logic, `dct_email_2fa.php`/`dct_whatsapp_2fa.php` (confirmed via grep to share the identical latent session-priority pattern, but **not** touched here — this fix is scoped strictly to TOTP, the method actually reported broken; the same class of bug in Email/WhatsApp 2FA can be addressed as a follow-up if it's ever reported), and the entire 3.1.9–3.1.12 Admin Users display / dispatcher-crash work.

### Testing

6 new source-inspection tests confirm `dct_totp_2fa_login_identity()` exists and never reads `$_SESSION`, that `challenge()`/`verify()` now call it instead of the session-priority resolver, that `activate()`/`activateverify()` correctly still use the session-based resolver, and that the DB-based type check is centralized in one shared helper rather than duplicated. **584/584 tests passing**, `php -l` clean across the full module tree.

### Manual verification

Reproduce the exact original failure condition — an admin with an active admin panel session, in the same browser, attempting (or having a client attempt) a client-area TOTP login for an account with a genuinely active enrollment — and confirm the login now succeeds instead of showing "not currently active." A normal client login (no coexisting admin session) should be unaffected, since it never depended on `$_SESSION["adminid"]` in the first place.

## 3.1.13 — Diagnostic-only step toward the TOTP client-login lockout bug (root cause NOT yet confirmed)

Real production bug, reported via screenshots (no accompanying text): the client-facing login screen for account #666037 shows "Time-Based Token Two-Factor Authentication is not currently active for this account. Please contact an administrator." — a full login lockout — even though Security Pack's own admin Authentication → Enrollment Overview confirms an active TOTP enrollment for that account (1 client, 0 admins).

**This release does NOT change any login behavior.** Per this project's own repeatedly-applied "confirm with live evidence before touching security-critical code" discipline, and per the explicit answer given when asked whether to proceed ("...reporting back what was found before making changes if it touches core 2FA logic"), the previously-protected TOTP Security Module provider code (`modules/security/dct_totp_2fa/dct_totp_2fa.php`) was touched **only to add diagnostic logging**, not to change how login decisions are made.

### What was investigated

`dct_totp_2fa_challenge()` and `dct_totp_2fa_verify()` are WHMCS Security Module callbacks that run **pre-authentication** — no client-area session (`$_SESSION["uid"]`) exists yet at that point. The only identity source available is `$params["user_info"]["id"]`, a value whose exact contents at this specific call point is an undocumented WHMCS Security Module contract detail that has been disclosed-but-unverified since 2.6.1. `dct_totp_2fa_context()` resolves an identity from `$_SESSION["adminid"]`/`$_SESSION["uid"]`/that fallback, and `TotpEnrollmentService::isActive()`/`verifyLogin()` look up the enrollment by an **exact** `(user_id, user_type)` match against that resolved identity. If the identity resolved at challenge/verify time doesn't exactly match the identity the enrollment was stored under, the enrollment silently looks "not active" even though it genuinely is — this is the leading hypothesis, but it is **unconfirmed** without a live reproduction.

### Added

- `dct_totp_2fa_log_challenge_mismatch(array $params, array $context): void` — a new, strictly non-sensitive diagnostic helper in `dct_totp_2fa.php`. It records one `security_pack_record_event()` entry (type `2fa.totp.challenge_identity_mismatch`, severity `warning`) containing only: the raw `$params["user_info"]["id"]` value (a WHMCS User/Client ID, not a credential), the top-level `$params` keys actually present, and the `(type, id)` this module resolved. It **never** logs the submitted TOTP code, `post_vars`, or any 2FA secret, and is fully fail-soft — guarded by `function_exists("security_pack_record_event")` and wrapped in `try/catch(\Throwable)`, so it can never itself cause a login failure.
- The helper is called from `dct_totp_2fa_challenge()` right before it returns the "not currently active" warning, and from `dct_totp_2fa_verify()` when `TotpEnrollmentService::verifyLogin()` reports `no_challenge` — the two points where this exact bug symptom is produced.

### Explicitly unchanged

`TwoFactorAuthenticationService::status()`, `TotpEnrollmentService`'s own lookup logic, `dct_totp_2fa_context()`'s identity-resolution logic, every other 2FA architecture class from prior tickets, and the entire 3.1.9–3.1.12 Admin Users display / dispatcher-crash fixes. `dct_email_2fa.php` and `dct_whatsapp_2fa.php` have the identical `$params["user_info"]["id"]` pattern (confirmed via grep) but were **not** touched — this pass is scoped strictly to the one method actually reported broken (TOTP, the account's currently-active method).

### Testing

6 new source-inspection tests confirm the diagnostic helper exists with the correct signature, is called from both `challenge()` and `verify()` at the right points, never references the submitted code/`post_vars`/secrets while logging the four intended non-sensitive fields, is fully fail-soft (`function_exists()` guard + `try/catch(\Throwable)`), and records the specific greppable event type `2fa.totp.challenge_identity_mismatch`. **578/578 tests passing**, `php -l` clean across the full module tree.

### Next step (requires the user)

Attempt the TOTP login again — it will still show the same "not currently active" message, since no behavior changed yet. Then check Security Pack's Activity/Security Event log (or the WHMCS Module/Activity Log) for the new `2fa.totp.challenge_identity_mismatch` event and report back its `params_user_info_id`, `params_top_level_keys`, `resolved_type`, and `resolved_id` values. That evidence will confirm (or rule out) the identity-mismatch hypothesis and let the real fix be applied with confidence in the next round.

## 3.1.12 — Fix: fatal "Call to private method ... from global scope" crash on Two-Factor Authentication Save/Bypass/Revoke

Real production bug, reported with a full stack trace: `Error: Call to private method WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController::save() from global scope in security_pack.php:959`, triggered by submitting the "Policy" Save form on Security Pack → Authentication → Two-Factor Authentication.

### Root cause

`security_pack_output()`'s admin action dispatcher decided whether to call a controller action method directly using `method_exists($controller, $action)`. `method_exists()` reports a hit regardless of the method's **visibility** — so when `$_REQUEST["a"]` was `save` (or `bypass`, or `revoke`), the dispatcher tried `$controller->save($vars)` directly from this plain global function, even though `TwoFactorController::save()`/`bypass()`/`revoke()` are `private` by design (meant to be called only from inside `TwoFactorController::index()`'s own `$_REQUEST["a"]` switch). PHP fatal-errors on a private-method call from outside the class's own scope — crashing the entire admin page render for that request, which is why the Policy Save button, and the Bypass/Revoke buttons on the same page, all failed identically.

### Fixed

- `security_pack_output()` (admin dispatcher) and `security_pack_clientarea()` (client-area dispatcher) both switched from `method_exists($controller, $action)` to `is_callable([$controller, $action])`. `is_callable()` is visibility-aware **from the calling scope** — called from this plain global function (outside the controller class), it correctly returns `false` for a private or protected method, so the dispatcher now falls through to `$controller->index($vars)` exactly as intended, instead of attempting (and crashing on) a direct call. `TwoFactorController::index()` already routes `a=save`/`a=bypass`/`a=revoke` internally via its own switch, so this fully restores the Policy Save and Bypass/Revoke buttons without changing any of that controller's own logic.
- No behavior change for any action that's genuinely public (e.g. `TwoFactorController::ajaxUsersTwoFactorStatus()`, or any other controller's public action methods) — `is_callable()` and `method_exists()` agree for those.

### Explicitly unchanged

Every 2FA architecture class the prior tickets protected (`TwoFactorAuthenticationService`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, all three `*TwoFactorProvider` classes, `OtpEngine`, `RateLimiter`), plus the entire 3.1.9/3.1.10/3.1.11 Admin Users 2FA display fix. This was a dispatcher-level bug in `security_pack.php` only.

### Testing

4 new tests confirm `save()`/`bypass()`/`revoke()` remain `private` (proving the old dispatch was unsafe), that both dispatchers now use `is_callable([$controller, $action])` with zero remaining `method_exists($controller, $action)` call sites, and that `TwoFactorController::index()`'s own internal routing for those three actions is untouched. **572/572 tests passing**, `php -l` clean across the module tree.

### Manual verification

On Security Pack → Authentication → Two-Factor Authentication: toggle "Require Two-Factor Authentication" and click Save — should redirect back with "Saved Successfully!" instead of a fatal error. Submit the Administrator Manual Bypass form and Revoke an existing bypass — both should now complete normally as well.

## 3.1.11 — Deployment-cache defense: version-tagged JS asset + confirmed debug output wording

A follow-up inspection of the actual JS file being served on the reported install proved that the 3.1.9/3.1.10 fixes were correct but had **not actually reached the browser yet** — the deployed `two_factor_admin_users.js` was still pre-3.1.9 code. This was proven from the debug output's exact wording: `Malformed row (fewer cells than the header expects)` for `rowPendingInvites` and `Rows detected: 2` only exist in code from *before* 3.1.9's `isSkippableRow()` fix and 3.1.10's `tr.user-item` selector existed at all — current code logs `Skipping known non-user row...` and `User rows detected: N (tr.user-item)` instead. This is a deployment/caching problem, not a code defect, but it can be defended against directly.

### Fixed

- `core/two_factor_admin_display.php`'s injected `<script src>` now carries a deterministic `?v=<version>` query string built from `security_pack_config()["version"]` — never a random or time-based value, so repeat requests for the *same* version still cache normally, but an actual version bump forces browsers/proxies to fetch the new file instead of silently continuing to serve a stale cached copy.
- `assets/js/two_factor_admin_users.js` now logs an explicit `Using server-provided endpoint:` line before the fetch call (previously `AJAX endpoint:`), matching the exact debug-output wording requested for verification.

### Explicitly unchanged

The 3.1.9 absolute-endpoint-URL fix, the 3.1.10 confirmed-markup row/User-ID selectors, `TwoFactorAuthenticationService`/`activateExclusive()`/`enforceSingleActiveMethod()`/`TwoFactorBypassService`/all three `*TwoFactorProvider` classes, `OtpEngine`, `RateLimiter`, `GeoIpManager`, `CountryRestrictionService` — none of these needed any change; the 3.1.9/3.1.10 code was already correct, it just wasn't live on the reported install yet.

### Testing

4 new tests: the injected asset src carries the deterministic version query string (never `rand()`/`time()`/`uniqid()`), the asset src remains `htmlspecialchars`-escaped, the JS logs the exact `Using server-provided endpoint:` wording, and a failed/non-2xx AJAX response's catch handler never writes to `cell.textContent` (native "N/A" is provably preserved on failure). **568/568 tests passing**, `php -l` clean, `node --check` clean.

### Manual verification

After deploying this zip (overwriting the old files on the server), reload `/ish_myadmin/client/666037/users?sp2fa_debug=1` and confirm: the `<script src>` for `two_factor_admin_users.js` now ends in `?v=3.1.11`; the console shows `User rows detected: 1 (tr.user-item)` (not `Rows detected: 2`); no `Malformed row` message for `rowPendingInvites`; the AJAX request goes to `/ish_myadmin/addonmodules.php?...` (not `/ish_myadmin/client/666037/addonmodules.php`) and returns 200; the log shows `Using server-provided endpoint: ...`; and the "Two Factor Auth Method" cell changes from `N/A` to the authoritative method for User 666037 (currently reported as `dct_totp_2fa` → "Time-Based Token Two-Factor Authentication").

## 3.1.10 — Admin Users 2FA overlay now matches the confirmed live DOM exactly (row/User-ID/column detection)

A live DOM + Network trace from the actual reported account (User ID 666037) confirmed the exact real markup this overlay runs against: the Users table is `<table id="userTable" class="datatable">`, real user rows are `<tr class="user-item">`, and the WHMCS User ID is exposed directly via `data-user-id` on the row's `.name`/`.email` spans and the Manage User button (e.g. `<span class="name" data-user-id="666037">`). This confirms User ID extraction itself was already working correctly (as established in 3.1.9) — this version replaces the broader 3.1.7 markup guesses with the confirmed, exact selectors, while keeping every prior broader check as a fail-soft fallback for installs/themes that don't match this confirmed markup.

### Changed

- `processTable()` now selects rows via the confirmed `tbody tr.user-item` selector first. This automatically excludes the known hidden `rowPendingInvites` row (and any other non-`.user-item` row) structurally — it simply never becomes a row candidate, with no reliance on `isSkippableRow()` for that case. If a table has **no** `.user-item` rows at all (a different theme/markup), the overlay falls back to the prior 3.1.9 behavior — scanning every `tbody tr` filtered by `isSkippableRow()` — rather than silently processing nothing.
- `extractUserId()` now checks the confirmed `.name[data-user-id]` markup (falling back to any `[data-user-id]`) via a new `extractUserIdFromConfirmedMarkup()` helper **first**, returning that value immediately when present. The previous multi-candidate scan (hidden `input[name='userid']`, `href`/`formaction`/`action`/`onclick` `"userid="` parsing) is now consulted only as a **fallback** when no `data-user-id` is present — matching the ticket's explicit "the Manage User href can remain a fallback only" instruction.
- Column detection (`findTargetColumnIndex()`, matching the real `<th>Two Factor Auth Method</th>` header text) is unchanged — already correct and confirmed live, so it was not touched.
- Debug logging (`?sp2fa_debug=1`) expanded with `AJAX endpoint:`, `endpoint response:`, `method:`, and `cell updated` log lines so a debug session's console output now mirrors the exact flow end-to-end.

### Explicitly unchanged

- The 3.1.9 fix for the AJAX endpoint URL itself (`TwoFactorController::buildAdminAjaxEndpointUrl()`, computed from `$_SERVER["SCRIPT_NAME"]`, injected as `security_pack_2fa_users_endpoint`) — already confirmed correct and untouched here.
- `TwoFactorAuthenticationService`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, and all three `*TwoFactorProvider` classes — never modified. This remains purely an Admin Users display/integration fix.
- Endpoint security (authenticated admin session, POST, CSRF, valid User ID, response shape) — unchanged.

### Testing

9 new regression tests covering: the confirmed `tbody tr.user-item` row selector, the fallback-to-`tbody tr` behavior when no `.user-item` rows exist, the confirmed `data-user-id` extraction path and its priority over the fallback scan, `rowPendingInvites` exclusion under both paths, and regression guards re-confirming the 3.1.9 absolute-URL fix, the WhatsApp mapping, endpoint auth/POST requirements, and safe failure on an unknown User ID. **564/564 tests passing**, full `php -l` clean across the module tree, `node --check` clean on the JS overlay.

### Manual verification

For the reported account (User ID 666037, `second_factor: dct_whatsapp_2fa`): reload the Admin Client Profile → Users tab with `?sp2fa_debug=1`, confirm the console shows `User rows detected: 1 (tr.user-item)` and `User ID detected: 666037`, confirm the AJAX request still goes to `/ish_myadmin/addonmodules.php?...` (not `/ish_myadmin/client/666037/addonmodules.php?...`), and confirm the "Two Factor Auth Method" column now shows "DCTLAB WhatsApp Two-Factor Authentication" instead of "N/A". Also confirm no "Malformed row" log line appears for `rowPendingInvites`.

## 3.1.9 — Fix confirmed: Admin Users 2FA overlay's AJAX request was 404ing (relative URL resolved against a client-side-routed Client Profile URL)

**This is the actual root cause of the "N/A" that survived 3.1.6/3.1.7/3.1.8.** The user supplied definitive live debug output from the real Admin Client Profile > Users page: the overlay correctly initialized, correctly found the Users table, correctly detected 2 rows, and correctly extracted User ID 666037 — everything through User ID extraction was working. The failure was the AJAX request itself: it was sent to `https://indianserverhosting.com/ish_myadmin/client/666037/addonmodules.php?module=security_pack&c=twoFactor&a=ajaxUsersTwoFactorStatus` and got a 404, because the correct endpoint is `https://indianserverhosting.com/ish_myadmin/addonmodules.php?...` — no `/client/666037/` segment. The overlay's `fetch()` call used a relative URL (`"addonmodules.php?..."`), and the browser resolved that relative URL against whatever it currently believed the document URL to be — on this install's Admin Client Profile page, that's an apparently client-side-routed `/client/{id}/...` URL, not the physical script that actually rendered the page.

### Fixed

- New pure helper `TwoFactorController::buildAdminAjaxEndpointUrl(string $scriptName, string $moduleQuery): string` computes the ABSOLUTE admin AJAX endpoint path from `$_SERVER["SCRIPT_NAME"]` — the real, physical PHP script WHMCS executed to render the current response — via `dirname()`. `SCRIPT_NAME` is unaffected by any client-side routing that happens in the browser afterward, so this is safe regardless of whether the admin area uses friendly/pretty URLs, and it works at any subdirectory depth (`/ish_myadmin/`, `/admin/`, `/billing/whmcs-admin/`, a root-level install, etc.) without ever hardcoding a specific admin directory name or matching against a `/client/{id}/` pattern (per the explicit "do not use a blind string replace" instruction).
- `core/two_factor_admin_display.php`'s `AdminAreaFooterOutput` hook now calls this helper once per page load and injects the resulting ABSOLUTE URL into the page as a new JS global, `security_pack_2fa_users_endpoint`, alongside the existing `security_pack_token`.
- `assets/js/two_factor_admin_users.js`'s `fetch()` call now uses `window.security_pack_2fa_users_endpoint` directly instead of a relative URL string. If that global is missing or empty for any reason, the overlay makes **no** request at all and leaves the native cell untouched — it deliberately does **not** fall back to a relative/derived URL, since that is the exact confirmed-broken behavior this version fixes.

### Also fixed — hidden non-user rows no longer treated as errors

The same live debug output also showed `[Security Pack 2FA overlay] Malformed row` for `<tr id="rowPendingInvites" class="hidden">` — a real WHMCS row that doesn't represent a user at all (a hidden "pending invites" placeholder row). New `isSkippableRow()` in the JS overlay checks for this specific row ID, plus the general cases of a `hidden` attribute, a `"hidden"` CSS class, or an explicit `display:none` — and skips these rows **before** any cell-count validation or User ID extraction is attempted, so they're never logged as malformed and never trigger an AJAX call. Real, visible User rows are structurally unaffected since they never match any of these conditions.

### Explicitly unchanged, per this ticket's own "ARCHITECTURE" section

`TwoFactorAuthenticationService`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, and all three `*TwoFactorProvider` classes are completely untouched. The endpoint's existing security (authenticated admin session, POST-only, CSRF, `tblusers` existence check, the `{success, method, state}` response shape, and the 3.1.8 `tblusers.second_factor` corroboration fallback) are all unchanged — only how the endpoint's URL is *constructed* changed, not what it does or how it's protected. User ID extraction logic in the JS is also unchanged this round (it was already proven correct by the live debug evidence).

### Testing

14 new tests (555/555 total, up from 541/541): `buildAdminAjaxEndpointUrl()`'s exact output for the reported install's real path plus several other admin subdirectory depths (proving no hardcoded directory name and no assumed `/client/{id}/` pattern), a root-level-install case, source checks that the hook derives the URL from `$_SERVER["SCRIPT_NAME"]` (never `REQUEST_URI`) and that the actual hook code (its docblock's discussion of the confirmed bug aside) never hardcodes `ish_myadmin` or a `/client/` pattern, a source check confirming the endpoint URL is injected as `security_pack_2fa_users_endpoint`, a regression guard that the endpoint is still admin-session- and POST-protected, re-confirmation of the `dct_whatsapp_2fa` → "DCTLAB WhatsApp Two-Factor Authentication" mapping for the exact reported account, JS source checks that `rowPendingInvites` and the general hidden-row conditions are recognized and skipped before any cell-count/extraction/AJAX step, a JS source check that the fetch call uses the injected absolute URL (never a relative `"addonmodules.php?..."` literal, never `window.location.pathname`), and a JS source check that a missing endpoint URL results in no request being made at all. Existing 541 tests unchanged and still passing. `php -l` clean across every changed file and a full sweep of the module tree.

### Manual verification

On the real installation: Admin → Client Profile → Users, with `?sp2fa_debug=1` enabled, confirm the AJAX request now goes to `/ish_myadmin/addonmodules.php?module=security_pack&c=twoFactor&a=ajaxUsersTwoFactorStatus` (not `/ish_myadmin/client/666037/addonmodules.php?...`), returns HTTP 200 with `{"success": true, "method": "DCTLAB WhatsApp Two-Factor Authentication", "state": "active"}` for User ID 666037, and that the "Two Factor Auth Method" column now shows that label instead of "N/A". Also confirm the `rowPendingInvites` row produces no warning and no AJAX request. This session still has no live browser/credentials access, so this fix — unlike the prior three passes — is built directly from the user's own definitive live evidence rather than reasoned about blind; it should be the one that actually closes this out, but manual confirmation against the real account is still the deciding test.

## 3.1.8 — Admin Users 2FA display: use confirmed live WHMCS evidence (`tblusers.second_factor`) as a corroborating fallback

**New evidence, not a new guess**: the user supplied real, live browser evidence from the actual WHMCS Admin Client Profile > Users page — a console object `{"second_factor": "dct_whatsapp_2fa"}` for the exact reported account. Grepping this module's entire source tree for `second_factor` before this change returns zero matches — this value is **not** produced by any Security Pack code (JS or PHP); it is a genuine WHMCS-native field, most plausibly `tblusers.second_factor`, the column WHMCS's own `modules/security/` Security Module interface uses to record which security module a User has activated (the same undocumented-but-real interface investigated back in 2.6.1 — see `whmcs_stack.md`). This is now treated as confirmed live evidence, not an assumption, and is used accordingly: as a corroborating signal, never a replacement for the authoritative service.

**What changed**: `TwoFactorController::resolveUserMethodStatus()` is unchanged in the case that matters most — whenever `TwoFactorAuthenticationService::status()` (still the ONE authoritative source, untouched) already resolves an active or pending method, the response is built exactly as before. The only new behavior: when `status()` finds **nothing** (would have shown "Not Enabled"), the endpoint now takes one extra, fail-soft look at `tblusers.second_factor` for that same User ID. If it holds one of Security Pack's own three known security-module directory names, that fills the gap:
- `dct_email_2fa` → "Email Two-Factor Authentication"
- `dct_whatsapp_2fa` → "DCTLAB WhatsApp Two-Factor Authentication"
- `dct_totp_2fa` → "Time-Based Token Two-Factor Authentication"

Any other value — an unrecognized module, WHMCS's own built-in methods (`totp`, `duo`, `yubikey`, etc.), empty, or null — is never trusted and leaves the "Not Enabled" answer exactly as the authoritative service computed it. This mapping lives in a new pure function, `TwoFactorController::labelFromSecondFactorModule()`, unit tested directly for all three known values plus every "must not guess" case. The corroboration read itself (`corroborateFromSecondFactorColumn()`) is fully fail-soft — a missing column on some installs, or any DB error, returns null and the response falls straight back to the authoritative service's own answer; it can never contradict or override an "active"/"pending" result `status()` already returned, and it never fabricates a "pending" state (Section "IMPORTANT": "Do not hard-code WhatsApp as the active method... The mapping must be based on the actual value... or, if the existing Security Pack endpoint has already resolved the authoritative status, use that authoritative status").

**Explicitly out of scope, per the ticket's own "ARCHITECTURE" section**: `TwoFactorAuthenticationService::status()`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, and all three `*TwoFactorProvider` classes are completely untouched. User ID extraction in `assets/js/two_factor_admin_users.js` is also untouched this round — the ticket was explicit not to touch it "unless the endpoint proves that the wrong User ID is being queried," and this session has no way to prove that (see below).

**Traced the requested chain, honestly, as far as this session can**: `actual User → second_factor → User ID → Security Pack endpoint → method/state response → method-name mapping → Two Factor Auth Method cell`. Everything from "Security Pack endpoint" onward was re-read line by line this pass and no bug was found: `ajaxUsersTwoFactorStatus()` correctly requires an authenticated admin session and POST+CSRF, `parseUserIdsParam()`/`buildUsersStatusMap()` are unchanged and correctly keyed, `methodStatusFromStatus()`'s `active_method` mapping (`"email"`/`"whatsapp"`/`"totp"`) matches `TwoFactorAuthenticationService::providers()`'s own keys exactly, the admin dispatcher (`c=twoFactor` → `TwoFactorController`, `ajaxUsersTwoFactorStatus` in `$bareOutputActions` so no page chrome wraps the JSON) is correctly wired, and the JS's `fetch()` URL/body and its `entry.success === true` gate on the response both match the endpoint's real shape. **What this session still cannot verify**: whether the affected row's User ID is being extracted correctly at all, and whether the fetch is actually reaching the endpoint for that row — both require literally watching the live page (Network tab / `?sp2fa_debug=1` console output), which remains unavailable in this session. If the column still shows "N/A" after this version, that is now the most likely remaining place to look — see "If it still doesn't work" below.

**Testing**: 9 new tests (541/541 total, up from 532/532): `labelFromSecondFactorModule()`'s exact mapping for all three known values, confirmation an unrecognized value (including WHMCS's own built-in `"totp"`) or an empty/null value is never trusted, a source check that the corroboration is gated strictly behind `$result["state"] === "inactive"` (can never override an active/pending answer), a source check that `corroborateFromSecondFactorColumn()` reads `second_factor` and is fully try/catch-wrapped, and a source check that it only ever produces `"active"`, never a fabricated `"pending"`. Existing 532 tests unchanged and still passing. `php -l` clean across every changed file and a full sweep of the module tree.

**If it still doesn't work**: this corroboration fix can only help if the real problem is a provider/status mismatch — it cannot fix a User-ID-extraction or DOM-detection failure, which remains the more likely root cause given "N/A" (not "Not Enabled" or any other wrong-but-present value) is what's still showing. The most useful next piece of evidence would be the `?sp2fa_debug=1` console output from the real Users tab page for this exact account (shows whether a User ID was even detected for that row, and if so what the endpoint actually returned for it) — or the raw outerHTML of the Users table row in question. Both would let the next pass target the real markup directly instead of reasoning about it from one console object.

## 3.1.7 — Debug/harden the Admin Users-tab 2FA display fix — 3.1.6 shipped but the reported account still showed "N/A"

**The report**: after 3.1.6 shipped, the user confirmed the exact reported account (Domain Manager / webnetwork20@gmail.com, Client #666037, DCTLAB WhatsApp 2FA = ACTIVE) **still** showed "N/A" in the "Two Factor Auth Method" column on Admin > Client Profile > Users. 3.1.6's `assets/js/two_factor_admin_users.js` overlay was built on two assumptions that were disclosed at the time as unverified against a live install: that the Users tab renders on a page whose filename is `clientssummary`, and that each row's Manage-user link carries the User ID in a `userid=` URL parameter. Both assumptions were wrong for this WHMCS install, or wrong often enough that no row was ever being resolved, so the overlay never had a chance to replace "N/A" with anything.

**What this session could and could not do about it**: the follow-up instructions were explicit that the live rendered markup should be inspected directly — table selector, header text, row structure, and exactly where each row's User ID actually lives — rather than continuing to guess. This session has no live browser or credentials access to the WHMCS install (`indianserverhosting.com`), and an attempt to reach it via the Claude-in-Chrome browser tool in this session returned "Browser extension is not connected." **The actual live markup was not inspected for this build.** Given the explicit "never guess" instruction, the fix below is deliberately not another guess at a different specific markup shape — instead it removes the previous guess and broadens detection to check every plausible location safely, refusing to act at all where it can't be sure, and adds an opt-in way for the user to hand back real diagnostic data if this still isn't enough.

### Changed

- `core/two_factor_admin_display.php`: removed the `App::getCurrentFilename() === "clientssummary"` gate entirely. The script's own real safeguard — it only ever acts on a table whose header literally contains "Two Factor Auth Method" — was always the actual gate that mattered; the filename check was an extra, unverified assumption that could silently prevent the whole feature from running if wrong. The JS now loads on every admin page; on any page without that column it does nothing.
- `assets/js/two_factor_admin_users.js` — `extractUserId()` rewritten to check far more of the places a WHMCS row plausibly carries its User ID: `data-userid`/`data-user-id`/`data-uid` attributes, a hidden `userid` form field, and every `href`/`action`/`formaction`/`onclick` attribute on any anchor, form, button, or clickable element in the row, matched against a `userid=` pattern. If more than one of these signals is found and they **disagree**, the row is treated as ambiguous and is left completely unchanged — per the explicit "if the User ID cannot safely be determined, leave the cell unchanged as N/A. Never guess" instruction — rather than picking one candidate.
- `assets/js/two_factor_admin_users.js` — added a `MutationObserver` on `document.body` in case the Users tab content renders or is replaced asynchronously (Lagom2/AJAX tab loading) after the page footer script first runs. Each table is marked with a `data-sp2fa-processed` attribute the moment it's dispatched for lookup, so a re-triggered mutation can never re-process the same table, call the endpoint again for it, or create a polling loop — matching the explicit "do not create a polling loop" constraint.
- `assets/js/two_factor_admin_users.js` — added opt-in diagnostic logging, off by default, enabled only by appending `?sp2fa_debug=1` to the admin URL. When enabled it logs (via `console.debug`, prefixed `[Security Pack 2FA overlay]`): that the overlay initialized, that the Users table was found, the row count, each resolved User ID, ambiguous-candidate and malformed-row skips, and the raw JSON the endpoint returned for a batch. It never logs an OTP, TOTP secret, API credential, recovery code, or authentication token — the endpoint response it logs is already restricted to `{success, method, state}` (see below), so there is nothing sensitive in scope to log in the first place.
- `lib/Admin/TwoFactorController.php` — `ajaxUsersTwoFactorStatus()` now returns, per requested User ID, exactly the shape given in the report: `{"success": true, "method": "DCTLAB WhatsApp Two-Factor Authentication", "state": "active"}` (or `{"success": false}` if the ID doesn't correspond to a real `tblusers` row, `TwoFactorAuthenticationService::status()` throws, or the ID is non-positive) — replacing 3.1.6's plain-string response. `resolveUserMethodLabel()`/`methodLabelFromStatus()` are replaced with `resolveUserMethodStatus()`/`methodStatusFromStatus()`, which now first confirm the User ID exists in `tblusers` before ever calling `TwoFactorAuthenticationService::status()`, so an invalid/guessed/mismatched ID always yields `{"success": false}` — never a default or fabricated label. The `state` value (`"active"` / `"pending"` / `"inactive"`) is new; the display-label logic and its authoritative source (`TwoFactorAuthenticationService::status()`, still the only place 2FA state is read from) are otherwise unchanged from 3.1.6.

### Explicitly not done

- No new markup assumption was substituted for the removed `clientssummary`/`userid=` ones — per the "never guess" instruction, broader-but-still-uncertain detection was chosen over a second specific guess.
- No change to `TwoFactorAuthenticationService`, `TwoFactorBypassService`, or any 2FA provider — the authoritative status source and its behavior are exactly as before. This is entirely an integration/detection-layer fix, not a change to how 2FA state is computed.
- Nothing is hardcoded — "DCTLAB WhatsApp Two-Factor Authentication" (or any other label) only ever reaches a cell via `TwoFactorAuthenticationService::status()`'s real return value for that row's real, safely-resolved User ID.

### Testing

- 7 new tests (532/532 total, up from 525/525): `methodStatusFromStatus()`'s exact `{method, state}` output for active Email/WhatsApp/TOTP, no active/no pending, unrecognised active_method, and pending TOTP; `buildUsersStatusMap()`'s per-user isolation against the new object-shaped responses; `resolveUserMethodStatus()` source checks confirming a non-positive User ID short-circuits to `{"success": false}` before any database call, that a `tblusers` existence check gates every lookup, and that its catch block returns `{"success": false}` rather than a guessed label; confirmation the AJAX endpoint requires an authenticated admin session; confirmation the JS never uses a Client ID as a User ID and never references bypass state; a JS source check that ambiguous User ID candidates are detected and logged rather than guessed at; a JS source check that processed tables are marked and never reprocessed; and a source check confirming the `clientssummary` filename gate is fully removed. Existing 525 tests unchanged and still passing. `php -l` clean across every changed file and a full sweep of every `.php` file in the module.
- As with 3.1.6, the DB-backed and browser-rendered pieces (the real `ajaxUsersTwoFactorStatus()`/`resolveUserMethodStatus()` path against a live `tblusers`/`TwoFactorAuthenticationService`, and the JS overlay's actual behavior against real rendered markup) cannot be exercised by this DB-less, browser-less test harness and were **not** manually verified against the live WHMCS install in this session — see the disclosure above. This is the one caveat that could not be closed out this pass; it needs real data from the user to close.

**If the column still shows "N/A" after installing 3.1.7**: please open the Users tab with `?sp2fa_debug=1` appended to the admin URL (e.g. `.../admin/clientssummary.php?userid=666037&sp2fa_debug=1`, or whatever the actual Users tab URL is — the query string works on any admin page), open the browser console, reload the tab, and send back what's logged there — or, alternatively, right-click the Users tab's table in DevTools → Inspect, then "Copy" → "Copy outerHTML" on that table element and send that back. Either one gives the real markup needed to make a fully verified fix instead of another broadened guess.

## 3.1.6 — Fix: Admin Client Profile > Users tab showed "N/A" for the "Two Factor Auth Method" column despite an active Security Pack 2FA method

**The bug**: on the native WHMCS admin **Client Profile > Users** tab, the "Two Factor Auth Method" column showed "N/A" for a user with **DCTLAB WhatsApp Two-Factor Authentication = ACTIVE** in Security Pack. That column is rendered by WHMCS core and only ever reflects WHMCS's own native Security-Module 2FA state — it has no idea Security Pack's Email/DCTLAB WhatsApp/TOTP enrollment exists, so any account whose only active 2FA is a Security Pack method shows "N/A" there, which is misleading for an admin trying to see a user's real 2FA posture.

**Why this can't be a normal template/controller fix**: WHMCS ships no documented extension point that lets an addon rewrite an *existing* native admin table's cell content. The `AdminClientProfileTabFields` hook (already used elsewhere in this module — see `core/email_2fa.php`) only *appends* new field rows to the client profile's own tab; it cannot alter a column WHMCS core already rendered on the Users tab. Per this module's established pattern for exactly this situation — the `AdminAreaFooterOutput` JS injection already used in `core/loginHistory.php` to add a "Login History" tab — this is fixed the same way, never by touching a WHMCS core file:

- A new `core/two_factor_admin_display.php` injects a small, fail-soft JavaScript file (`assets/js/two_factor_admin_users.js`) on the Client Profile page via the documented `AdminAreaFooterOutput` hook.
- That script finds the native table by its **actual rendered column header text** ("Two Factor Auth Method") — never by assuming a specific page URL or WHMCS build's markup. If the header text isn't found (a future WHMCS UI change), the script does nothing and the native value is left exactly as WHMCS renders it — never worse than before this fix.
- For each row it finds, it resolves the row's real **WHMCS User ID** (never the selected Client ID — Security Pack's 2FA state is keyed per-user, and a client can have several associated users, each with their own independent 2FA state) and calls a new admin-session-gated JSON endpoint, `TwoFactorController::ajaxUsersTwoFactorStatus()`, which returns each user's display label.
- That label comes from **one** authoritative source, `TwoFactorAuthenticationService::status()` — the same unified 2FA status API the Client Security Center already uses — never a fresh, independent query against the Email/WhatsApp/TOTP tables. `TwoFactorController::methodLabelFromStatus()` is the one place that turns `status()`'s `active_method`/`pending` fields into display text:
  - Email active → "Email Two-Factor Authentication"
  - DCTLAB WhatsApp active → "DCTLAB WhatsApp Two-Factor Authentication"
  - TOTP active → "Time-Based Token Two-Factor Authentication"
  - TOTP pending, nothing active → "Time-Based Token — Verification Pending"
  - Nothing active or pending → "Not Enabled"
  - Any other/unrecognised status shape → falls through to "Not Enabled" rather than guessing.
- A 2FA **bypass** is a separate security property and is deliberately never consulted here — a user with an active admin-manual bypass still shows their real active method, never "Bypassed" and never "N/A".
- No OTP, OTP hash, TOTP secret, recovery code, or WhatsApp/API credential is ever part of this response — only the method label string.
- The AJAX endpoint caps the number of User IDs it will resolve in one request (200) so a malformed or oversized request can't turn one Users-tab page load into an unbounded number of status lookups; it does not add a second 2FA-status cache/table — every lookup goes straight through the existing `TwoFactorAuthenticationService`/provider classes.

**Testing**: 19 new tests (525/525 total, up from 506/506). The DB-backed pieces (`ajaxUsersTwoFactorStatus()`/`resolveUserMethodLabel()`, which call the real `TwoFactorAuthenticationService::status()`) require a live database and are exercised manually against a real WHMCS install, the same as every other DB-backed integration point in this suite. What's covered directly: the pure label-decision logic (`methodLabelFromStatus()`) for every supported state (Email/WhatsApp/TOTP active, TOTP pending, nothing active, an unrecognised/malformed status shape); `buildUsersStatusMap()`'s per-user isolation (User A's method never leaks onto User B's row, using an injected fake resolver so this runs without a database); `parseUserIdsParam()`'s dedup/cap behaviour; and source-inspection checks that the endpoint never substitutes a Client ID for a User ID, never references bypass state, fails soft on a lookup error, never modifies a WHMCS core file, and never lets sensitive 2FA data reach the response. `php -l` clean across every changed and every existing PHP file in the module.

**Manual verification recommended** (the actual DOM lookup in `two_factor_admin_users.js` cannot run in this suite's DB-less, browser-less test harness): open the exact account from the report — Admin > Client Profile > Users — and confirm the column now reads "DCTLAB WhatsApp Two-Factor Authentication" instead of "N/A". Then check the same page for an account with Email active, TOTP active, TOTP pending, and no method at all, and a Client Profile with multiple associated Users, confirming each row shows that row's own method. If the column doesn't update on your install, it most likely means this WHMCS version's Users-tab markup doesn't expose a `userid=` parameter on the row the script expects (Section "USER IDENTITY") — the script will simply leave "N/A" untouched in that case rather than showing anything incorrect; let us know and we'll adjust the row-detection logic to match your build's actual markup.

## 3.1.5 — Fix: unhandled TypeError from the DCTLAB WhatsApp addon's own notification pipeline could crash a WhatsApp 2FA send

**The bug**: user-reported production crash (`TypeError: ...PlatformFactory::make(): Argument #1 ($platform) must be of type ...Platforms, null given`) while activating WhatsApp 2FA, with a stack trace running from `dct_whatsapp_2fa_activate()` all the way down through `WhatsAppTwoFactorService::beginActivation()` → `createChallenge()` → `sendOtpWhatsApp()` → `DctWhatsAppNotificationsBridge::sendCode()` → `sendViaTemplatedNotification()` → into the `dct_whatsapp_notifications` addon's own `NotificationSender::send()` → `NotificationPlatformResolver::resolve()` → `PlatformFactory::make()`, where a null platform reached a non-nullable typed parameter deep inside the addon's own code. `sendViaTemplatedNotification()` already wrapped its call to the addon's `NotificationSender::send()` in a `try/catch(\Throwable)`, but the error still reached WHMCS's top-level handler and crashed the request — the outer `sendCode()` method itself had no equivalent safety net.

### Fixed

- `lib/Security/TwoFactor/Providers/DctWhatsAppNotificationsBridge.php`: `sendCode()` — the ONE public entry point `WhatsAppTwoFactorService` calls to send a WhatsApp 2FA code — now wraps its entire body (both the templated-notification attempt and the plain-message fallback) in its own top-level `try/catch(\Throwable)`, on top of the pre-existing per-platform catches inside `sendViaTemplatedNotification()`/`sendPlainMessage()`. Any unexpected error anywhere in this call chain — including one originating deep inside the third-party addon's own code — now returns `false` (send failed) instead of escaping and crashing the login/activation request, consistent with this module's standing "never let a broken dependency lock someone out of authenticating" discipline. The failure is disclosed via `lkn_hn_log()` (if available) and a new `security_pack_record_event()` warning event, `2fa.whatsapp.dctlab_send_unexpected_error`, that specifically calls out the likely root cause: the addon's own "TwoFactorAuthentication" notification may be enabled with no delivery platform actually assigned to it in that addon's own Notifications settings.

### Recommended follow-up (addon-side, not a Security Pack bug)

- The underlying `null` reaching `PlatformFactory::make()` is inside the `dct_whatsapp_notifications` addon's own notification-resolution code, not Security Pack's. Recommend checking that addon's admin UI — Notifications → "TwoFactorAuthentication" — to confirm it has an actual WhatsApp delivery platform assigned (not just "enabled" with no platform selected). Security Pack cannot fix a missing platform assignment inside a third-party addon's own configuration; it can only (and now does) guarantee that a failure there never crashes the request.

### Testing

- 3 new tests confirm, via source inspection (the addon isn't installed in this DB-less test environment, so the real call chain can't be exercised directly), that `sendCode()`'s own body — not just the private helpers it calls — has a top-level `try/catch(\Throwable)` and that the catch returns `false` rather than re-throwing or letting the error propagate. No existing tests removed or modified. Full suite now 506/506 (`php -l` clean across every changed file and the full module tree).
- Manual staging verification recommended: reproduce the original crash scenario (WhatsApp 2FA activation with the addon's "TwoFactorAuthentication" notification enabled but unconfigured) and confirm activation now fails gracefully (falls through to the plain-message path or reports a send failure) instead of crashing, and that the new `2fa.whatsapp.dctlab_send_unexpected_error` event appears in Security Pack → Security Events when it does.

No `version` bump beyond `3.1.4` → `3.1.5` for schema reasons — no table/column change.

## 3.1.4 — Fix: DCTLAB WhatsApp 2FA activity was missing from the DCTLAB WhatsApp module's "Client Logs Review" page

**The bug**: DCTLAB WhatsApp Two-Factor Authentication activity (code sent, verification success/failure, etc.) never appeared on the `dct_whatsapp_notifications` addon's own admin reporting page, Notification Report → 2FA Logs ("Client Logs Review" — page description: "Review WhatsApp-based two-factor authentication activity."). Root cause, confirmed by auditing the addon's real source: that page (`TwoFactorAuthLogsController` + `pages/2fa_logs.tpl`) reads **exclusively** from one hardcoded table, `mod_lkn_wa2fa_logs`, which Security Pack's `dct_whatsapp_2fa`/`WhatsAppTwoFactorService` had never written to — that table is owned by an entirely separate reference module, `modules/security/dct2fa`, and Security Pack's own WhatsApp 2FA activity has always lived only in its own Security Events, never in this table.

### A note on how this was decided

The original task spec explicitly said not to restore or create `mod_lkn_wa2fa_logs`. Auditing the real, cloned `dct_whatsapp_notifications` source confirmed this page has **no other extension point** — it is the table or nothing. This conflict was surfaced to the user directly (via a clarifying question) rather than silently resolved either way. The user chose to write into the existing `mod_lkn_wa2fa_logs` table, and followed up with detailed, binding constraints on exactly how (producer-only, existing schema, existing 3-value event vocabulary, fail-soft, no duplicate rows) — summarized below and reflected exactly in the implementation.

### Added

- `lib/Security/TwoFactor/Providers/DctWhatsAppTwoFactorLogBridge.php` — a new, small, dedicated reporting adapter. It is the **only** class that touches `mod_lkn_wa2fa_logs`, and it is a producer only:
  - Never creates, migrates, renames, truncates, or redefines the table — if the table doesn't exist (the `dct2fa` reference module was never installed/activated), every write is a silent, fail-soft no-op.
  - Writes using `mod_lkn_wa2fa_logs`'s own existing schema and its own existing, live event vocabulary — `code_sent` / `verify_success` / `verify_failed` — exactly the three values `2fa_logs.tpl` renders with a distinct status badge and the only three its filter dropdown offers. No new event name is ever invented.
  - Encodes every more specific outcome (delivery failure, expired code, too many attempts, no pending code, activation vs. login) in the existing free-text `details` column, using the same short, non-sensitive wording the reference module's own `dct2fa_log_event()` call sites already use (`"delivered"` / `"delivery failed - check module log"` / `"code expired"` / `"too many attempts"` / `"no pending code"` / `"incorrect code"`) — so Client Logs Review reads identically regardless of which module produced a given row.
  - Every public method is wrapped in try/catch and never throws. A reporting-log write failure can never block OTP verification, never causes a login failure, and is never surfaced to the user — it is disclosed only via the existing `security_pack_record_event()` pipeline as a `warning`-severity diagnostic event (`2fa.whatsapp.dctlab_log_write_failed`).
  - Never receives or writes a plaintext OTP, an OTP hash, a TOTP secret, a recovery code, or any WhatsApp/Meta/Botms/Baileys credential or API token — only `user_type`, `user_id`, `event`, a short non-sensitive `details` reason, and `ip_address`, none of it re-derived from `$_GET`/`$_POST`/`$_REQUEST`.

### Changed

- `lib/Security/TwoFactor/WhatsAppTwoFactorService.php` — the sole, authoritative 2FA logic chain (`TwoFactorAuthenticationService` → `WhatsAppTwoFactorService` → `DctWhatsAppNotificationsBridge`) is unchanged; this integration adds only reporting calls at the existing real outcomes:
  - `createChallenge()`: after the real `DctWhatsAppNotificationsBridge`-backed send attempt, calls `DctWhatsAppTwoFactorLogBridge::logCodeSent()` with the actual `$sent` boolean the bridge returned — never assumed "delivered" merely because a send was attempted. Never called for rate-limited/cooldown/max-resends early returns, since no code was actually generated or sent for those (no fabricated events).
  - `verify()`: calls `logVerifySuccess()` on `"valid"`, and `logVerifyFailed()` with the matching dct2fa-style reason on `"invalid"` ("incorrect code"), `"expired"` ("code expired"), `"locked"` ("too many attempts"), and the `"no_challenge"` early-return path ("no pending code"). Not called for the verify-side rate-limit early return (out of the current, narrowed event vocabulary — see "Explicitly not done" below).
  - `security_pack_record_event()` calls for `2fa.whatsapp.sent`/`2fa.otp.resent`/`2fa.verification.success`/`2fa.verification.failed`/`2fa.enabled`/`2fa.disabled` are all **unchanged** — dual logging (Security Pack Security Events + DCTLAB WhatsApp 2FA Logs) is intentional; they serve different purposes and a successful event legitimately appears in both places.
- `modules/security/dct_whatsapp_2fa/dct_whatsapp_2fa.php` — bootstrap now also requires the new `Providers/DctWhatsAppTwoFactorLogBridge.php` file (before `WhatsAppTwoFactorService.php`, which depends on it), following the module's existing manual-require pattern (no autoloading in this native Security Module).

### Explicitly not done, per the narrowed, current scope

- WhatsApp 2FA enabled/disabled, admin/manual 2FA changes, same-IP bypass, and rate-limit events are **not** written to `mod_lkn_wa2fa_logs` — the reference `dct2fa` module's own real implementation never emits an event for any of these either (only `code_sent`/`verify_success`/`verify_failed` exist in its live vocabulary), and inventing additional event names the existing Client Logs Review UI cannot render distinctly would violate the "do not silently create event names the UI doesn't support" rule. These remain fully covered by Security Pack's own `security_pack_record_event()` (`2fa.enabled`/`2fa.disabled`/bypass/rate-limit events), unaffected by this change.
- No new database table, subsystem, or migration. No schema change to `mod_lkn_wa2fa_logs`. No `Capsule::schema()->create/rename/drop/truncate` call against it anywhere in Security Pack.
- No second WhatsApp 2FA implementation and no changes to `TwoFactorAuthenticationService`, `TwoFactorBypassService`, `RateLimiter`, or `DctWhatsAppNotificationsBridge`.

### Testing

- 35 new tests covering: `code_sent`/`verify_success`/`verify_failed` are written (both "the real service calls the bridge" via source inspection, and "the bridge call itself never throws"); client identity and admin identity are accepted and passed through untouched (no `$_GET`/`$_POST`/`$_REQUEST` anywhere in the bridge); expired-code and excessive-attempts branches use the exact dct2fa-style wording; no plaintext OTP, no OTP hash, and no WhatsApp/Meta/Botms/Baileys credential or API token ever appears in the bridge's source; no duplicate records (`logCodeSent()`/`logVerifySuccess()` are each called exactly once per real event); the reporting bridge never creates/migrates/renames/truncates the table; and — the key regression — every public bridge method runs to completion without throwing even with **no** `\Illuminate\Database\Capsule\Manager` available at all (this DB-less test runner's actual environment, strictly harder than a merely-missing table), proving a reporting-log failure can never break authentication. Existing Security Pack event call sites (`2fa.whatsapp.sent`/`2fa.verification.success`/`2fa.verification.failed`/`2fa.enabled`/`2fa.disabled`) are confirmed still present and untouched. No existing tests were removed or modified. Full suite now 503/503 passing (`php -l` clean across every changed/new file and the full module tree).
- The bridge's actual DB write path against a real `mod_lkn_wa2fa_logs` table — same "DB-backed orchestration, exercised manually against a real WHMCS install" category as `WhatsAppTwoFactorService`'s other DB-backed methods — was **not** exercised by this automated suite (no live database here). Manual staging verification is still required: enable/activate/verify WhatsApp 2FA as a client, receive and confirm a correct code, enter an incorrect code, let a code expire, trigger the resend/rate limit, use the same-IP bypass, and log in as an admin with WhatsApp 2FA active — then confirm the corresponding rows appear on DCTLAB WhatsApp → Notification Report → 2FA Logs / Client Logs Review, **and** that Security Pack → Security Events still contains the corresponding security events for the same activity (both are expected to show it — that's the point of dual logging).

No `version` bump beyond `3.1.3` → `3.1.4` for schema reasons — no table Security Pack owns changed; `mod_lkn_wa2fa_logs` remains fully owned by the `dct2fa` reference module and is never created/migrated by Security Pack.

## 3.1.3 — Fix: 2FA "Manage" buttons pointed at a page with no Two-Factor Authentication section

**The bug**: on the Client Security Center, the "Manage" buttons for WHMCS's own native 2FA row and the Email/DCTLAB WhatsApp/Time-Based Token rows all linked to `{$WEB_ROOT}/clientarea.php?action=security` — the classic (non-friendly) URL confirmed correct back in 2.7.9. User-supplied screenshots proved that on this WHMCS install, that page renders only Login Notification, Disable Forgot Password Reset, and a Sessions list — it does **not** include a Two-Factor Authentication section at all. The actual native page hosting a "Two-Factor Authentication" tab (alongside "Linked Accounts", where a client picks/manages Email, DCTLAB WhatsApp, or Time-Based Token) is the friendly URL `{$WEB_ROOT}/user/security` ("Security Settings") — confirmed working by the same screenshots.

### Fixed

- `templates/security_center.tpl`: the Manage links for WHMCS's own native "Two-Factor Authentication" row and all three Security Pack method rows (Email, DCTLAB WhatsApp, Time-Based Token) now point to `{$WEB_ROOT}/user/security` instead of `{$WEB_ROOT}/clientarea.php?action=security`. This is a template-only navigation change — no controller/service logic, no route/action was added anywhere.
- Login Notification, Password Reset Protection, and Session IP Security Limits Manage links are **unchanged** — `clientarea.php?action=security` is still their correct, confirmed destination (that page genuinely hosts those toggles, per the same screenshot evidence).
- No provider-specific deep-link, tab anchor, or query parameter into `/user/security`'s Two-Factor Authentication tab was found or confirmed to exist anywhere in WHMCS — per the "do not fabricate a URL" rule, Email/WhatsApp/TOTP and WHMCS's own native 2FA row all share this ONE confirmed destination rather than three different guessed per-provider URLs. This matches WHMCS's native UI itself, which already lets a client pick among installed 2FA methods from that single screen — the same reason the 3.0.0 design chose to lean on this native UI instead of duplicating it.
- Nothing about the 2FA provider architecture, mutual-exclusion enforcement, or status display changed. `TwoFactorAuthenticationService::status()` remains the sole source for each row's ✓ Active / ⚠ pending / ○ Not active state — this fix only changes where the "Manage" *button* navigates to.

### Explicitly unchanged, per scope

- `TwoFactorAuthenticationService`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, `EmailTwoFactorProvider`/`WhatsAppTwoFactorProvider`/`TotpTwoFactorProvider`, `SecurityScoreService`, Security Events, `RateLimiter` — the route audit found no architectural issue requiring any of these to change.
- The Manage links remain pure navigation: no query string, no `userid`/`user_id`/`clientid`/`client_id` parameter, no action that activates/deactivates/switches a method, resets TOTP, creates/revokes a bypass, or sends an OTP. The destination page resolves the authenticated WHMCS session itself, exactly as `clientarea.php?action=security` already did.
- No schema change, no new `schema_version` marker.

### Testing

- 14 new static-analysis tests (same technique as `sp_test_index_identifier_lengths()`) parse the actual `security_center.tpl` source and assert every row's Manage destination, that the 2FA-specific rows no longer fall back to the generic `action=security` page, that no Manage link carries an untrusted identifier or a state-changing query parameter, and that all four 2FA-related rows share the one confirmed `/user/security` destination rather than fabricated per-provider URLs. Full suite now 482/482 passing.
- Manual verification against a real WHMCS install (per this class of fix's standing disclosure discipline) is still recommended to confirm `/user/security` resolves correctly under this install's specific Friendly URLs configuration, and that `/user/security`'s native Two-Factor Authentication tab remains functional — the classic `action=security` fix in 2.7.9 was deliberately chosen for working with Friendly URLs disabled; if Friendly URLs are disabled on a given install, `/user/security` may not resolve, in which case that install-specific gap should be reported so a Friendly-URL-independent equivalent can be investigated.

No `version` bump beyond `3.1.2` → `3.1.3` — no table/column change, no new schema_version marker.

## 3.1.2 — Fix: Security Score banner recognized only Email 2FA, not the unified active method

**The bug**: the Client Security Center's "Your Security" banner could say "Email Two-Factor Authentication is disabled — enable it to add a second sign-in factor" even when DCTLAB WhatsApp (or Time-Based Token) 2FA was already active — directly contradicting the Authentication section immediately below it, which (since 3.1.1) correctly showed WhatsApp as `✓ Active`. Root cause: `ClientController::security_center()`'s "Your Security" strength/recommendation block checked `$email2faStatus === "active"` specifically, ignoring WhatsApp and TOTP entirely, instead of using the same authoritative `TwoFactorAuthenticationService::status()` active method already computed for the Authentication section on the same page.

### Fixed

- `ClientController::security_center()` no longer scores or recommends based on Email 2FA specifically. It now consumes the SAME `$activeTwoFactorMethod` value (`TwoFactorAuthenticationService::status()`'s authoritative `active_method` — "email"/"whatsapp"/"totp"/`null`) already used by the Authentication section, via a new pure helper, `ClientController::twoFactorRecommendation()`. This guarantees the banner and the Authentication section can never disagree again — there is exactly one place `active_method` is read from (`TwoFactorAuthenticationService::status()`), consistent with the 3.1.1 fix's own rule.
- The requirement is now "at least one of Email / DCTLAB WhatsApp / Time-Based Token is active" — not "Email specifically". A pending, not-yet-verified enrollment on an unused method (e.g. TOTP "verification not yet completed") never counts as active here, matching `TwoFactorAuthenticationService`'s own ACTIVE/PENDING/INACTIVE model — it is not enough to satisfy the requirement, but it also does not suppress the point already earned by whichever method actually is active.
- When no method is active, the recommendation text is now provider-neutral: "Two-factor authentication is not enabled. Enable Email, DCTLAB WhatsApp, or Time-Based Tokens." (new `security_center_rec_enable_2fa_unified` lang string) — it no longer singles out Email, and links through the existing 2FA management flow (unchanged from 3.1.1 — no new route).
- No behavior change when Email 2FA genuinely is the only method offered/active on an install — the fix only removes the incorrect penalty when a *different* method is the one actually active.

### Left untouched, per explicit scope

- `TwoFactorAuthenticationService`, `activateExclusive()`, `enforceSingleActiveMethod()`, `TwoFactorBypassService`, and all three providers (Email/WhatsApp/TOTP) — unchanged from 3.1.1. This is a display/scoring-only fix; the underlying 2FA state and its mutual-exclusion enforcement are untouched.
- No schema change and no new `schema_version` marker — this fix corrects computed display logic only, with no persisted bad state to repair (unlike 3.1.1's multi-active-method data, there is nothing in the database for this bug to have left inconsistent).
- The admin-area `SecurityScoreService` (a separate, sitewide 0-100 score for the admin dashboard) was inspected and is unaffected — this bug was specific to the Client Security Center's own, simpler per-client "Your Security" banner in `ClientController`, a different code path.

### Testing

- 12 new unit tests cover `ClientController::twoFactorRecommendation()` — the pure decision logic behind the banner's contribution/recommendation (each method active alone, no method active, a pending-only method, provider-neutral recommendation text, and the "no method available at all on this install" case). Full suite now 468/468 passing.
- Manually re-verified against the exact reported scenario (Email not active, WhatsApp active, TOTP pending): the banner no longer shows the Email-specific warning and the Authentication section and banner agree.

## 3.1.1 — Fix: only one 2FA method may be active at a time

**The bug**: the Client Security Center's Authentication box could show more than one of Email / DCTLAB WhatsApp / Time-Based Token as "Active" (✓) simultaneously. Root cause: `ClientController::security_center()` computed each method's status by independently querying that method's own table (`nnm_security_pack_email2fa` / `_whatsapp2fa` / `_totp2fa`) in isolation — nothing anywhere enforced that at most one method could actually be active, either in the database or in the display.

### Fixed — server-side, not just the display

- **`TwoFactorAuthenticationService`** gained the actual mutual-exclusion enforcement, reusing the existing provider architecture end to end (no new schema, no duplicate "active method" field):
  - `activateExclusive(string $activatedMethod, ...)` — called by each method's own WHMCS Security Module (`dct_email_2fa`/`dct_whatsapp_2fa`/`dct_totp_2fa`) immediately after ITS OWN activation completes (the one place a method newly becomes active). Disables every other currently-active method via that method's own existing `disable()` — same as before, this preserves the enrollment/config row (status flips to `disabled`; nothing is deleted, and TOTP's secret is kept — only `reset()` ever wipes it) and emits that method's own existing audit event, plus a new `2fa.method.switched` event describing the automatic switch.
  - `enforceSingleActiveMethod(...)` — a self-healing check that runs at the top of `status()` every time it's called (i.e. every Client Security Center page load, every admin overview read). Repairs any account already left with more than one active method (data from before this fix) by keeping the most-recently-activated one (by each table's own `activated_at` column) and disabling the rest the same way. Idempotent.
  - `status()` is now the ONE authoritative status read for all three methods — it returns `active_method` (the single active method key, or `null`) alongside each method's own `active`/`pending` flags.
- **`ClientController::security_center()`** no longer independently queries `nnm_security_pack_email2fa`/`_whatsapp2fa`/`_totp2fa` for status — it calls `TwoFactorAuthenticationService::status()` exclusively, the same single source of truth every other screen must use going forward.
- **The three security modules** (`dct_email_2fa`, `dct_whatsapp_2fa`, `dct_totp_2fa`) each call `TwoFactorAuthenticationService::activateExclusive()` right after their own activation succeeds. Their `bootstrap()` functions now require the full combined dependency set (all three methods' services + all three providers + the orchestrator) so any one of them can check/disable the other two.
- **One-time batch repair** (`security_pack_repair_2fa_exclusivity()`, gated by a new `3.1.1` schema_version marker, runs once via `_upgrade()`/`_activate()`): finds every account already left with more than one active method and repairs it immediately via the same `enforceSingleActiveMethod()`, rather than waiting for each affected user to next open their Security Center page. Never fatal — any failure is swallowed and the same self-heal still runs lazily on that user's next status read.

### Client Security Center display

- Each of the three methods now renders `✓ Active` (green check) or `○ Not active` (grey circle) — never more than one `✓ Active` across the three, matching the enforced server-side state. Verification-pending stays its own distinct `⚠` state, unchanged.
- New info line: "Only one two-factor authentication method can be active at a time. Activate a different method to switch — your previous enrollment is kept, not deleted."
- **Manage buttons were audited, not changed** — every one already correctly linked to WHMCS's own native `clientarea.php?action=security` screen (fixed in 2.7.9), the one place all three methods are actually activated/deactivated. No new routes were invented.

### Left untouched, per explicit scope

- Administrator manual bypass, same-IP trusted bypass, bypass expiration, and `TwoFactorBypassService` itself — bypass is independent of which primary method is active, exactly as before.
- All state-changing actions continue to require POST + `security_pack_csrf_valid()` + session-derived user identity (`dct_*_context()` already resolves from `$_SESSION`, never a request parameter) — unchanged, since this fix added no new HTTP-facing endpoint; `activateExclusive()` is only ever reached from inside each security module's existing, already-POST-and-CSRF-gated `_activateverify()`.
- No OTP/TOTP secret, recovery code, WhatsApp credential, or internal database ID is newly exposed anywhere in this fix.

### Testing

- 6 new unit tests cover `TwoFactorAuthenticationService::pickMostRecentTimestamp()` — the one genuinely pure piece of new decision logic (which method wins when more than one is found active, by recency, with deterministic non-random tie-breaking). Full suite now 456/456 passing.
- **Disclosed scope, consistent with this project's standing test architecture** (`tests/run.php` has never touched a real database or WHMCS runtime — see its own header comment; `WhatsAppTwoFactorService`/`TotpEnrollmentService`/`TwoFactorBypassService`'s DB-backed methods have never been covered by this suite either): the actual DB state transitions — Email active → WhatsApp/TOTP inactive, WhatsApp active → Email/TOTP inactive, TOTP active → Email/WhatsApp inactive, switching between any pair, enrollment preservation on deactivation, and self-heal of a pre-existing multi-active account — are **not** exercised by automated tests in this suite. These must be verified manually against a real WHMCS staging install before production use, per this class's own header comment and this entry's "Fixed" section above. Cross-user isolation and the POST+CSRF requirement are inherited, unmodified guarantees from the existing `dct_*_context()`/security-module contract (see 2.6.1) — this fix added no new HTTP-facing surface to those.

No `version` bump beyond the addon's own `3.1.0` → `3.1.1` string and the new `3.1.1` schema_version marker — no table/column change.

## 3.1.0 — Real DCTLAB WhatsApp integration (github.com/dctlab/WHMCS-WhatsApp-Notifications)

**Background**: explicit instruction to stop treating DCTLAB WhatsApp sending as a best-effort, unverified HTTP client and instead integrate with the real, named, open-source companion addon this project actually uses: [`dctlab/WHMCS-WhatsApp-Notifications`](https://github.com/dctlab/WHMCS-WhatsApp-Notifications) (`modules/addons/dct_whatsapp_notifications`, namespace `Dct\HookNotification\...`). The repository was cloned and read directly (not just the previously-uploaded `dct2fa.php` reference module, though that reference proved byte-accurate against the real repo) to verify every class/method call used below actually exists with the signature assumed.

### Changed

- **Replaced** `DctlabWhatsAppClient` (deleted — a second, parallel WhatsApp transport would have violated this project's non-duplication rule) **with** `DctWhatsAppNotificationsBridge` (`lib/Security/TwoFactor/Providers/DctWhatsAppNotificationsBridge.php`), a thin bridge into the real addon's own notification pipeline instead of a hand-rolled HTTP client:
  - For client users, tries `NotificationFactory::getInstance()->makeByCode('TwoFactorAuthentication')` + `NotificationSender::getInstance()->send(...)` first — the addon's own template-driven, client-record-based, opt-out-respecting `TwoFactorAuthenticationNotification` pipeline (mirrors `dct2fa_send_code()` exactly).
  - Falls through (client users on any failure, and always for admin users, since the addon's own manual-notification pipeline explicitly excludes admin logins) to `sendPlainMessage()`, which reads the configured platform (`Settings::WA2FA_PLATFORM` — `meta`/`botms`/`baileys`/`auto`) via `lkn_hn_config()` and sends directly through `PlatformApiClientFactory`, trying Meta → Botms → Baileys in `auto` mode (mirrors `dct2fa_send_plain_message()`/`dct2fa_send_via_meta()` exactly, including the `"template_name|language"` pipe-delimited encoding Meta template settings use and tolerance for a bare name with no `|`).
  - Fails closed, not fatally: if the `dct_whatsapp_notifications` addon isn't installed (`vendor/autoload.php` or its `helpers.php` missing) or its core classes don't load, `isAvailable()` returns `false` and every send attempt returns `false` — 2FA WhatsApp sending is reported as failed (logged via the existing `security_pack_record_event()`), never a fatal PHP error blocking login.
  - **One deliberate deviation from the `dct2fa.php` reference**: client-id resolution for the notification pipeline uses this project's existing, more careful `WhatsAppTwoFactorService::resolveClientIdForUser()` (looks up `tblusers_clients`, falls back to an email match) instead of the reference module's shortcut of passing the raw WHMCS User ID (`$_SESSION['uid']`) straight through as if it were a `tblclients.id`.
  - Everything else (class names, method signatures, config setting names, notification code, success-status check) was cross-checked directly against the cloned repository source — see the class's own header comment for the full list of files read.
- `WhatsAppTwoFactorService::sendOtpWhatsApp()` now resolves and passes `userType`/`clientId` through to the bridge instead of a flat settings array, since the real integration needs a resolved client record for client users (not needed for the old, since-removed direct-HTTP client).
- `dct_whatsapp_2fa` security module: config screen no longer collects `ApiBaseUrl`/`ApiKey`/`SenderId` (there is nothing left in this module to configure for DCTLAB WhatsApp specifically — platform credentials, sender numbers, and templates are all configured on the `dct_whatsapp_notifications` addon's own settings page). The config description now says so and links to the addon's GitHub repository.
- `WhatsAppTwoFactorProvider::isConfigured()` now checks `DctWhatsAppNotificationsBridge::isAvailable()` (is the addon installed and loadable?) instead of checking for the removed base-URL/API-key settings.

### New installation dependency

- WhatsApp 2FA now requires the [`dctlab/WHMCS-WhatsApp-Notifications`](https://github.com/dctlab/WHMCS-WhatsApp-Notifications) addon to be installed alongside Security Pack, activated, configured (a WhatsApp platform — Botms.in, Baileys, or Meta WhatsApp Cloud API — enabled and its credentials filled in), and its own `composer install` run so `modules/addons/dct_whatsapp_notifications/vendor/autoload.php` exists. Without it, `DctWhatsAppNotificationsBridge::isAvailable()` returns `false` and WhatsApp 2FA reports itself as unconfigured/unavailable rather than failing silently or fatally.

### Added

- 6 new unit tests covering `DctWhatsAppNotificationsBridge`'s two pure helpers (`platformAttemptOrder()` — auto-mode Meta→Botms→Baileys ordering, a specific platform with no fallback, an unrecognized value failing safe to the full auto order; `parseStoredTemplateValue()` — the `name|language` split and bare-name backward compatibility) and its `isAvailable()` fail-closed behavior when the addon isn't present in the test environment — full suite now 450/450 passing.

### Not yet verified

- This integration has been verified by reading the real addon's source directly (cloned from GitHub) and cross-checking every call site, plus a matching, previously-uploaded reference module (`dct2fa.php`) that agrees byte-for-byte — but it has **not** been exercised end-to-end against a live WHMCS install with the `dct_whatsapp_notifications` addon actually installed and a real WhatsApp platform (Botms.in/Baileys/Meta) configured. Test in a staging environment with the companion addon installed before relying on it in production.

## 3.0.1 — TOTP enrollment QR code + reference-module audit

**Background**: after 3.0.0 shipped, three real-world reference WHMCS security modules were reviewed (`dct2fa` — a WhatsApp 2FA module; `smsmanagertwofactor` — an SMS 2FA module; and WHMCS's own bundled `totp` "Time Based Tokens" module) to validate this release's security-module contract usage and close previously disclosed gaps.

### Added

- **`TotpQrGenerator`** (`lib/Security/TwoFactor/TotpQrGenerator.php`) — a small, dependency-free, from-scratch QR Code encoder (ISO/IEC 18004 "Model 2": Reed-Solomon error correction in GF(256), BCH-encoded format/version info, standard masking) that renders the TOTP `otpauth://` enrollment URI as an inline SVG directly on the enrollment page. This closes the "no QR image" limitation disclosed in 3.0.0 — the secret still never leaves the server (no third-party QR image API is called, matching the same reasoning that ruled one out originally). `dct_totp_2fa_activate()` now shows the QR image above the manual-entry secret; if an unusually long issuer/account label pushes the `otpauth://` URI past what the encoder supports, the QR image is silently omitted and manual entry / the clickable link remain the fallback (never a hard error).
  - Encoded output was verified two ways: (1) unit tests pin the exact Reed-Solomon codewords and generator-polynomial coefficients against an independently-computed reference, and (2) the rendered SVG was rasterized and decoded byte-for-byte with `pyzbar`/`zbar` and OpenCV's `QRCodeDetector` during development across several realistic `otpauth://` payload lengths (short label, long label requiring the ECC-M→ECC-L capacity fallback, and a payload deliberately sized past the encoder's version-10 ceiling to confirm it fails loudly rather than truncating).
  - **Why written from scratch**: WHMCS's own bundled `totp` module (which ships both a `LocalQrGenerator` and `RemoteQrGenerator`) was available for reference during the audit above, but every one of its files (`totp.php`, `ga4php.php`, and everything under `lib/Generator/`) is ionCube-encoded, official WHMCS Ltd. protected code whose EULA explicitly forbids reverse engineering — none of it was read, copied, or adapted. Only the published, open ISO/IEC 18004 standard was used.
- 7 new unit tests covering `TotpQrGenerator` (Reed-Solomon regression pin, generator-polynomial pin, version selection, SVG well-formedness/no-external-references, ECC-level fallback for long URIs, loud failure on oversized input) — full suite now 444/444 passing.

### Verified, no change needed

- Reviewed `dct2fa.php` (WhatsApp 2FA reference module) and `smsmanagertwofactor.php` (SMS 2FA reference module) end to end against this release's `dct_whatsapp_2fa`/`dct_totp_2fa` security modules. Both confirm the WHMCS security-module contract this release already relies on: `$params['user_info']['id']`, `$params['post_vars'][...]`, `$params['settings'][...]`, and an `activateverify()` that may return `[]`/`['msg' => ...]` or throw an `Exception` to redisplay a step — this release's `dct_whatsapp_2fa_activateverify()`/`dct_totp_2fa_activateverify()` already match this shape; no `'settings'` return key is required by WHMCS core (one reference module includes it, the other does not — it is module-specific bookkeeping, not part of the contract).
- Both reference modules let the user type their own phone number in-module and store it separately from `tblclients.phonenumber`; this release deliberately does not (WhatsApp 2FA resolves the destination number ONLY from the account's own on-file record, per the 3.0.0 disclosed limitation) — a hardening choice against phone-spoofing during activation, kept as-is rather than matched to the reference behavior.
- The reference `dct2fa` module's actual WhatsApp-sending path delegates to a separate companion addon (`dct_whatsapp_notifications`, supporting Botms.in/Baileys/Meta WhatsApp Cloud API) rather than calling a single "DCTLAB API" directly — this release's isolated `DctlabWhatsAppClient` HTTP client remains a best-effort, explicitly-disclosed-as-unverified implementation (per 3.0.0); no concrete DCTLAB API reference was found to verify or correct it against. **CLOSED in 3.1.0** — `DctlabWhatsAppClient` was replaced with a real integration against the actual `dct_whatsapp_notifications` addon.

## 3.0.0 — Unified Two-Factor Authentication (Email + DCTLAB WhatsApp + Time-Based Tokens)

**Background**: built against an explicit, detailed specification requiring ONE authoritative 2FA architecture across three methods (Email Verification, DCTLAB WhatsApp, Time-Based Tokens/TOTP), extending — never duplicating — the existing Email 2FA engine (`Email2faService`, unchanged in this release) and the existing WHMCS Security Module integration pattern (`modules/security/dct_email_2fa`).

### Added

- **`OtpEngine`** (`lib/Security/TwoFactor/OtpEngine.php`) — the shared, pure OTP primitives (clamp/generate/hash/verify/evaluate, email/phone masking) extracted so Email and WhatsApp use identical logic. `Email2faService` is unchanged and keeps its own copies of these methods (same behavior, same event names) — nothing calling it needs to change; `OtpEngine` is the new single source of truth for every NEW caller (WhatsApp).
- **DCTLAB WhatsApp 2FA**: `WhatsAppTwoFactorService` (challenge/verify/enroll lifecycle, structurally parallel to `Email2faService`) + isolated `DctlabWhatsAppClient` (all DCTLAB HTTP API interaction, nowhere else) + new native WHMCS Security Module `modules/security/dct_whatsapp_2fa`. New tables `nnm_security_pack_whatsapp2fa` / `nnm_security_pack_whatsapp2fa_challenges`, mirroring the existing Email 2FA schema shape.
  - **Disclosed limitation**: no live DCTLAB API reference was available while building this — `DctlabWhatsAppClient`'s endpoint path/payload/response shape is a best-effort, defensively-structured implementation that is UNVERIFIED against a real DCTLAB endpoint. Verify and adjust before production use (see the class's own header comment).
  - **Disclosed limitation**: the destination phone number is resolved ONLY from the account's own on-file record (`tblclients.phonenumber`) — this release does not yet offer an in-module "add/change my number" wizard (the exact WHMCS security-module multi-step POST contract for that flow is unverified). Add a phone number to your account profile first.
- **Time-Based Tokens (TOTP)**: pure, dependency-free `TotpService` (standard RFC 6238 / RFC 4226 — SHA-1, 6 digits, 30s period, ±1 step clock tolerance; unit tested against the RFC 6238 published test vector) + `TotpEnrollmentService` (DB-backed enrollment/verify/reset lifecycle) + `TotpKeyStore` (server-side libsodium master key for secret-at-rest encryption, stored in the already-`.htaccess`-protected `core/data/` directory) + new native WHMCS Security Module `modules/security/dct_totp_2fa`. New table `nnm_security_pack_totp2fa`.
  - **Disclosed limitation (closed in 3.0.1)**: no QR *image* is generated — enrollment shows the manual-entry secret and a clickable `otpauth://` link instead, to avoid either hand-implementing an unverified QR encoder or sending the secret to a third-party QR image API (which would violate "never expose the secret"). See 3.0.1's `TotpQrGenerator`.
- **Recovery Codes**: `RecoveryCodeService` — 10 single-use codes per account, cryptographically random, stored as a bcrypt hash (never plaintext, reusing the same `password_hash()` primitive as every OTP). New table `nnm_security_pack_2fa_recovery_codes`.
- **Unified bypass**: `TwoFactorBypassService` — reuses the EXISTING `nnm_security_pack_email2fa_bypasses` table as the one authoritative 2FA bypass store (per the non-negotiable non-duplication requirement), with one additive nullable `method` column for audit display only — a bypass is NOT scoped per method; it applies regardless of which method the user has enrolled. `Email2faService`'s own bypass methods are unchanged (same table, same `email_2fa.bypass.*` event names, for Analytics/Anomaly-dashboard backward compatibility); WhatsApp/TOTP and the new unified admin screen use the new `2fa.bypass.*` event names from the spec's event list.
- **`TwoFactorAuthenticationService`** — thin cross-cutting orchestrator (enrollment status across all 3 methods, "Require 2FA" / default-method policy, bypass/recovery delegation). Contains no provider-specific OTP/TOTP logic of its own, per spec.
- **`TwoFactorProviderInterface`** + `EmailTwoFactorProvider` / `WhatsAppTwoFactorProvider` / `TotpTwoFactorProvider` — the one shared provider abstraction for status/enrollment queries.
- New admin page, **Security Center → Authentication → Two-Factor Authentication** (`?module=security_pack&c=twoFactor`): enrollment overview across all three methods, "Require 2FA" + default-method policy, and the unified administrator manual bypass (grant/revoke, applies regardless of method).
- Client Security Center now shows read-only status for WhatsApp 2FA, TOTP, and remaining recovery-code count, alongside the existing Email 2FA status row.
- ~30 new events per the spec's Section 24 list (`2fa.enrollment.started`, `2fa.enrollment.completed`, `2fa.totp.enrolled`, `2fa.totp.reset`, `2fa.whatsapp.sent`, `2fa.recovery_code.generated`, `2fa.recovery_code.used`, `2fa.bypass.*`, etc.) via the existing `security_pack_record_event()` — no new event table.
- 54 new unit tests (`OtpEngine`, `TotpService` against the RFC 6238 test vector, `RecoveryCodeService`) — full suite now 437/437 passing.

### Explicitly NOT done / deliberate design decisions (confirmed with the requester before implementation)

- **Email 2FA's Global BCC behavior is unchanged from 2.7.0** (Global BCC still receives a copy of Email 2FA OTP mail if configured, since Email 2FA continues to send via WHMCS's own mail pipeline per the explicit 2.7.0 instruction). The new spec's Section 8 asked for the opposite (OTP mail must never reach Global BCC); this is a direct conflict with the standing 2.7.0 decision, which was surfaced explicitly and the requester chose to keep the 2.7.0 behavior rather than reintroduce a raw-mail() send path for Email 2FA only.
- **No custom method-selection/admin-config UI was built to match the spec's Section 18/20 mockups.** WHMCS's own native Setup > Security > Two-Factor Authentication screen already lets a user pick among installed methods and lets an admin configure each method's own settings (including the new DCTLAB WhatsApp credentials and OTP/TOTP fields) — building a parallel custom UI would duplicate that native screen. This was surfaced explicitly and confirmed; the new unified admin page covers only what WHMCS's native screen has no equivalent for (cross-method overview, Require-2FA policy, unified bypass).
- No second GeoIP, RateLimiter, CSRF, or event-table implementation was introduced anywhere in this feature — every new provider reuses the existing `RateLimiter::hit()`, `security_pack_csrf_valid()`/`security_pack_csrf_token()`, and `security_pack_record_event()`.
- `Email2faService` itself was left completely unmodified — no method signature, return shape, or event name changed, so `modules/security/dct_email_2fa` and every existing admin/client screen referencing it needed zero changes.

## 2.9.0 — Country Restriction rebuilt as a consumer of the existing GeoIP architecture

**Background**: Country Restriction (`core/disallow_countries.php`) already reused the shared `security_pack_resolve_country()` → `GeoIpManager` → configured provider(s) → the SAME MaxMind database used by GeoIP Language & Currency — no second GeoIP system existed. This release closes the remaining gaps against that architecture and adds the missing policy controls.

### Fixed

- `SecurityPackCountryRestriction::getCountry()` read the raw WHMCS global `$remote_ip` directly instead of the module's own trusted-proxy-aware `security_pack_detect_visitor_ip($settings["ip_source"])` — every other feature (GeoIP Language & Currency, IP Restrictions, Security Events, Security Diagnostics) already used the shared resolver. This meant a forwarded-for header (CF-Connecting-IP/X-Forwarded-For/X-Real-IP) was trusted/ignored inconsistently between Country Restriction and the rest of the module, and a visitor behind an untracked proxy could get a different (wrong) apparent country than every other feature would compute for the same request. Now uses the shared resolver exclusively, with the same fallback-to-`$remote_ip` behavior already used by `security_pack_record_event()` if the resolver is unavailable.

### Added

- **Mode**: Country Restriction can now run in either **Block selected countries** (previous/default behavior) or **Allow only selected countries**.
- **Unknown-country policy**: explicit, configurable Allow/Block behavior for when GeoIP cannot determine a visitor's country (database unavailable, provider failure/timeout, private/invalid IP). Previously this was an implicit, undocumented "always allow" — now it's a visible setting (`country_restriction_unknown_policy`, default `allow`/fail-open, recommended).
- New pure `\WHMCS\Module\Addon\Security_Pack\Security\CountryRestrictionService` — holds ONLY the allow/block decision matrix (mode + unknown-country policy + rule list). It performs no GeoIP lookup, no database/cache access, and no provider calls of its own — `SecurityPackCountryRestriction::checkBlocked()` resolves the country via the existing shared resolver and hands it to this service to decide. This is what makes the decision logic fully unit-testable without a WHMCS runtime (see `tests/run.php`).
- New dedicated admin page, **Security Center → Protection → Country Restrictions** (`?module=security_pack&c=countryRestriction`): status (enabled/disabled, GeoIP provider availability, MaxMind database availability, mode, unknown-country policy), a Test Lookup tool (delegates to the same `security_pack_resolve_country()` every other feature uses), the Mode/Countries/Unknown-policy rule form, and a "Recently Blocked" list read from the existing `nnm_security_pack_events` table (event_type `country_restriction.blocked` — no new event system).
- `DiagnosticsController` now reports a dedicated "Country Restriction" row (enabled/disabled, mode, configured-country count) alongside the existing "GeoIP Manager" row — it does not duplicate that row's provider-availability check.
- `SecurityScoreService`'s existing "Geo Protection" category (which already counted Country Restriction toward its score) now also surfaces an info-level recommendation when the feature is enabled with zero countries configured — a safe no-op state that's worth flagging, not penalizing.

### Changed

- Settings tab's "Country Restriction" panel now holds only the enable toggle, GEO Providers, and Whitelist IP (all either the master switch or shared with GeoIP Language & Currency); Mode, the country list, and the unknown-country policy moved to the new dedicated page. The old combined "Geo provider + restricted countries required" validation was relaxed to just require a GEO provider — an empty country list is now a valid, safe (no-op) configuration in either mode, not a save-blocking error.
- The blocked-visitor event's `event_type` changed from `country.blocked` to `country_restriction.blocked` (context now also includes `mode` and `reason`), matching the naming this feature is documented/referenced by everywhere else (menu, diagnostics, settings link).

### Not changed / explicitly NOT done (per requirements)

- No second MaxMind database, upload path, GeoIP cache, or provider implementation was created. `MaxMindProvider`, `CurlApiProvider`, `GeoIpManager`, `GeoResult`, `GeoProviderInterface`, and `lib/MaxMindDb/Reader.php` are all unchanged and remain the single authoritative GeoIP path for every feature (Language & Currency, Country Restriction, Security Intelligence facts).
- No new database table. The country rule list and its two new policy settings are stored in the existing generic `nnm_security_pack` key/value settings table, same as every other Security Pack setting.
- Country Restriction is still enforced ONLY via the client-area hooks (`ClientAreaPage`, `ClientAreaHeaderOutput`, `ClientDetailsValidation`) in `core/disallow_countries.php`, which is only `require`d at all when `defined("CLIENTAREA")` — the WHMCS admin area, cron, the API, and webhooks never load this file and are structurally unaffected, not just "not currently blocked."
- Existing tests unchanged; 129 new assertions added for the new decision matrix (mode, unknown-country policy, list normalization/validation against SQLi/XSS-style junk, case-insensitivity). Full suite: 383/383 passing.

## 2.8.0 — Removed: Legacy Hard-Coded Licensing Stub

**Background**: the module shipped with a legacy licensing mechanism
that was never a real validation system — `security_pack_license()`
unconditionally returned `status => "Active"`, and a second, already
dead/commented-out function `security_pack_keyfunction()` returned a
hardcoded key string. `security_pack_output()` (admin area) and
`security_pack_clientarea()` (client area) each called
`security_pack_license()` and gated all real functionality behind a
`switch ($licensestatus["status"])`, with unreachable `"Invalid"` /
`"Expired"` / `"Suspended"` / `default` branches that could never
execute because the function only ever returned `"Active"`.

### Removed

- `security_pack_license()` — deleted entirely, including its
  `licensestatus`/`labeltype` return payload.
- `security_pack_keyfunction()` — the commented-out hardcoded key
  function, and the hardcoded key string it contained, deleted
  entirely (not left commented out).
- The `$licensestatus = security_pack_license(); switch (...) { case
  "Active": ... }` gating wrapper in both `security_pack_output()` and
  `security_pack_clientarea()`, along with the unreachable `"Invalid"`
  / `"Expired"` / `"Suspended"` / `default` dead-code branches under
  it. The real logic in each function now runs unconditionally, at
  corrected top-level indentation.

### Not changed

- No replacement licensing/validation mechanism was introduced — the
  module now simply has no license-gating concept at all, per the
  explicit instruction not to substitute another licensing system.
- `README.md`'s and `whmcs.json`'s "license" mentions (MaxMind GeoLite2
  license key note, and the `"license": "proprietary"` package field)
  are unrelated to the removed gating mechanism and were left as-is.

## 2.7.9 — Fix: "Manage" Buttons on the Account Security Page Linked to Nonexistent URLs

**Reported**: on the Account Security page's "Authentication" box, none
of the "Manage" buttons (Login Notification, Email/native Two-Factor
Authentication, Password Reset) worked.

**Root cause**: `templates/security_center.tpl` linked every "Manage"
button to a guessed, nonexistent path —
`{$WEB_ROOT}/user-security` or `{$WEB_ROOT}/security` — neither of
which is a real WHMCS client-area URL, so every button 404'd.

### Fixed

- All four "Manage" buttons now link to
  `{$WEB_ROOT}/clientarea.php?action=security` — WHMCS's own documented,
  always-valid classic (non-friendly) URL for the native Security
  Settings page, which hosts Password Reset, Login Notification, and
  Two-Factor Authentication together in one place. This form works
  regardless of whether Friendly URLs are enabled.
- Deliberately did NOT switch to Smarty's `routePath()` function as an
  alternative fix — it has a documented "unknown function" failure mode
  in some WHMCS rendering contexts (per WHMCS Community reports), so
  the plain, always-valid query-string URL is the safer choice here.

### Not changed

- `ClientController::backToSecuritySettings()`'s use of
  `App::redirectToRoutePath("user-security", [])` is untouched — that's
  a different, PHP-side WHMCS API (not the Smarty function) already
  confirmed working in this codebase, and was never the bug.
- No schema change; a `2.7.9` schema_version marker was still added for
  audit-trail consistency with prior releases.
- 359/359 tests still passing (template-only fix, no new branchable
  logic).

## 2.7.8 — Add: "Account Security" Nested Under the Client Area's "Account" Sidebar Item

**Requested**: add "Account Security" back to the client area, this
time as a child of the existing WHMCS "Account" item in the PRIMARY
sidebar, rather than as a new top-level entry (2.7.5, removed in 2.7.6)
or the secondary "Account" dropdown (2.3.0, removed in 2.7.6).

### Added

- New `ClientAreaPrimarySidebar` hook in `core/loginHistory.php`, built
  from user-supplied reference code: resolves the primary sidebar's
  existing "Account" node via `getChild("Account")` and adds "Account
  Security" as its child, linking to
  `index.php?m=security_pack&page=security_center`, with a `fas
  fa-shield-alt` icon and an `account-security-sidebar` CSS class on
  the resulting menu item.
- Session check (`$_SESSION["uid"]`) and the `getChild("Account")` →
  `addChild()` → `setAttribute()` structure follow the supplied
  reference exactly. Unlike the earlier secondary-navbar attempt (2.3.0
  era), where `getChild("Account")` returned null on this WHMCS/Lagom2
  combination, the reference confirms it resolves correctly on the
  PRIMARY sidebar — no defensive fallback/no-op needed for that lookup
  specifically; the existing `if(!$account) { return; }` guard still
  covers the case where it doesn't.

### Not changed

- No schema change; a `2.7.8` schema_version marker was still added for
  audit-trail consistency with prior releases.
- 359/359 tests still passing (pure menu addition, no new branchable
  logic in `lib/Security/*` or the controllers).

## 2.7.7 — Remove: Login History Client-Area Menu Entry

**Requested**: per explicit follow-up instruction, remove the Login
History entry from the client area's secondary "Account" dropdown too
— this was the last remaining item added by the
`ClientAreaSecondaryNavbar` hook (the "Account Security" entry was
already removed in 2.7.6).

### Removed

- The entire `ClientAreaSecondaryNavbar` hook in
  `core/loginHistory.php` — with both its entries gone (Login History
  here, Account Security in 2.7.6), the hook body would only be a
  no-op, so it was removed outright rather than left as dead weight.

### Not changed

- The Login History controller/page itself
  (`index.php?m=security_pack&page=login_history`) is fully intact and
  still reachable directly by URL — only the automatic menu link to it
  was removed.
- The `client_history`/`login_history` admin settings toggles are
  unaffected — they still control whether login history is *recorded*
  and shown on the admin side; this change only removed the client-area
  menu link.
- No schema change; a `2.7.7` schema_version marker was still added for
  audit-trail consistency with prior releases.

## 2.7.6 — Remove: Both "Account Security" Client-Area Menu Entries

**Requested**: per explicit follow-up instruction, remove BOTH menu
injections that pointed at the Client Security Center ("Account
Security") page.

### Removed

- The 2.7.5 `ClientAreaPrimarySidebar` hook (the main left-hand icon
  nav entry) — deleted entirely, including its doc comment.
- The original `ClientAreaSecondaryNavbar` "Account Security" entry
  (added in 2.3.0, the "Account" dropdown list item) — removed from the
  hook in `core/loginHistory.php`; the Login History entry in the same
  hook is untouched and still shows when enabled.

### Not changed

- The Client Security Center controller/page itself
  (`ClientController`'s `security_center` action,
  `index.php?m=security_pack&page=security_center`) is fully intact and
  still reachable directly by URL — only the two automatic menu links
  to it were removed.
- No schema change; a `2.7.6` schema_version marker was still added for
  audit-trail consistency with prior releases.

## 2.7.5 — Add: "Account Security" in the Client Area Main (Primary) Sidebar

**Requested**: the "Account Security" client page (Client Security
Center — Email 2FA status, login history, bypass management) was only
reachable via Account Details > the secondary "Account" list. The user
asked for it to also appear directly in the main left-hand sidebar
(Dashboard / Services / Domains / Billing / Support / …).

### Added

- New `ClientAreaPrimarySidebar` hook in `core/loginHistory.php` adds a
  top-level "Account Security" item to the client area's primary
  sidebar, linking to the same `index.php?m=security_pack&page=security_center`
  page already used by the existing secondary-navbar entry — one page,
  now reachable from two places.
- Defensive: wrapped in `class_exists("WHMCS\View\Menu\Item")` +
  try/catch so a WHMCS version without this hook, or any failure while
  building the menu item, can never break the rest of the client area.
  An icon is set only if the returned menu item object actually exposes
  a `setIcon()` method — WHMCS's own documentation excerpts available in
  this environment did not confirm the exact icon API for a custom
  top-level primary-sidebar item, so this is disclosed rather than
  guessed at.

### Not changed

- The existing secondary "Account" list entry (added in 2.3.0, still
  present) — this is additive, not a replacement.
- No schema change; a `2.7.5` schema_version marker was still added for
  audit-trail consistency with prior releases.

## 2.7.4 — Fix: Security Activity Table IP Column Width (IPv6)

**Reported**: the fixed-width IP column introduced in 2.7.2 (110px) was
sized for IPv4 addresses (max ~15 characters). Full IPv6 addresses —
e.g. `2001:16a2:cf7b:9600:1dc9:f4b6:7e6b:8a9c` (39 characters) — did
not fit, and the overflowing text visually ran into the adjacent
Country column.

### Fixed

- Widened the IP column from 110px to 190px; trimmed the Actor column
  from 100px to 90px to compensate (Message still absorbs whatever
  remains).
- Gave both the Actor and IP cells `word-break` styling so long values
  wrap within their own cell instead of overlapping a neighboring
  column, matching the approach already used for the Event column
  (2.7.3) and Message cell (2.7.2).
- No schema change; a `schema_version` audit-trail marker was still
  added for consistency with prior releases.

## 2.7.3 — Fix: Security Activity Table Event Column Width

**Reported**: after 2.7.2's fixed-width columns, the "Event" column
(170px) was too narrow for the longest real `event_type` values (e.g.
`email_2fa.verification.success`, 31 characters) — `<code>` doesn't
wrap by default, so the overflowing text visually collided with the
Severity badge in the next column instead of dropping to a second line.

### Fixed

- Widened the Event column from 170px to 230px (Time/Severity/Actor
  trimmed slightly to compensate, Message still absorbs the remainder).
- Gave the Event cell's `<code>` element its own `white-space: normal`
  + `word-break: break-word` so long event-type strings wrap within
  their own cell rather than overflowing past it.

No schema change; `2.7.3` schema_version row added for audit trail only.
`tests/run.php`: **359/359 passing** (pure layout change, no new
branchable logic).

## 2.7.2 — Fix: Security Activity Table Overflow (Long Context Values)

**Reported**: after 2.7.1 moved event context onto the same row, rows
for events with very long context (e.g. `settings.updated`, which logs
a full "before" settings snapshot) still overflowed past the table and
panel's right edge instead of wrapping — the JSON just ran on as one
long unbroken line.

### Fixed

- The table is now wrapped in `.table-responsive`, so any residual
  overflow scrolls within the panel instead of spilling past it.
- Columns are given fixed widths via `<colgroup>` (`table-layout:fixed`)
  so the Message column — the only genuinely variable-length one —
  absorbs the remaining space instead of every column stretching to fit
  its longest row.
- The Message cell now force-wraps long words
  (`word-wrap`/`overflow-wrap: break-word`), and the context line
  additionally uses `word-break: break-all` for JSON with no natural
  break points.
- Context JSON longer than ~220 characters is now truncated for display
  with a visible "(truncated — see `nnm_security_pack_events.context`
  for the full value)" marker, rather than rendered in full — this view
  is for at-a-glance auditing; the complete value is always still in the
  database for anyone who needs it.

No schema change; `2.7.2` schema_version row added for audit trail only.
`tests/run.php`: **359/359 passing** (no new tests — pure HTML/CSS
rendering change with no new branchable logic beyond a length check;
verified via `php -l` and manual review of the emitted markup for a
long-context fixture).

## 2.7.1 — Fix: Security Activity Table Column Alignment

**Reported**: on the Security Activity page (Activity > Security
Activity), rows for events carrying extra context (e.g. `email_2fa.*`
events with `user_id`/`user_type`/`purpose`) rendered that context as a
separate table row — a blank cell under "Time" followed by a
colspan-6 cell holding the raw JSON, with no visual connection to the
event row above it. This broke the table's column rhythm and made
context-carrying rows look disconnected/floating compared to plain rows.

### Fixed

- `ActivityController::renderTable()` no longer emits a second `<tr>`
  for context. The context JSON now renders as a second, muted line
  inside that same row's **Message** cell — every row keeps exactly one
  `<tr>` with the same seven columns, so column alignment is consistent
  whether or not that particular event has context.
- No behavior change to what data is shown — same JSON, same fields,
  still `htmlspecialchars()`-escaped — purely a layout fix.

No schema change; `2.7.1` schema_version row added for audit trail only.
`tests/run.php`: **359/359 passing** (no new tests — this is a pure
HTML-rendering change with no new branchable logic; verified via `php -l`
and manual review of the emitted markup).

## 2.7.0 — Email 2FA OTP Mail Now Sent via WHMCS's Own Mail System

**Explicit user instruction, verbatim: "use WHMCS Mail SYSTEM do not use
PHP mail()."** This directly reverses a hard requirement from this
feature's original specification and every release through 2.6.3 —
disclosed prominently here, not silently changed.

### What changed

- `Email2faService::sendOtpEmail()` no longer calls PHP's `mail()` at
  all. It now sends via:
  - **Admin accounts**: `sendAdminMessage()` — the exact same WHMCS
    function `core/loginHistory.php`'s admin login notification already
    uses successfully in this production environment.
  - **Client accounts**: `sendMessage()` — the same function
    `core/loginHistory.php`'s client login notification uses.
- Both go through WHMCS's own configured mail transport (whatever
  General Settings > Mail specifies — plain PHP mail, SMTP, etc.),
  **not** a bare, unconfigured local `mail()` call. This is expected to
  resolve delivery on hosts that have no local mail transport agent but
  do have a working SMTP relay configured inside WHMCS — the underlying
  cause most likely behind the 2.6.3 "no mail received" report.
- The email content itself is now genuinely Smarty-rendered by WHMCS's
  own template engine (merge fields `auth_code`, `auth_validity_minutes`,
  `auth_purpose_label`, plus `otp`/`validity` aliases) instead of the
  previous manual `strtr()` placeholder substitution — the existing
  "Security Pack - Admin/User Two-Factor Authentication" templates
  needed no changes, since they already used matching `{$auth_code}`-
  style Smarty variable syntax.

### ⚠️ SECURITY-RELEVANT TRADE-OFF REVERSAL — read before relying on this

Every release through 2.6.3 sent OTP mail via raw PHP `mail()`
specifically and deliberately so that WHMCS's **Global BCC recipient**
(General Settings > Mail > BCC Messages) would **never** receive a copy
of a one-time code — this was a hard, explicit requirement from the
feature's original 82-step specification. `sendAdminMessage()`/
`sendMessage()` use WHMCS's own templated mail-send pipeline, which
**does** apply Global BCC, and this module now has **no way to exclude
it** (no documented WHMCS API for that was ever found across two
separate investigations — see `Email2faService::sendOtpEmail()`'s own
doc comment and `SECURITY-AUDIT-PHASE-4.md`).

**If a Global BCC recipient is configured, it will now receive a copy of
every Email 2FA one-time code — admin and client.** If this is not
acceptable, do not configure a Global BCC recipient while Email 2FA is
active, or reconsider this change. The Diagnostics page's "Email 2FA —
OTP Delivery" check now surfaces whether a Global BCC recipient appears
to be configured, as a warning, every time it's viewed.

### Client-side delivery: a new, disclosed uncertainty

`sendMessage()` requires a genuine `tblclients.id` — but this module's
identity model is the WHMCS **User** (`tblusers.id`), since one User can
own/access multiple Client accounts, and WHMCS documents no "primary" or
"default" account for a User. A new `Email2faService::resolveClientIdForUser()`
resolves one via:
1. `tblusers_clients` (the User↔Client junction table — corroborated by
   independent WHMCS Community developer discussion, not official
   documentation), lowest client id if multiple.
2. Falling back to a `tblclients` row whose own `email` column matches
   the User's email, if the junction table lookup finds nothing.

If **both** fail, the send fails closed with a clear, logged reason
("no client account could be resolved") rather than guessing or picking
an arbitrary account. This resolution logic is disclosed as unverified
against live WHMCS core source — the same disclosure policy used for the
`modules/security/` interface in 2.6.1 — and should be verified in
staging (via the new "Send Test Email" client-path test, see below)
before being relied on in production.

### Diagnostics page changes

- "Send Test Email" no longer accepts an arbitrary destination address
  — `sendAdminMessage()`/`sendMessage()` can only ever target a real
  WHMCS admin/client record's own configured email. It now offers two
  separate tests: **"Send Test Email to My Admin Account"** (one click,
  targets the currently logged-in admin) and a **client-path test**
  (enter a WHMCS User ID to exercise the same client-account resolution
  a real client OTP send would use).
- The old "PHP mail() Transport" (`sendmail_path`) check was removed —
  no longer relevant, since PHP's `mail()` is no longer used at all.
- "Email 2FA — OTP Delivery" now reports WHMCS's configured `MailType`
  and an at-a-glance Global BCC warning instead of describing the old
  BCC-exclusion guarantee.
- A new "Email 2FA — Client Account Resolution" check reports whether
  `tblusers_clients` is available.

### Upgrade Notes

- No manual database cleanup or migration is required — this is a
  code-only change (application logic and diagnostics only).
- **Before relying on this in production**: use the new "Send Test
  Email" actions (both the admin path and, with a real WHMCS User ID,
  the client path) to confirm delivery actually works in your specific
  environment, and check General Settings > Mail > BCC Messages to
  understand what, if anything, will now also receive OTP copies.

`tests/run.php`: **Existing tests: 254 / New tests: 105 / Total: 359 /
Passed: 359 / Failed: 0** (the 2.6.3 `sendTestEmail()` contract tests
were updated for the new admin/client-path signature; all other tests
unchanged and still passing — this environment has no live WHMCS
session, so `sendAdminMessage()`/`sendMessage()` are unavailable here
and both tests assert the fail-closed `{sent, reason}` contract rather
than a live send).

## 2.6.3 — Fix: Email 2FA Delivery Diagnostics ("No Mail Received")

**Production bug, reported after successfully upgrading to 2.6.2 and
attempting to activate Email 2FA:** the activation screen displayed
("We've sent a verification code to w•••••••••••@gmail.com...") but no
OTP email ever arrived.

### Root cause

Two separate problems, both in the Email 2FA delivery path:

1. **Silent failure, false success message.** `dct_email_2fa_activate()`
   and `dct_email_2fa_challenge()` called
   `Email2faService::beginActivation()` /
   `Email2faService::createChallenge()` — both of which already returned
   a `status` of `"sent"` or `"send_failed"` — but **discarded the
   return value** and always displayed the same "we sent a code"
   message regardless of whether the underlying `mail()` call actually
   succeeded. A real delivery failure was therefore indistinguishable
   from success at the UI level.
2. **No delivery diagnostics.** `Email2faService::sendOtpEmail()` called
   PHP's `mail()` with the `@` error-suppression operator and discarded
   the result, so even server-side (`security_pack_record_event()`)
   logs had no record of *why* a send failed — only that "an OTP was
   marked sent: false" in the rare case anyone thought to check the
   Security Activity log. In this project's own reproduction
   environment, `mail()` fails because there is no local mail transport
   agent installed (`sh: /usr/sbin/sendmail: not found`) — a realistic
   stand-in for the underlying cause on hosts that rely on an external
   SMTP relay configured within WHMCS itself (General Settings > Mail),
   since that relay is deliberately NOT used by this direct-`mail()`
   path (see "Email Delivery" in the 2.6.0 notes below for why).

### Fixed

- `dct_email_2fa_activate()` and `dct_email_2fa_challenge()` now branch
  on the real `sent` / `send_failed` / `rate_limited` status and show an
  honest message for each — including telling the client area user to
  contact an administrator on an actual failure, instead of implying
  success unconditionally.
- `Email2faService::sendOtpEmail()` now captures the real `mail()`
  failure reason via `error_get_last()` (immediately after
  `error_clear_last()`) and logs it — the transport-level reason only,
  **never the OTP itself and never the raw recipient address beyond
  what's already logged elsewhere** — via
  `security_pack_record_event("email_2fa.otp.mail_transport_error", ...)`
  at `warning` severity, so failures are diagnosable from the Security
  Activity log without needing to reproduce them live.
- `sendOtpEmail()` now also passes an explicit envelope sender
  (`mail()`'s 5th, `-f` parameter) whenever WHMCS's own configured
  "Email" address is set and valid. A missing envelope sender is a
  common real-world cause of messages being silently rejected or
  dropped by MTAs/relays that enforce sender verification, and is
  invisible to PHP-level testing. This does **not** add a visible
  `Bcc`/`Cc` header and does not touch the Global BCC exclusion this
  method exists to guarantee.
- Added a **"Send Test Email"** action on the addon's Diagnostics page
  (Setup > Addon Modules > Security Pack > Diagnostics) that sends a
  harmless test message through the exact same transport code path
  (`Email2faService::sendTestEmail()`, sharing the same underlying
  `rawSend()` as real OTPs) and reports the real success/failure reason
  — so an admin can verify server mail delivery independently of a live
  login/activation attempt, before relying on it for real.
- The existing "Email 2FA — OTP Delivery" Diagnostics check now also
  reads WHMCS's own `MailType` setting and, when it isn't plain PHP
  `mail`, explicitly warns that "ordinary WHMCS emails working does not
  by itself prove Email 2FA delivery will work" — since that relay is
  not used by this module's delivery path — and points the admin at
  "Send Test Email" to verify directly.
- Added a new **"PHP mail() Transport"** Diagnostics check that reads
  `sendmail_path` from `php.ini` (and whether `mail()` is disabled
  outright via `disable_functions`) — an empty `sendmail_path` with no
  local MTA configured is the single most common cause of this exact
  failure, and this check surfaces it passively, at a glance, without
  needing to trigger a live test send first.

### Not changed

- The deliberate choice to send OTP mail via raw `mail()` rather than
  WHMCS's own templated mail pipeline is **unchanged** in this release
  — it remains the only verified way to guarantee the Global BCC
  recipient never receives a one-time code (a hard requirement from the
  original specification). If your server has no working local MTA and
  relies entirely on an SMTP relay configured within WHMCS, Email 2FA
  mail delivery will continue to fail until the server itself has a
  working local `mail()` transport (e.g. `sendmail`/`postfix`/`msmtp`
  configured to relay outbound), or a different resolution is chosen
  (see "Deferred" below).

### Upgrade Notes

- No manual database cleanup or migration is required — this is a
  code-only fix (application logic and diagnostics only).
- After upgrading, use **Diagnostics > Send Test Email** to confirm your
  server can actually deliver Email 2FA mail before relying on it for a
  real login. If the test fails, the reported reason will point at the
  underlying server-side mail configuration issue.

### Deferred

- A configurable alternate delivery path (e.g. routing through WHMCS's
  own mail provider with BCC deliberately suppressed for this one
  message type, if/when a documented, stable way to do so is confirmed)
  was considered but not implemented in this release — it would resolve
  the "no local MTA" class of failure without requiring server-level
  mail configuration, but doing so safely requires confirming a way to
  exclude Global BCC that this module's own investigation could not
  verify (see `SECURITY-AUDIT-PHASE-4.md`, `sendOtpEmail()`'s own doc
  comment). Sites that cannot get a local `mail()` transport working
  should treat this as a known limitation for now.

`tests/run.php`: **Existing tests: 254 / New tests: 105 / Total: 359 /
Passed: 359 / Failed: 0** (4 new tests for the sendTestEmail() contract
and the activation/challenge status-branch source pattern; all prior
tests unchanged and still passing).

## 2.6.2 — Fix: Module Upgrade Failure (Over-Length MySQL Index Name)

**Production bug, reported immediately after upgrading to 2.6.1:**

```
PDOException: SQLSTATE[42000]: Syntax error or access violation: 1059
Identifier name 'nnm_security_pack_email2fa_challenges_user_id_user_type_purpose_status_index'
is too long
```

### Root cause

`nnm_security_pack_email2fa_challenges`'s migration declared a
4-column index with no explicit name. Laravel's schema builder
auto-generates an index name (`<table>_<col1>_<col2>_..._index`) when
none is given — for this table, that name is 76 characters, over
MySQL's hard 64-character identifier limit. MySQL rejected the
`CREATE TABLE` statement outright, which failed the entire module
upgrade with an uncaught exception (this specific statement, unlike
most of this module's DB calls, is not wrapped in its own try/catch).

### Fixed

- Every index/unique-key declaration on
  `nnm_security_pack_email2fa_challenges` and
  `nnm_security_pack_email2fa_bypasses` now passes an explicit, short
  name (e.g. `sp_e2fa_chal_lookup_idx`) instead of relying on Laravel's
  auto-generated one — removing the dependency on table/column name
  length entirely for these two tables. **No data or indexed-column
  change** — only the index identifiers themselves changed.
- Added a source-level regression test (`tests/run.php`) that computes
  the actual MySQL identifier length — explicit or Laravel-auto-generated
  — for every index/unique declaration in `security_pack.php`'s
  migrations, and fails if any exceeds 64 characters. Verified to
  actually catch this exact bug (temporarily reverting the fix locally
  reproduces the identical 76-character-identifier failure). This
  guards every future migration change, not just this one.
- Confirmed every other index already present in `security_pack.php`
  before this fix (`nnm_security_pack_ip_rules`,
  `nnm_security_pack_anomalies`) was already safely under the limit
  (44-51 characters) — this was specific to the two longer-named Email
  2FA tables, not a module-wide pattern.

### Upgrade Notes

- No manual database cleanup is required. Because MySQL rejects an
  over-length `CREATE TABLE` atomically, the affected tables were never
  actually created on the previous failed attempt — simply installing
  this version and re-running the module upgrade creates them correctly
  on the first attempt.

`tests/run.php`: **Existing tests: 254 / New tests: 101 / Total: 355 /
Passed: 355 / Failed: 0** (one new schema-length regression test added;
all 2.6.1 tests unchanged and still passing).

## 2.6.1 — Architecture Correction: Email 2FA as a Native WHMCS Security Module

**This release supersedes how 2.6.0 enforces Email 2FA. It does not
change the OTP engine, its security properties, its tests, or its
database tables — those are unchanged and fully reused.** What changes
is WHERE and HOW Email 2FA plugs into WHMCS's login flow.

2.6.0 shipped a hybrid enforcement model: a real pre-session hard gate
for admins (the documented `AuthAdmin` hook) and a post-login SESSION
gate for clients (`UserLogin` + `ClientAreaPage`), because WHMCS's
documented Authentication Hooks expose no pre-session client-area login
hook. That conclusion about the Hooks API was correct — but incomplete.
WHMCS separately ships a distinct module type, "Security Modules"
(`modules/security/`), used by WHMCS's own built-in Two-Factor
Authentication methods (Time-Based Tokens, Duo, YubiKey). That interface
genuinely does intervene between password validation and completed
authentication, for both admin and client logins, before either kind of
session is considered fully authenticated — the correct, native
integration point this feature should have used from the start.

Email 2FA is now implemented as one of those modules:
`modules/security/dct_email_2fa/dct_email_2fa.php` ("Email Verification"
in WHMCS's 2FA method list). The old enforcement hooks in
`core/email_2fa.php` (`UserLogin`'s session-gate marking, `ClientAreaPage`'s
force-redirect, the `AuthAdmin` hard gate) and the standalone
`email2fa-admin-verify.php` pre-session page have been **removed** —
they are replaced, not left running alongside the new module. Account
lifecycle hooks (`UserEdit`, `UserChangePassword`), admin visibility
(`AdminClientProfileTabFields`), and scheduled cleanup (`DailyCronJob`)
remain in `core/email_2fa.php` unchanged, since none of them depended on
which enforcement mechanism was used.

**Important disclosure, carried over honestly from the reference this
was built from**: the `modules/security/` interface is **not published**
in WHMCS's official developer documentation. `developers.whmcs.com`'s
module documentation covers only Gateway, Merchant Gateway,
Provisioning, Registrar, and Addon modules — confirmed by direct
inspection during this phase, not assumed. This module's function names,
`$params` usage, and control flow were reconstructed from (a) a working
reference Two-Factor Authentication security module already installed
in this WHMCS instance ("WhatsApp Verification"), and (b) publicly
visible third-party WHMCS security modules following the identical
folder-name-prefixed-function pattern. No WHMCS core source file was
available to trace directly, so this could not be verified against
WHMCS's actual internal invocation code — only against working examples
and consistent third-party precedent. **Test this thoroughly end-to-end
(activation AND login, for both an admin and a client account) in a
staging copy of this WHMCS install before relying on it in production.**
Full investigation notes are in `SECURITY-AUDIT-PHASE-4.md`'s "Phase 7 /
2.6.1" section.

### Changed

- Email 2FA activation/deactivation moved from this addon's Client
  Security Center buttons to WHMCS's own native Two-Factor
  Authentication screens (client "Security Settings", admin "My
  Account") — the same screens used for every other 2FA method. The
  Client Security Center now shows Email 2FA status read-only, with a
  "Manage" link to that native screen (identical to how this module
  already linked WHMCS's own built-in 2FA status).
- OTP length, code validity, maximum attempts, maximum resends, resend
  cooldown, and same-IP bypass settings moved from this addon's
  "Email 2FA" admin settings form to WHMCS's own Setup > Security >
  Two-Factor Authentication configuration screen for the "Email
  Verification" module — declared natively via that module's own
  `dct_email_2fa_config()`. The admin "Email 2FA" page in this addon no
  longer has a settings form; it now shows enrollment overview and
  administrator manual bypass management only (a Security Pack feature
  with no native WHMCS equivalent).
- `SecurityScoreService`'s "Authentication" category no longer reads an
  `email_2fa_enabled`/`email_2fa_apply_clients`/`email_2fa_apply_admins`
  settings flag (that flag no longer exists) — it now awards points
  based on real adoption (at least one account, and separately at least
  one administrator account, with Email 2FA genuinely active), the same
  principle this module has applied to every other adoption-based score
  category.
- `DiagnosticsController`'s Email 2FA checks now report whether the
  native security module file is present alongside this addon, rather
  than reading a settings flag that no longer exists.

### Security

- **Genuine second-factor enforcement, now symmetric between admin and
  client accounts.** The 2.6.0 admin-hard-gate-vs-client-session-gate
  asymmetry, explicitly disclosed at the time, no longer applies: both
  account types now go through the same native WHMCS Security Module
  challenge-then-verify flow, which WHMCS itself places between password
  validation and completed authentication for both login paths. This
  removes the residual "a client session briefly exists before Email 2FA
  completes" limitation that 2.6.0 explicitly documented.
- The OTP engine itself — generation, hashing, single-use enforcement,
  attempt limiting, rate limiting, bypass scoping, audit logging, BCC
  exclusion — is **completely unchanged** from 2.6.0. This release is
  integration/wiring only; see the 2.6.0 entry below for the full
  security design of `Email2faService`, which this release continues to
  use without modification.
- The bypass system's behavior is preserved exactly: a same-IP or
  administrator-manual bypass is re-checked independently inside the new
  module's `verify()` function even when the challenge screen renders an
  auto-submitting "trusted sign-in" form — a tampered/replayed POST of
  that form's hidden field alone cannot grant access without a genuinely
  active, correctly-scoped bypass already on record.
- Visitor IP resolution continues to use the module's single shared
  resolver (`security_pack_detect_visitor_ip()`) everywhere, including
  in the new security module — the exact rule the 2.6.0 → this release
  transition was careful not to regress, since a 2.6.0 security review
  finding was specifically about two code paths disagreeing on IP
  resolution (see the 2.6.0 entry's Security section).

### Database

- No schema change. All three Email 2FA tables from 2.6.0 are unchanged
  and continue to be created by this addon (the native security module
  reuses them directly, cross-module, rather than creating its own). A
  `2.6.1` row is recorded in `nnm_security_pack_schema_version` for the
  audit trail even though no table changed. The `continuation_hash`
  column on the challenges table (used only by the now-removed
  `email2fa-admin-verify.php`) is left in place, unused — never
  destructively dropped from a live schema — and documented as legacy in
  code.

### Testing

- `tests/run.php` grew from 340 to **354** passing assertions (14 new,
  0 removed): pure-function tests for the new security module's
  WHMCS-config-to-Email2faService-settings mapping (defaults, full
  custom values, and the security_pack-settings fallback for fields with
  no native config equivalent), a structural check that the module's
  declared config fields cover every configurable value and never
  declares a field for anything sensitive, session-marker-based context
  resolution (admin/client/neither), and a fail-closed bypass check with
  no database available. Every existing Email2faService/anomaly/bypass-
  scoping/attack-surface test from 2.6.0 is unchanged and still passes,
  since the underlying engine did not change.
  `Existing tests: 254 / New tests: 100 / Total: 354 / Passed: 354 /
  Failed: 0`. All PHP files across both `modules/addons/security_pack`
  and the new `modules/security/dct_email_2fa` remain lint-clean
  (`php -l`).

### Upgrade Notes

- **New installation step**: copy `modules/security/dct_email_2fa/` into
  your WHMCS install's `modules/security/` directory (alongside this
  addon, which stays in `modules/addons/security_pack/` as before), then
  go to **Setup > Security > Two-Factor Authentication** and Activate
  "Email Verification". Existing 2.6.0 users: your enrolled accounts
  (the `nnm_security_pack_email2fa` table) are preserved, but each
  account owner will see Email 2FA listed as a normal WHMCS 2FA method
  going forward rather than through this addon's own Client Security
  Center buttons — no re-enrollment is required, but re-test login
  end-to-end before relying on it.
- If `modules/security/dct_email_2fa/` is not installed, this addon's
  Diagnostics page reports it as a warning, and the Client Security
  Center / admin profile status displays continue to work read-only
  (they read the same tracking table either way) but Email 2FA will not
  actually be enforced at login until the module is installed and
  activated.
- The 2.6.0 admin settings form fields
  (`email_2fa_enabled`/`email_2fa_apply_clients`/`email_2fa_apply_admins`/
  `email_2fa_length`/`email_2fa_minutes`/`email_2fa_max_attempts`/
  `email_2fa_resend_cooldown`/`email_2fa_max_resends`/
  `email_2fa_bypass_same_ip`/`email_2fa_bypass_days`/
  `email_2fa_admin_bypass_enabled`) are no longer read or written by any
  code path. Any values already saved under those keys in the
  `nnm_security_pack` table are harmless and inert; they are not
  automatically migrated into the native module's config (WHMCS's own
  config storage for security modules could not be verified/written to
  directly without risking undocumented internal behavior) — re-enter
  your preferred OTP length/validity/attempts/resend/bypass values on
  the native Setup > Security > Two-Factor Authentication screen after
  upgrading.

### Deferred

- The exact behavior of WHMCS's internal dispatch for
  `modules/security/` modules — precisely how it discovers the module,
  what every `$params` key contains in every context, and how it
  combines a module's `verify()` boolean with its own session state —
  remains independently unverified beyond the working reference
  implementation and third-party precedent this was built from. If
  WHMCS ever publishes an official Security Module developer reference,
  reconciling this implementation against it is a natural follow-up.
- No attempt was made to read or migrate WHMCS's own internal storage
  for which 2FA method + secret a given account has selected (that
  storage format is undocumented and was not guessed at) — this
  implementation relies entirely on WHMCS calling this module's own
  functions when it decides to, and on this module's own
  `nnm_security_pack_email2fa` table for everything it needs to know.

## 2.6.0 — "Security Pack 2.6" Email Two-Factor Authentication

Security Pack 2.6.0 wires up, extends, and hardens the Email 2FA
scaffold that had existed since an earlier release (the
`email_2fa_length`/`email_2fa_minutes` settings and the "Security Pack -
Admin/User Two-Factor Authentication" email templates) but was never
actually connected to authentication — this release makes it a genuine
second authentication factor for both WHMCS Users (client accounts) and
WHMCS Admins, built as one extension of the existing architecture, never
a second/parallel implementation.

### Added

- **Email Two-Factor Authentication**, keyed by WHMCS **User** identity
  (`user_id` + `user_type` of `client`/`admin`) — never by `client_id` —
  since one WHMCS User can be associated with multiple Clients and must
  have exactly one Email 2FA configuration, matching WHMCS's own
  User/Client separation. Administrators enable/manage it from a new
  **Security Pack > Authentication > Email 2FA** admin page; clients
  enable/manage it from a new panel in the existing Client Security
  Center.
- A cryptographically secure OTP (`random_int()` — never `rand()`,
  `mt_rand()`, `time()`, or `uniqid()`) of a configurable, bounded length
  (6–8 digits, default 6), valid for a configurable, bounded window
  (1–30 minutes, default 10), hashed at rest with PHP's password hashing
  API (never stored in plaintext), single-use (consumed on first
  successful verification, never valid a second time), and
  attempt-limited (configurable, 3–10, default 5). Resend is supported
  with its own cooldown and a capped number of resends, reusing the
  module's **existing** `RateLimiter` service — not a new limiter — keyed
  by (user, purpose), never by IP alone, so an attacker spreading
  requests across many source IPs is still bounded per victim and a
  shared office IP can't exhaust one user's budget for everyone else on
  it.
- A dedicated, professional OTP entry page (`templates/email2fa_otp.tpl`)
  with dynamic-length digit boxes, auto-advance/backspace/paste support,
  a live countdown, and a resend action — keyboard- and screen-reader
  accessible, and built with the same Lagom2-safe template patterns
  (including `{literal}`-wrapped inline CSS) already established
  elsewhere in this module, so it renders correctly on desktop, tablet,
  and mobile without regressing prior Lagom2 compatibility work.
- **Bypass system**, always scoped to (User + specific IP) — never to an
  IP alone: (1) an administrator-controlled manual bypass, created
  explicitly with a confirmation step and a configurable duration
  (1–90 days); and (2) an automatic same-IP bypass granted the moment a
  login-time Email 2FA verification succeeds, so a returning login from
  the same account **and** the same IP skips the OTP step for the
  configured duration. Both bypass types auto-expire on their own
  (checked at read time) and never depend on cron for correctness. A
  successful verification **refreshes** (never silently, indefinitely
  extends) the same-IP bypass window from that moment — a documented,
  predictable policy.
- **Anomaly Detection** gains a new deterministic rule (not AI/ML, same
  as every existing rule): repeated Email 2FA verification failures from
  the same IP within a configurable window, at the same
  info/warning/high/critical severity shape as the existing repeated
  failed-login rule.
- `SecurityScoreService`'s existing "Authentication" category (never a
  new scoring service) now also awards points for the Email 2FA service
  being enabled and for at least one administrator account having it
  active, with matching recommendations when neither is true yet — admin
  accounts being the highest-value unprotected target.
- `AnalyticsController` gains Email 2FA success/failure/resend/bypass-use
  metrics in its existing aggregate-metrics panel (bounded `COUNT`
  queries against the existing Security Events table, same as every
  other metric there — never a full-table load).
- `DiagnosticsController` gains three new checks: table health for the
  three new Email 2FA tables, OTP delivery reachability, and which
  enforcement model (hard pre-session gate vs. session gate — see
  Security, below) is active for admins vs. clients.
- The admin client/user profile page shows Email 2FA status (via the
  documented `AdminClientProfileTabFields` hook — no WHMCS core template
  was modified) — status only; never the OTP, its hash, or any secret
  value.
- Every Email 2FA action is recorded via the **existing**
  `security_pack_record_event()` function — never a second audit log —
  with dedicated event types (`email_2fa.enabled`, `email_2fa.disabled`,
  `email_2fa.otp.sent`, `email_2fa.otp.resent`,
  `email_2fa.verification.success`, `email_2fa.verification.failed`,
  `email_2fa.bypass.created`, `email_2fa.bypass.used`,
  `email_2fa.bypass.revoked`, `email_2fa.bypass.refreshed`,
  `email_2fa.settings.changed`, `email_2fa.reverification_required`) that
  clearly distinguish User/Admin/System actors and never log an OTP
  value, its hash, a password, a session token, or a CSRF token.

### Security

- **Genuine second-factor enforcement — with a documented, deliberate
  asymmetry between admin and client accounts.** WHMCS's documentation
  was checked directly (not assumed) for a pre-authentication
  integration point:
  - **Admins** get a real, hard pre-session gate via the documented
    `AuthAdmin` hook, which fires during WHMCS's own admin password
    check. When Email 2FA is required and no valid bypass exists, the
    hook redirects the browser to a standalone, pre-session OTP page
    (`email2fa-admin-verify.php`) instead of ever completing the login —
    password success alone is never sufficient. The hook is purely
    additive: it never independently re-verifies the password and never
    returns `true` to force a login through; it only ever adds a
    redirect-based requirement on top of whatever WHMCS's own core check
    decides.
  - **Clients** do not have an equivalent option: WHMCS documents no
    pre-session hook for the client area (`UserLogin` and `ClientAreaPage`
    are the only relevant hooks, and both fire only after core
    authentication already succeeded). Faking a pre-session gate here
    was explicitly rejected as insecure. Instead, client enforcement uses
    a **post-login session gate**: `UserLogin` marks the session
    "Email 2FA pending" the moment core auth succeeds, and every
    subsequent `ClientAreaPage` hook invocation force-redirects to the
    OTP page until it is completed — the session is never treated as
    fully authorized in the interim. This is honestly documented
    everywhere as a **weaker enforcement point than the admin path**,
    not a true pre-authentication gate, because a session does briefly
    exist before the OTP step completes. This trade-off was explicitly
    confirmed with the site operator before implementation, given no
    stronger documented WHMCS integration point exists for the client
    area.
  - WHMCS's own native two-factor authentication is left completely
    untouched — this feature never reads, writes, disables, or overrides
    it; the two systems coexist independently, and an account can have
    either, both, or neither enabled.
- The admin OTP page is a standalone, pre-session entry point (necessary
  since `AuthAdmin` cannot pause mid-request to render an interactive
  page). It never receives or trusts an admin identity from the URL or
  query string; the only credential is a random, single-use continuation
  token in a dedicated `HttpOnly`/`SameSite=Lax` cookie this module sets
  and reads itself (never WHMCS's own session, whose bootstrap behavior
  in this specific pre-session context could not be verified), resolved
  server-side to one pending challenge row bound to the requesting IP.
  It carries its own CSRF protection (a separate double-submit cookie,
  compared with `hash_equals()`), independent of the module's normal
  session-based CSRF helper, since it runs before any WHMCS session
  exists. It never itself establishes a WHMCS admin session; on success
  it clears its own cookies and returns the browser to WHMCS's normal
  login form to complete the (now Email-2FA-cleared) password login.
- OTP verification (`Email2faService::verify()`) rejects the submission
  if the matching challenge is missing, already consumed, invalidated,
  expired, or at its attempt cap — evaluated as a single pure decision
  function (`evaluateOtpSubmission()`) covering all five outcomes, unit
  tested at every boundary. The attempt-count increment is written with
  an atomic `WHERE attempt_count = <value just evaluated>` conditional
  update (fixed during this phase's security regression review) so that
  two concurrent verification attempts against the same challenge cannot
  each land an "extra", uncounted attempt past the configured cap.
- The OTP is never placed in a URL or query string — every verify/resend
  action is POST-only, and the OTP itself travels only in a POST body
  field.
- The global WHMCS BCC recipient (General Settings > Mail > BCC Messages)
  never receives an Email 2FA OTP message — see Email Delivery, below —
  while every other WHMCS-sent email continues to be BCC'd exactly as
  configured; WHMCS core was not modified and BCC was not globally
  disabled to achieve this.
- Bypass lookups always match on the exact (user_id, user_type, ip)
  tuple — an IP is never, by itself, treated as an identity or bypass
  key, so a shared office/NAT IP cannot let one account's bypass apply
  to a different account, and a bypass never silently follows an account
  across networks.
- A dedicated security regression review of every new/changed file in
  this phase (SQL injection, XSS, CSRF, authentication bypass,
  authorization bypass, OTP brute force, OTP replay, session fixation,
  IP spoofing, email/resend flooding, open redirects, sensitive-data
  logging, information disclosure) found one Medium-severity issue and
  fixed it: the standalone admin OTP verify page resolved the visitor IP
  differently (`REMOTE_ADDR` only) than the `AuthAdmin` hook that wrote
  the challenge's IP (the module's shared, Trusted-Proxy-aware IP
  resolver), which would have made the challenge lookup fail on any
  deployment sitting behind a reverse proxy or CDN with an IP source
  other than `remoteaddr` configured — now both paths resolve IP the
  same, shared way. No other issue was found; full detail is in the new
  "Phase 6 / 2.6.0 Security Review" section of
  `SECURITY-AUDIT-PHASE-4.md`, including two accepted Low-severity
  residual items (documented there, not fixed in this release — see
  Deferred, below).

### Database

- Three new tables, added via idempotent, existence-guarded, additive
  migrations tracked by `nnm_security_pack_schema_version` (version
  `2.6.0`): `nnm_security_pack_email2fa` (one row per User: status,
  masked-displayable email, activation/last-verified timestamps),
  `nnm_security_pack_email2fa_challenges` (one row per issued OTP:
  hash, expiry, attempt/resend counters, purpose, and — for admin
  login-purpose challenges only — a `continuation_hash` column), and
  `nnm_security_pack_email2fa_bypasses` (one row per granted bypass:
  scope, IP, expiry, revocation). No existing table, column, or setting
  was altered, renamed, or removed; uninstalling with the "delete all
  data" option drops these three tables symmetrically with every other
  table this module creates.

### Client Area

- The Client Security Center gains an Email 2FA panel: masked email
  address, current status, and enable/disable controls, plus the shared
  OTP verification page used for both activation and login-time
  verification.

### Admin Area

- New **Authentication > Email 2FA** admin page: global settings (OTP
  length/validity/attempts/resend limits/bypass duration, each clamped
  server-side to the same bounds enforced everywhere else), an overview
  of enrolled accounts, and bypass management (create/revoke), every
  state-changing action gated on POST + CSRF with an explicit
  confirmation step.
- The admin client/user profile tab shows Email 2FA status via the
  documented `AdminClientProfileTabFields` hook.

### Lagom2 Compatibility

- `templates/email2fa_otp.tpl` follows the same `{literal}`-wrapped
  inline-CSS pattern used elsewhere in this module (see the 2.5.x
  production fix to `security_center.tpl` for why this matters — Smarty
  can otherwise misparse CSS rules like `.card{border:1px solid #eee}`
  as a template tag) and was verified responsive at desktop, tablet, and
  mobile widths, consistent with every other Client Security Center
  panel.

### Email Delivery

- OTP mail is sent via PHP's native `mail()` function directly, rather
  than through WHMCS's own templated mail-send pipeline — a deliberate,
  disclosed trade-off. WHMCS's global BCC setting is applied by that
  pipeline itself; the only way to guarantee OTP mail never reaches it
  without modifying WHMCS core or globally disabling BCC (both
  explicitly out of scope) was to not use that pipeline for this one
  message type. Subject/body content is still sourced from the existing
  "Security Pack - Admin/User Two-Factor Authentication" email template
  rows, so it remains editable from WHMCS's normal Email Templates
  screen. **Known limitation**: this path does not use the
  administrator's configured SMTP relay/provider for this specific
  message type — it uses the PHP `mail()` transport of the underlying
  server. Sites relying entirely on a configured SMTP provider (with
  local `mail()` unconfigured or blocked) should verify OTP delivery
  works in their environment before enabling this feature broadly.

### Testing

- `tests/run.php` grew from 254 to **340** passing assertions (86 new,
  0 removed, 0 modified): OTP generation/hashing/verification round-trip
  and exact-length correctness; `evaluateOtpSubmission()` across all five
  outcomes (valid/invalid/expired/consumed/locked) at exact boundary
  conditions (attempt count == cap, now == expiry); every configuration
  clamp (`clampOtpLength`, `clampValidityMinutes`, `clampBypassDays`,
  `clampMaxAttempts`, `clampMaxResends`, `clampResendCooldownSeconds`) at
  its minimum, maximum, and out-of-range boundaries, plus a combined
  full-settings-object resolution matrix; bypass activity/expiry/
  revocation logic; email masking edge cases; the new Email 2FA anomaly
  rule at below-threshold, at-threshold, and 2x-threshold-critical
  boundaries, and confirmed not to fire on unrelated event types; a
  bypass-scoping matrix (same user+IP / same user+different IP /
  different user+same IP / same user+different user_type); a
  configuration-resolution boundary matrix; an OTP-never-in-a-URL
  structural assertion; attack-style tests for OTP brute force
  (sequential guesses against the attempt cap, including the locked
  6th attempt), OTP replay (a consumed OTP rejected on resubmission),
  resend/email flood protection (reusing the existing `RateLimiter`),
  user-ID-tampering resistance (identity sourced from session context,
  never request parameters), and IP-spoofing resistance (bypass scoping
  never IP-alone); and a routing/authorization regression assertion
  confirming the new admin Email 2FA controller resolves into the same
  authenticated admin namespace as every pre-existing controller, with
  the standalone pre-session admin verify page identified as the one
  deliberate, separate unauthenticated entry point this phase adds (by
  necessity — it runs before admin authentication completes).
  `Existing tests: 254 / New tests: 86 / Total: 340 / Passed: 340 /
  Failed: 0`. All 55 PHP files remain lint-clean (`php -l`).

### Upgrade Notes

- Email 2FA is **off by default** after upgrading — no existing account
  is forced into a new verification step without an administrator or
  the account holder explicitly enabling it.
- Sites behind a reverse proxy, load balancer, or CDN should confirm
  their existing "IP Source" / Trusted Proxies setting (used elsewhere
  in this module for IP-based restrictions) is configured correctly
  before relying on the same-IP bypass, since bypass matching depends on
  that same IP resolution being accurate.
- Because the client-area enforcement point is a post-login session gate
  rather than a true pre-authentication gate (see Security, above), an
  administrator evaluating this feature for a security-sensitive client
  population should read that section's asymmetry note before assuming
  client-side Email 2FA carries the same guarantee as the admin-side
  gate.

### Deferred

- No public/addon-facing WHMCS API was found for constructing and
  sending a `\WHMCS\Mail\Message` through WHMCS's configured mail
  provider while deliberately excluding the BCC recipient; if WHMCS
  documents one in the future, migrating OTP delivery to it (recovering
  use of the admin's configured SMTP relay) is a natural follow-up — see
  Email Delivery, above.
- Two Low-severity items from this phase's security review are accepted,
  not fixed, in this release (both detailed in
  `SECURITY-AUDIT-PHASE-4.md`): the shared `RateLimiter::hit()` counter
  increment is not atomic (a pre-existing, module-wide pattern predating
  this feature, not introduced by it; bounded impact); and the
  continuation/CSRF cookies' `Secure` flag depends on `$_SERVER["HTTPS"]`
  being set correctly by the web server for TLS-terminating-at-proxy
  deployments, the same category of trust already documented for this
  module's IP detection.
- No admin UI currently lets an administrator search/filter enrolled
  Email 2FA accounts by status at scale beyond the overview list; larger
  deployments needing bulk visibility are a candidate for a future
  release.

## 2.5.0 — "Security Pack 2.5" Advanced Security Center

Security Pack 2.5.0 re-opens feature development (the 2.4.0 release was a
deliberate feature freeze for security assurance) and adds a CSP Reporting
Center, Security Analytics, deterministic Anomaly Detection, and Security
Alerts — all built as extensions of the module's existing, authoritative
security services (Security Events, Security Score, Diagnostics, IpUtil,
IP Restrictions, RateLimiter, GeoIpManager, CSRF, Trusted Proxy detection,
Security Headers), never as parallel implementations. Every 2.4.0 control
remains exactly as it was; nothing in this release removes or weakens a
prior check.

### Added

- **CSP Reporting Center** (`System > CSP Reports`). A new, dedicated
  public endpoint (`/modules/addons/security_pack/csp-report.php`)
  accepts standard browser Content-Security-Policy violation reports
  (both the classic `application/csp-report` shape and the modern
  Reporting API shape) when explicitly enabled. Reports are normalized,
  bounded, deduplicated by a deterministic grouping key
  (directive + resource origin + source file), and stored — grouped,
  never one row per report — in a new `nnm_security_pack_csp_reports`
  table with an `occurrence_count`/`first_seen`/`last_seen`. The admin
  page shows aggregate stats, a filterable/paginated grouped list, a
  per-group detail view, and a "Policy Analysis" view that classifies
  each observed resource origin using hedged, honest terminology
  (`Observed`, `Unrecognized`, `Likely third-party`, `Needs review`) —
  it never labels anything "safe", and any suggested policy additions
  are explicitly review-only text, never auto-applied. CSP itself
  remains **Report-Only** — this release does not add enforcement.
- **Security Analytics** (`Activity > Analytics`). A dashboard of
  aggregate metrics (login attempts, blocked requests, IP/country
  restrictions triggered, CSP violations, and more), a per-day event
  trend chart, and top-10 breakdowns by IP, country, event type, and CSP
  blocked resource — all computed with bounded aggregate SQL
  (`COUNT`/`SUM`/`GROUP BY`/`LIMIT`) against the existing Security
  Events table, never by loading full tables into PHP. User agents are
  deliberately not offered as a "top" breakdown, to avoid surfacing
  fingerprinting-adjacent data with little analytical value.
- **Anomaly Detection** (`Activity > Anomalies`). A small set of
  hand-written, deterministic threshold rules — explicitly **not**
  described as AI or machine learning anywhere in the UI or code —
  evaluated against existing Security Events: repeated failed logins
  from one IP, distributed failed logins across multiple IPs, a login
  from a new country shortly after a login from a different country for
  the same actor, and an overall daily event-volume spike relative to a
  7-day baseline. Every finding states its rule, severity
  (info/warning/high/critical), confidence, a plain-language reason, and
  structured evidence — nothing opaque. Findings can be acknowledged or
  dismissed; dismissing suppresses that specific recurring pattern for 7
  days, after which it is re-evaluated and re-opened if it is still
  occurring — dismissal is never permanent silent suppression.
- **Security Alerts** (`Activity > Alerts`). A read-only, on-demand
  summary layer over existing signals (open high/critical anomalies,
  repeated IP/country blocking, CSP violation spikes, Security Score
  drops) — not a second persisted notification system. An optional daily
  digest email to admins (off by default) reuses WHMCS's existing
  `sendAdminMessage()` admin-message mechanism and a normally-seeded
  email template; no new external notification provider was added, and
  only meaningful HIGH/CRITICAL conditions are ever included.
- New "Security Intelligence" category (10 points) added to the
  **existing** `SecurityScoreService` — CSP report collection being
  enabled and having zero unresolved high-severity anomalies each
  contribute points, with matching recommendations. No new/parallel
  scoring service was created; ordinary telemetry volume does not swing
  the score.
- New Security Center navigation: `Activity` is now a group containing
  All Events (the existing Activity page, unchanged), Analytics,
  Anomalies, and Alerts; `System` gains a CSP Reports entry. Every
  existing `?module=security_pack&c=...` URL continues to work
  unchanged — see Compatibility, below.
- `DiagnosticsController` gained checks for the CSP reporting endpoint's
  status, the Anomaly Detection service and its open-finding count, the
  Security Alerts service, and Security Score snapshot history.

### Changed

- `core/security_headers.php`'s existing Report-Only CSP header now
  optionally appends `report-uri`/`report-to` directives and a companion
  `Reporting-Endpoints` header, but only when a new, separate
  `csp_report_collection` setting is explicitly enabled — an opt-in on
  top of the CSP feature's own existing opt-in toggle. CSP enforcement
  mode is unchanged (still Report-Only).
- `DiagnosticsController::save()` now also rejects non-POST requests
  (previously CSRF-token-checked but not method-restricted), matching
  the POST + CSRF pattern every other state-changing action in the
  module already uses. Found during this phase's security regression
  review; not exploitable as classic CSRF (a valid session-bound token
  was already required), but a genuine defense-in-depth gap since a
  state-changing GET request's token can leak via `Referer` headers,
  browser history, or server access logs.

### Security

- CSP report fields are treated as untrusted input end-to-end: the
  public endpoint validates HTTP method, content-type, and a hard body
  size cap (checked before reading the body, not just trusted from
  `Content-Length`); JSON parsing is strict and rejects anything that
  isn't a well-formed object/array; every extracted string field is
  bounded to 500 characters; nothing submitted is ever reflected,
  executed, or used to build a query/path. Verified against `<script>`,
  `"><script>`, SQL-injection-shaped strings, CRLF sequences, a
  10,000-character oversized value, and Unicode input — all stored
  inertly and bounded, never executed.
- The CSP endpoint reuses the **existing** `RateLimiter` service (keyed
  `csp_report:<ip>`, 30 hits/60s) rather than introducing a new
  rate-limiting mechanism; the rate-limit key is the TCP peer address
  (`REMOTE_ADDR`), not an attacker-controlled header, so it cannot be
  bypassed by forging `X-Forwarded-For`-style headers.
- CSP report collection writes are gated behind an explicit setting
  (off by default) even though the endpoint file itself is always
  reachable — when disabled, every request is a fast, side-effect-free
  204.
- Admin actions in this phase (`csp.policy.changed`, `csp.report.cleared`,
  `anomaly.acknowledged`, `anomaly.dismissed`, `alert.configuration.changed`)
  are recorded via the **existing** `security_pack_record_event()`
  function, consistent with every prior phase — none log the complete
  raw CSP payload, only bounded/structured summary context.
- A full security regression review (SQL injection, XSS, CSRF,
  authorization, SSRF, information disclosure, header injection, log
  injection, resource exhaustion, rate-limit bypass) was performed
  against every new and modified file in this phase. One Low-severity
  finding (the `DiagnosticsController::save()` GET issue above) was
  identified and fixed; no other issues were found. Full detail in the
  new "Phase 5 / 2.5.0 Security Review" section of
  `SECURITY-AUDIT-PHASE-4.md`.
- Client Security Center is explicitly unchanged in this phase: still
  view-only, still no session revocation, still no fabricated session
  data — the 2.4.0 limitation stands.

### Database

- Three new tables, added via idempotent, existence-guarded, additive
  migrations tracked by `nnm_security_pack_schema_version` (version
  `2.5.0`): `nnm_security_pack_csp_reports` (grouped CSP violation
  storage), `nnm_security_pack_anomalies` (anomaly lifecycle:
  open/acknowledged/dismissed, with a non-permanent
  `suppressed_until`), and `nnm_security_pack_score_snapshots` (one row
  per day, used for the Security-Score-drop alert). No existing table,
  column, or setting was altered, renamed, or removed. Uninstalling with
  the "delete all data" option removes these three new tables and the
  new email template symmetrically with every other table this module
  creates; a normal upgrade never truncates or drops anything.

### Performance

- Every new dashboard/report metric is computed with aggregate SQL
  (`COUNT`, `SUM`, `GROUP BY`) with explicit `LIMIT`s and date-bounded
  `WHERE` clauses — never a full-table `SELECT *` loaded into PHP to
  compute a number. `SecurityAnomalyService::gather()` bounds its
  Security Events pull to a capped lookback window and a 20,000-row
  ceiling. CSP reports are retained/pruned on a daily cron
  (configurable retention days and a maximum row count), and grouping
  itself keeps storage proportional to the number of distinct violation
  shapes rather than the number of individual browser reports.

### Testing

- `tests/run.php` grew from 172 to **254** passing assertions (82 new,
  0 removed, 0 modified): CSP report normalization/grouping/classification
  against valid, malformed, oversized, XSS, SQLi, CRLF, and Unicode
  payloads; the endpoint's method/content-type/body-size validation logic
  and its reuse of the existing rate limiter; the anomaly rule engine
  across normal, threshold, boundary, high-frequency, multi-IP,
  multi-country, and false-positive-suppression-then-reopen scenarios,
  plus explainability assertions (every finding has a non-empty reason,
  evidence, and dedupe key); Security Alert severity classifiers at
  their exact boundary values; analytics day-bucketing (empty/single/
  large/date-boundary datasets) and pagination edge cases; Security
  Score determinism, bounds, and recommendation consistency for the new
  "Security Intelligence" category; an authorization/routing regression
  block confirming every new admin controller resolves into the exact
  same authenticated admin namespace as every pre-existing controller,
  with the public CSP endpoint identified as the one deliberate new
  unauthenticated surface (which handles only inert telemetry writes).
  `Existing tests: 172 / New tests: 82 / Total: 254 / Passed: 254 /
  Failed: 0`. All 51 PHP files remain lint-clean
  (`php -l`).

### Compatibility

- Every admin and client route, database table, and settings key from
  1.2.0 through 2.4.0 is fully preserved. The Security Center navigation
  is reorganized (Activity is now a dropdown group; the former "Activity"
  label is now "All Events" inside it) but every underlying href/address
  is unchanged, so no existing URL or bookmark breaks. The 2.5.0 spec's
  target navigation tree also lists an "Authentication" group and an
  "Audit Log" page; neither was added because both are still panels
  inside the existing Settings/Activity pages rather than dedicated
  controllers — adding a grouped link to a sub-section of another page
  would misrepresent it as a page of its own, contrary to this module's
  established navigation principle (first stated in 2.3.0).

### Deferred

- No admin UI currently exposes the anomaly-detection thresholds
  (`anomaly_failed_login_count`, `anomaly_failed_login_window_minutes`,
  `anomaly_country_switch_window_minutes`,
  `anomaly_event_spike_multiplier`) for tuning — sensible defaults are
  used. A settings panel for these is a reasonable follow-up but was not
  required by this phase's Definition of Done.
- This release does **not** claim "AI-powered security" (Anomaly
  Detection is fixed, deterministic, hand-written rule logic, explicitly
  documented as such in the UI) and does **not** claim "CSP fully
  enforced" (CSP remains Report-Only; only violation *reporting* was
  added).

## 2.4.0 — "Security Pack 2.4" Phase 4

Security Pack 2.4.0 is a **security assurance and audit release** — feature
development was deliberately frozen for this phase. No new dashboard
features, Security Center pages, protection mechanisms, authentication
features, IP features, GeoIP providers, session-management systems, or UI
functionality were added. The entire codebase — including the original
1.2.0-era files earlier audits had only spot-checked — was reviewed
line-by-line, confirmed issues were fixed, and the automated test suite
was substantially expanded. Full detail, including every finding's
severity, impact, and fix, is in `SECURITY-AUDIT-PHASE-4.md`.

### Security Audit

A complete, line-by-line audit of every admin controller, the client
controller, every `core/*.php` hook file, every template, the module's
JavaScript, the GeoIP providers, and the in-house MaxMind DB reader was
performed — not limited to previously-modified files or obvious
request-input-to-output paths, per this phase's explicit scope. SQL
injection, XSS, CSRF, authorization, authentication, session handling, IP
spoofing, CIDR handling, GeoIP/SSRF, path traversal, open redirects, file
uploads, filesystem writes, information disclosure, security headers, and
sensitive-data logging were all reviewed. Five issues were found — all Low
or Informational severity, none Critical/High/Medium — and all five were
fixed. See `SECURITY-AUDIT-PHASE-4.md` for the full findings register.

### Fixed

- **Client-area destructive action reachable via GET**
  (`ClientController::limit_ip_range()`'s "remove IP range" action, linked
  from the client's own Security Settings page). This was the same class
  of issue Phase 3B closed for every *admin* controller, missed because
  that sweep didn't cover the client controller. Not exploitable as
  classic CSRF (the token was already required and validated), but a
  genuine defense-in-depth gap — the token could leak via browser
  history, a proxy log, or a `Referer` header. Now POST-only, with the
  template's link converted to a small POST form.
- Unescaped session-flash error message in
  `SettingsController::index()` — every current call site only ever sets
  a hardcoded string, so this was not exploitable today, but is now
  consistently `htmlspecialchars()`-escaped like every other output in
  the module.
- Missing type guard on `$_REQUEST["settings"]` in
  `SettingsController::save()` — a crafted non-array `settings` value
  previously triggered PHP warnings on array-offset access (noise, not a
  security bypass, since the existing key-allowlist already prevented any
  unexpected write); now explicitly guarded.

### Security

- `core/user_security.php`'s theme-template file write (used to append
  the module's settings panel to a theme's native Security Settings page)
  now verifies the resolved destination path is actually inside
  `ROOTDIR/templates` before writing to it — defense-in-depth; no
  demonstrated exploit path exists today, since the values it's built
  from come from WHMCS's own hook, not request input.
- Added explicit `|escape` to four template values
  (`templates/logs.tpl`'s IP/OS/browser/date columns,
  `templates/settings.tpl`'s current-IP display and IP-range table) that
  were already constrained to `FILTER_VALIDATE_IP`-passing content
  upstream and therefore not exploitable, but are now escaped anyway as
  defense-in-depth against any future change to that upstream validation.
- Reviewed and confirmed safe, no change needed: GeoIP/SSRF (every
  provider call is fed an already-validated, non-private IP), MaxMind DB
  upload path handling (destination path is never derived from the
  uploaded filename), the in-house MaxMind DB binary parser (no
  eval/unserialize/dynamic include), dynamic GeoIP provider instantiation
  (never request-influenced), every other destructive admin action
  (already POST+CSRF since 2.3.0), trusted-proxy / forwarded-header
  spoofing resistance, and Security Event context payloads (no
  password/token/secret/session data found logged anywhere).

### Tests

- `tests/run.php` grew from 125 to **172** passing assertions (47 new, 0
  removed, 0 modified). New coverage: the full Step 30 security test
  matrix — input edge cases (empty, whitespace, 10,000-character strings,
  Unicode homoglyphs, zero-width-joiner injection, SQLi, UNION SELECT,
  DROP TABLE, path traversal, CRLF injection, null bytes), an
  authorization matrix (unauthenticated / client A / client B), a CSRF
  matrix (missing/invalid/valid token crossed with GET/POST), an IP /
  trusted-proxy matrix (valid IPv4/IPv6, spoofed non-IP headers,
  malformed candidates), a security-header matrix (confirms every emitted
  header value is a fixed string with no CR/LF, i.e. header-injection-safe
  by construction), and a GeoIP matrix (public/private/loopback/link-local/IPv6
  ULA/invalid IPs against `IpUtil::isPrivateOrReserved()`), plus dedicated
  regression tests for each of the five fixes above.

### Changed

- `ClientController::limit_ip_range()`'s remove-range action now requires
  `POST` (previously accepted `GET`/`REQUEST`). The client-facing button
  and confirmation dialog are unchanged — only the underlying HTTP method
  changed, from a link click to a form submit.

### Database

- New non-destructive migration (schema version `2.4.0`): adds one
  existence-guarded row to `nnm_security_pack_schema_version` and nothing
  else. No table created, altered, or dropped; no setting added, changed,
  or removed. This phase was a code-review/hardening pass, not a
  data-model change.

### Compatibility

- Every admin and client route, every database table, and every settings
  key from 1.2.0 through 2.3.0 is fully preserved. The one visible change
  is that old bookmarked GET-based "remove IP range" links no longer
  execute (they now redirect safely to the Security Center instead of
  erroring) — see Changed, above. All 172 tests pass (125 pre-existing +
  47 new), and the module remains lint-clean across all 55 PHP files.

### Deferred

- Exhaustive byte-level fuzzing of the custom MaxMind DB binary parser
  (`lib/MaxMindDb/Reader.php`) against adversarial `.mmdb` input — the
  only entry point requires authenticated admin access + CSRF and already
  rejects anything that fails to parse; revisiting this is only warranted
  if the module ever accepts `.mmdb` data from a lower-trust source.
- `core/content_protection.php`'s inline `<script>` string interpolation
  of admin-configured (not request-controlled) language strings — not a
  vulnerability today, flagged as a pattern to avoid in any future touch
  of that file.
- CSP enforcement mode remains Report-Only, unchanged, per this phase's
  explicit instruction not to alter it during the assurance phase.
- This release does **not** claim the codebase is "fully secure" —
  `SECURITY-AUDIT-PHASE-4.md` documents precisely what was reviewed,
  what was fixed, and what remains explicitly out of scope.

## 2.3.0 — "Security Pack 2.3" Phase 3B

Security Pack 2.3.0 is the fourth implementation phase of the Security Pack
2.0 modernization project — Security Center navigation, a Client Security
Center, converting destructive admin actions from GET to POST+CSRF, and a
conservative, individually-toggleable set of security response headers —
built directly on 2.2.0 Phase 3A (Full Audit, IP Restrictions, GeoIP
Architecture), 2.1.0 Phase 2 (Security Score, Activity Center, RateLimiter,
IpUtil), and 2.0.0 Phase 1 (Security Events, Diagnostics, Trusted Proxies).
Nothing from any earlier phase was replaced, duplicated, or removed — every
existing `?module=security_pack&c=...` admin route and
`index.php?m=security_pack&page=...` client route from prior releases
continues to work exactly as before.

### Added

- **Security Center navigation.** The admin top navbar now groups related
  tabs under Bootstrap dropdown menus (Protection, Geo & Localization,
  Clients, System) via a new `NNM_Page_Builder::$menuGroups` property.
  This is purely a visual/organizational change — every tab's underlying
  `?module=security_pack&c=<name>` URL, routing, and controller is
  completely unchanged, so existing bookmarks, links from other parts of
  WHMCS, and anything scripted against these URLs keep working. Dashboard,
  Activity, and Settings are intentionally left as flat top-level items.
- **Client Security Center** (`index.php?m=security_pack&page=security_center`,
  linked from the client-area secondary navbar as "Account Security").
  Shows the logged-in client their own: simplified security status/
  strength summary, which optional account-security features are active
  (login notifications, two-factor authentication if detectable, password
  reset protection, session IP limits), their current session's browser/
  OS/IP/country, and their 10 most recent login events. Identity is
  always derived from `\WHMCS\Authentication\CurrentUser()`'s own session
  — never from a request parameter — so one client can never view or
  infer another client's data.
- **Security response headers** (Settings tab, new "Security Headers"
  panel): `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  strict-origin-when-cross-origin`, and a narrow `Permissions-Policy`
  (`geolocation=()`, `camera=()`, `microphone=()`) are each individually
  toggleable and default **on** for new/upgraded installs (no realistic
  compatibility risk). `Content-Security-Policy` is offered in
  **Report-Only** mode with a permissive default policy, and `Strict-
  Transport-Security` requires a second, explicit "this entire site is
  HTTPS-only" confirmation checkbox before it will ever be sent — both
  default **off** and stay off unless an admin deliberately enables them,
  since either can break checkout/third-party widgets or lock out
  visitors on a site not fully migrated to HTTPS. None of this touches
  the existing 1.2.0 `X-Frame-Options` toggle (Content Protection panel),
  which remains the sole owner of that header.
- New Diagnostics checks: Security Center Navigation, Client Security
  Center, Baseline Security Headers, Advanced Headers (CSP/HSTS), and
  State-Changing Actions (POST + CSRF) — extending the existing
  Diagnostics page rather than building a second status page.
- New Security Score sub-check: the existing "Architecture Health"
  category (10 → 15 points) now includes 5 points for having all three
  baseline security headers enabled. CSP/HSTS are deliberately excluded
  from scoring in either direction, since leaving them off is a
  legitimate, often-correct choice.
- `geo_cache.cleared` security event, recorded when an admin clears the
  GeoIP lookup cache from the Language & Currency panel (previously
  un-logged).
- 22 new test assertions in `tests/run.php` (103 → 125): header-scoring
  logic, the POST-only action allowlist pattern, CSRF double-submit token
  comparison, client-data session-scoping (proving a spoofed
  request-supplied client ID cannot widen access), and additional XSS
  payload coverage for the Phase 3A `LoginLogsController` fix.

### Changed

- **Destructive/state-changing admin actions converted from GET to
  POST-only, with CSRF enforced on every one:** removing a disabled-
  password-reset entry, removing an IP-limited-clients entry, Language &
  Currency country-override save/enable/disable/delete and cache
  clearing, and IP Restriction rule save/enable/disable/delete. A GET
  request to any of these actions is now rejected/redirected rather than
  executed — closing the "soft" GET+CSRF-token-in-URL finding noted as
  deferred in 2.2.0's `AUDIT.md`. No existing valid workflow changes for
  an admin using the UI normally; only the underlying HTTP method for
  these specific buttons/links changed, from a link to a small POST form.

### Security

- Closed the residual GET-based destructive-action finding from the
  2.2.0 audit (see Changed, above, and `AUDIT.md`).
- No new vulnerabilities were found during this phase's review of the
  legacy admin controllers beyond what 2.2.0 had already fixed
  (reflected XSS in `LoginLogsController`, missing CSRF on two delete
  actions) — see `AUDIT.md` for the full 2.3.0 audit entry.

### Database

- New non-destructive migration (schema version `2.3.0`): seeds
  `sh_nosniff`, `sh_referrer_policy`, and `sh_permissions_policy` to `"1"`
  the first time this migration runs, and only if each key is not already
  present — an admin who already visited Settings and explicitly turned
  one off will never have that choice silently overwritten by a later
  upgrade. No table is altered or dropped.

### Compatibility

- All 2.0.0/2.1.0/2.2.0 admin and client URLs, settings keys, database
  tables, and behavior are fully preserved. The Security Center
  navigation change is additive/visual only. All 125 tests pass
  (103 pre-existing + 22 new), and the module remains lint-clean.

### Upgrade Notes

- On upgrade, the three baseline security headers will start being sent
  automatically (seeded on by the 2.3.0 migration). If your site relies
  on embedding itself or third-party content in a way that could be
  affected by `Referrer-Policy` or `Permissions-Policy`, review the new
  Security Headers panel on the Settings tab after upgrading — each
  header can be individually turned back off with no other side effects.
- `Content-Security-Policy` and `Strict-Transport-Security` are **not**
  enabled by this upgrade and must be turned on deliberately.

### Deferred (honestly out of scope for this release)

- Security Center navigation is implemented as Bootstrap dropdown
  grouping of the existing flat tab list, not a full sidebar/framework
  rewrite of `NNM_Page_Builder` — this was a deliberate choice to avoid
  risking the routing/URL-compatibility guarantee above.
- The Client Security Center's "Current Session" card shows only the
  active session — WHMCS has no supported, addon-safe API for listing or
  remotely revoking a client's other active sessions, so this was not
  built. The page states this limitation to the client directly rather
  than implying a capability that doesn't exist.
- Two-factor-authentication status in the Client Security Center is
  detected defensively (via `method_exists()`/table-existence checks
  wrapped in `try`/`catch`) and shown as "not enough data" rather than a
  false positive/negative if the running WHMCS version's 2FA API can't be
  safely introspected.
- `Content-Security-Policy` is Report-Only, not enforcing — authoring a
  safe, enforcing CSP for an arbitrary WHMCS install (unknown payment
  gateways, themes, and third-party widgets) is not something this module
  can safely do generically.
- An exhaustive, formal line-by-line audit of every original 1.2.0-era
  controller was not performed in this phase; this phase's review focused
  on request-input-to-output data flow (echo/query-builder call sites)
  across all controllers and found no new issues beyond what 2.2.0 had
  already fixed. See `AUDIT.md`.

## 2.2.0 — "Security Pack 2.2" Phase 3A

Security Pack 2.2.0 is the third implementation phase of the Security Pack
2.0 modernization project — full security audit, centralized IP
Restrictions, and a provider-based GeoIP architecture — built directly on
2.1.0 Phase 2 (Security Score, Activity Center, RateLimiter, IpUtil) and
2.0.0 Phase 1 (Security Events, Diagnostics, Trusted Proxies,
non-destructive Settings save). Nothing from either phase was replaced or
duplicated.

Per its own scope, this release does **not** attempt the full nested
Security Center navigation, the complete Client Security Center, or a
Security Headers configuration UI — see Deferred, below.

### Security

A real code-level audit was performed (see `AUDIT.md` for full detail).
Two confirmed vulnerabilities were fixed, not just reported:

- **Reflected XSS fixed** in `LoginLogsController` — the admin Login
  History search page's IP-address field was echoing
  `$_REQUEST["ip_address"]` straight into an HTML attribute with no
  escaping. Now escaped like every other output in the module.
- **CSRF fixed** in `PasswordDisabledController` and
  `IpLimitedClientsController` — both deleted a database row directly off
  a bare `delete_id` GET parameter with **no CSRF token check at all**.
  Both now require and validate the existing Phase 1 CSRF token before
  deleting, and both now log the deletion as a security event.

Everything else audited (SQL injection across every query in `lib/`/
`core/`, the cURL GeoIP providers' URL construction, file-upload
validation for the MaxMind database, per-client authorization on every
client-area action, and `IpUtil`'s CIDR matching against a battery of
malformed/attack-style inputs) was confirmed already safe — see
`AUDIT.md` for what was checked and why nothing needed to change.

### Added — Centralized IP Restrictions

- **`IpRestrictionService`** (`lib\Security`) — the one authoritative
  ALLOW/BLOCK IP-rule evaluator, built entirely on the existing,
  already-tested `IpUtil` (no second CIDR implementation). Supports exact
  IPv4/IPv6 addresses and CIDR ranges, permanent or expiring rules, and a
  documented, deterministic precedence model: more specific match wins
  (exact IP over CIDR, narrower CIDR over broader), ties break on an
  admin-set Priority, remaining ties break on the most recently saved
  rule — never left to database row order.
- **New `nnm_security_pack_ip_rules` table** (additive migration, via the
  existing `nnm_security_pack_schema_version` mechanism) — deliberately
  separate from the pre-existing `nnm_security_pack_ips` table, which is
  the unrelated 1.2.0 per-client "Session IP Security Limits" feature.
- **New "IP Restrictions" admin page** (`lib/Admin/IpRestrictionsController.php`) —
  add/enable/disable/delete rules, with search-free list view showing
  type, target, status, expiration, priority, and who created each rule.
- **Admin lockout protection**, enforced server-side (never only in
  client-side JS): before saving a BLOCK rule, the current admin's
  detected IP is checked against the candidate rule (accounting for any
  existing rule that would already protect it); if it would be blocked,
  saving is stopped and an explicit "I understand — block it anyway"
  confirmation is required.
- **Safe by default:** with zero rules configured — the state of every
  upgraded install — `IpRestrictionService::evaluate()` always returns
  "allowed". Nothing is enforced just by upgrading to 2.2.0.
- **Scoped enforcement:** wired into the client area only, for guests,
  via the same hook location the existing (1.2.0) Country Restriction
  feature already uses safely. Admin-area and login-time enforcement are
  intentionally not implemented in this phase — see Deferred.
- All rule create/enable/disable/delete actions are recorded through the
  existing `security_pack_record_event()` system
  (`ip_rule.created`/`updated`/`enabled`/`disabled`/`deleted`/`blocked`).

### Added — Provider-based GeoIP Architecture

- **`GeoProviderInterface`**, **`GeoResult`**, **`GeoIpManager`**
  (`lib\Security`), **`MaxMindProvider`**, **`CurlApiProvider`**
  (`lib\Security\Providers`) — the existing, working MaxMind `.mmdb`
  parsing and curl/API fallback logic from 1.2.0 is reused verbatim behind
  these classes, not rewritten. `GeoIpManager` tries MaxMind first (local,
  no network call), then the curl/API providers, exactly matching prior
  behaviour, and never throws — any provider failure results in a clean
  failed `GeoResult`, never a broken page.
- `security_pack_resolve_country()` (used since 1.2.0 by Country
  Restriction, Language & Currency, and the admin Test-a-Lookup tool) is
  now a thin backward-compatible wrapper around `GeoIpManager` — same
  function name, same signature, same callers, same
  `nnm_security_pack_geo_cache` table (no cache data lost on upgrade).
- Private/reserved/invalid IPs (loopback, RFC1918, link-local, etc.) are
  rejected by `GeoIpManager` before touching the cache table or any
  provider — never sent to an external API.
- `GeoIpManager` receives its IP from the caller only — it does not
  itself inspect `CF-Connecting-IP`/`X-Forwarded-For`/`X-Real-IP`. The
  Phase 1 trusted-proxy-aware resolver remains the single place headers
  are interpreted.

### Changed

- `security_pack_is_trusted_proxy()` (Phase 1) now delegates to the new
  `IpUtil::matchesAny()` instead of carrying its own copy of the same
  CIDR-matching logic — one authoritative implementation for both Trusted
  Proxies and IP Restrictions.

### Extended (not replaced)

- **`SecurityScoreService`**: new "Architecture Health" category (IP
  Restrictions service availability, GeoIP provider availability).
  Deliberately scored as system/architecture health, not "did you turn on
  an optional feature" — an install with zero IP rules or only the
  default GeoIP provider is not penalized, only nudged with an info-level
  (not warning-level) recommendation.
- **Security Diagnostics**: new checks for the IP Restrictions
  service/table and rule count, and for GeoIP Manager provider
  availability — same page, not a second diagnostics system.
- **Security Center Overview**: new "IP Restrictions" status card.
- **`tests/run.php`**: grew from 40 to 103 assertions. All 40 original
  Phase 1/2 assertions still pass unchanged; 63 new assertions cover
  `IpUtil` CIDR/entry validation, `IpRestrictionService` rule precedence
  (specific-vs-CIDR, narrower-vs-broader, priority ties, id ties, IPv6),
  admin lockout detection, `GeoResult`, and a battery of malicious inputs
  (SQL injection strings, `<script>` tags, path traversal, `javascript:`
  URIs, null bytes, CRLF injection, malformed IPv4/IPv6/CIDR, and a
  10,000-character string) fed directly into `IpUtil`/
  `IpRestrictionService` to confirm they're safely rejected rather than
  matched, thrown on, or otherwise mishandled.

### Compatibility / Preserved

All Security Pack 1.2.0, 2.0.0, and 2.1.0 functionality — login history,
notifications, disable password reset, session IP limits, block free
email providers, email 2FA settings, content protection, country
restriction, GeoIP Language & Currency (MaxMind + curl providers, banner,
country rules, default fallback, advanced settings), Trusted Proxies,
Security Diagnostics, Security Events, non-destructive Settings save,
Security Center Overview, Security Score, Recommendations, Activity
Center, RateLimiter, Lagom2 client-area toggle switches — is untouched and
verified still present. No existing table was renamed, dropped, or
truncated.

### Database

New table (additive only, via the existing schema-version mechanism):
`nnm_security_pack_ip_rules`. No column was removed or renamed on any
existing table. `1.2.0 → 2.0.0 → 2.1.0 → 2.2.0` remains a safe incremental
upgrade path.

### Upgrade Notes

Same procedure as prior releases: back up, upload files, run the module
upgrade, open Security Diagnostics and confirm all checks pass (including
the two new ones), then optionally visit the new IP Restrictions page —
it does nothing until you add a rule.

### Final QA

```
Existing tests: 40
New tests:      63
Total:          103
Passed:         103
Failed:         0
```

All PHP files pass `php -l`.

### Deferred to Phase 3B+ (not yet built)

Per this phase's own explicit scope: the full nested Security Center
navigation tree (still blocked on `core/pagebuilder.php` only supporting a
flat tab bar); the complete Client Security Center redesign with session/
device management; a Security Headers configuration UI (CSP/HSTS/etc.);
IP Restrictions/rate-limiting enforcement on the actual WHMCS admin-area
or login hooks (client-area-for-guests is the only enforced scope in this
release); and converting the module's remaining GET-based-but-CSRF-token-
protected destructive links (see `AUDIT.md`) to POST+confirm, which is a
mechanical UI change better scoped as its own pass.

## 2.1.0 — "Security Pack 2.1" Phase 2

Security Pack 2.1.0 is the second implementation phase of the Security Pack
2.0 modernization project, building directly on the 2.0.0 Phase 1
foundation (Security Events, Diagnostics, Trusted Proxies, non-destructive
Settings save, schema versioning). Nothing from Phase 1 was replaced or
duplicated — every new piece in this release extends an existing
authoritative implementation rather than creating a competing one.

This is a partial implementation of the full Security Pack 2.1 "Security
Center" specification (see Deferred, below) — it ships the pieces that could
be built, tested, and verified not to break Phase 1/1.2.0 functionality in
this pass. It is not the complete redesign.

### Added

- **Security Center Overview (Dashboard).** New default landing page
  (`lib/Admin/DashboardController.php`) replacing the bare Settings form as
  the module's first screen. Shows the Security Score, a per-category
  breakdown, prioritized Security Recommendations, and status cards for
  Login Protection / IP Restrictions / Country Protection / GeoIP / Trusted
  Proxies / Content Protection with one-click links into their real
  settings pages. The old Settings tab is unchanged and still one click
  away (`c=settings`).
- **Dynamic Security Score service**
  (`lib\Security\SecurityScoreService`). Computes a deterministic 0-100
  score from 8 categories — Authentication, Login Protection, IP
  Protection, Geo Protection, Account Protection, Notifications, System
  Health, and Event Coverage — purely from actual settings/environment
  state. Nothing is hard-coded; `compute()` is a pure function (settings +
  facts in, score + category breakdown + recommendations out), which is
  what makes it unit-testable without a live database (see Testing,
  below).
- **Security Recommendations engine**, built into the score service.
  Every unmet check becomes a PASS/INFO/WARNING/CRITICAL recommendation
  with a direct link to fix it (e.g. "Trusted Proxies are not configured →
  Configure Trusted Proxies"), sorted by severity so the dashboard doesn't
  bury actionable warnings under a wall of PASS entries.
- **Security Activity Center** (`lib/Admin/ActivityController.php`, new
  "Activity" admin tab). A full filterable/paginated browser on top of the
  *existing* Phase 1 `nnm_security_pack_events` table — no second event
  table was created. Supports free-text search, event-type filter,
  severity filter, IP filter, country filter, and date-range filter, with
  pagination and an expandable structured-context row per event. The
  Diagnostics page's "Recent Security Events" panel now links here for
  full history instead of being the only view.
- **Centralized Rate Limiting service** (`lib\Security\RateLimiter`).
  Fixed-window rate limiting backed by a new, purpose-built
  `nnm_security_pack_rate_limits` counter table (deliberately *not* reused
  from `nnm_security_pack_events`, since a mutable "current count" and an
  append-only audit log are different responsibilities). The pure
  window-evaluation logic (`RateLimiter::evaluate()`) is unit tested in
  isolation. Applied in this release to the module's own two client-area
  AJAX toggle endpoints (disable-password-reset, login-notification) as a
  concrete, low-risk first use; **deliberately not wired into the core
  WHMCS admin/client login flow** in this release — see Deferred.
- **Single authoritative CIDR-matching implementation**
  (`lib\Security\IpUtil`). The Phase 1 `security_pack_is_trusted_proxy()`
  function now delegates to `IpUtil::matchesAny()` instead of carrying its
  own copy of the same logic, so IP Restrictions (Phase 3+) and Trusted
  Proxies share one tested implementation rather than two that could drift
  apart.
- **Plain-PHP automated test suite** (`tests/run.php`, run with
  `php tests/run.php`, no PHPUnit/Composer dependency required since the
  deployment target is a shared WHMCS host). 40 assertions covering IPv4/
  IPv6 CIDR matching, malformed-CIDR and attack-payload inputs (SQL/script
  injection strings as a "trusted proxy" entry), rate-limiter window
  boundaries and bypass attempts, and Security Score determinism
  (identical input always produces identical output; a stronger
  configuration never scores lower than a weaker one; missing database
  tables always surfaces a CRITICAL recommendation).
- Diagnostics page extended (not replaced — same page, same authoritative
  implementation) with checks for the new rate-limit table, the current
  schema migration version, and Rate Limiting service availability.

### Changed

- The module's default admin landing page is now the Security Center
  Overview instead of the bare Settings form. Settings functionality
  itself is completely unchanged, just reachable at its own tab/URL now
  rather than being the implicit default.

### Security

- `IpUtil::matchesOne()` rejects malformed CIDR masks and non-IP input
  without throwing, so a bad entry in an admin-entered Trusted Proxies /
  future IP Restrictions list can't take down request handling for every
  visitor.
- `RateLimiter::hit()` fails open (allows the request) if the rate-limit
  table is temporarily unavailable, rather than failing closed and locking
  every user out because of a transient DB issue.

### Compatibility / Preserved

All Security Pack 1.2.0 and 2.0.0 functionality — login history,
notifications, disable password reset, session IP limits, block free email
providers, email 2FA settings, content protection, country restriction,
GeoIP Language & Currency, MaxMind + curl providers, Trusted Proxies,
Security Diagnostics, Security Events, non-destructive Settings save,
Lagom2 client-area toggle switches — is untouched and verified still
present in this release. No existing table was renamed, dropped, or
truncated.

### Database

New tables (additive only, via the existing
`nnm_security_pack_schema_version` migration mechanism):
`nnm_security_pack_rate_limits`. No column was removed or renamed on any
existing table.

### Upgrade Notes

Same procedure as the 2.0.0 upgrade: back up, upload files, run the module
upgrade, then open Security Diagnostics and confirm all checks pass
(including the two new ones). No destructive migration is performed;
`1.2.0 → 2.0.0 → 2.1.0` is a safe incremental path in either one or two
hops.

### Deferred to Phase 3+ (not yet built)

This release does **not** include: the full nested "Security Center"
navigation tree from the original spec (the module's admin page framework,
`core/pagebuilder.php`, only supports a flat tab bar — building the nested
Overview/Activity/Protection/Authentication/Geo/Clients/Settings/System
menu tree would require replacing that framework, which is a larger,
separate change flagged here rather than done partially); the
provider-based `GeoProviderInterface`/`GeoIpManager` refactor of the
working MaxMind/curl GeoIP code; a redesigned Client Security Center page
with session/device management; centralized IP Restrictions (allow/block/
CIDR/temporary rules UI — `IpUtil` is ready for this, the admin UI and
rule table are not built yet); rate limiting on the actual WHMCS
admin/client login hooks (intentionally deferred — getting login lockout
behavior wrong is worse than not having it, and WHMCS already has its own
login throttling on that path); security headers (CSP/HSTS/etc.)
configuration UI; and the full code-level XSS/SQLi/CSRF/SSRF/path-traversal
security audit with fixes applied. These remain accurately described as
not-yet-built rather than claimed complete.

## 2.0.0 — "Security Pack 2.0" Phase 1

Security Pack 2.0.0 is the first implementation phase of the Security Pack 2.0
modernization project.

This release is intentionally focused on low-risk, high-value security and
infrastructure improvements built on top of the existing Security Pack 1.2.0
codebase. The existing 1.2.0 functionality, database tables, configuration
keys, and WHMCS integrations are preserved. This release does **not** attempt
the complete architectural and UI/UX redesign described in the Security Pack
2.0 roadmap. The larger Security Center redesign will be delivered
incrementally in subsequent phases.

### Added — Centralized Security Event System

Added a new centralized security-event infrastructure.

New database table: `nnm_security_pack_events`

Security-relevant actions can now be recorded in a single, queryable event
log.

Added: `security_pack_record_event($type, $message, $context, $severity)`

Events currently recorded include:

- Client logins
- Admin logins
- IP-range login blocks
- Country-restriction blocks
- Security settings changes

Events are designed to avoid recording sensitive authentication material such
as passwords, authentication tokens, API secrets, and session tokens.

**Event severity.** Events support severity levels so future versions can
build filtering, alerting, and security scoring on top of the same
infrastructure. Current levels: `info`, `warning`, `critical` (the roadmap
label set — `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` — will be mapped onto this
same column when the Security Score/Activity Center work in Phase 2 lands,
rather than requiring a second severity scheme).

**Event retention.** Security-event retention is configurable. Default: 90
days. Old events are automatically pruned by the existing cron infrastructure.

### Added — Security Diagnostics

Added a new Security Diagnostics administration page. The diagnostics page is
always available from the admin navigation and provides visibility into the
health of the Security Pack installation.

Current diagnostics include:

- PHP version
- Required PHP extensions
- Security Pack database tables
- GeoIP database status
- Security Pack data-directory permissions
- CSRF token generation
- Visitor IP detection
- Trusted Proxy configuration
- Recent security events

Checks are reported as `PASS`, `WARNING`, or `FAIL`.

The page also provides a live view of the most recent security events. The
current diagnostics view displays the latest 25 events.

### Security Hardening — Trusted Proxies

Added trusted-proxy-aware visitor IP detection. Security Pack can now
distinguish between a direct client connection, a trusted reverse proxy, and
untrusted forwarded headers.

Forwarded IP headers such as `CF-Connecting-IP`, `X-Forwarded-For`, and
`X-Real-IP` are only trusted when the direct TCP peer is configured as a
trusted proxy. This prevents an attacker from simply sending a forged
forwarded-IP header to spoof their apparent IP address.

**Why this matters.** The detected visitor IP can affect GeoIP lookups,
country restrictions, IP-range restrictions, login security, and security
event logging. Without trusted-proxy validation, a visitor could potentially
manipulate these systems by supplying forged forwarding headers.

**Backward compatibility.** Trusted Proxies are disabled by default. If the
Trusted Proxies list is empty, Security Pack continues using the existing
1.2.0 behavior. Administrators using Cloudflare or another reverse proxy can
explicitly configure the appropriate trusted proxy IP/CIDR ranges.

### Fixed — Destructive Settings Save

Fixed a significant data-loss issue in the main administration Settings tab.

**Previous behavior.** `SettingsController::save()` previously used a
destructive operation equivalent to truncating the settings table and then
recreating only the settings submitted by that particular form. This meant
that saving the main Settings page could unintentionally remove settings
belonging to other Security Pack administration pages — for example, settings
belonging to GeoIP Language & Currency, Advanced Settings, Default Fallback,
Trusted Proxies, or Event Retention could be silently removed when the main
Settings form was saved.

**New behavior.** Settings are now updated non-destructively. The main
Settings form only modifies the configuration keys it owns. Other settings
remain untouched. This eliminates the cross-page settings data-loss problem.

### Added — Non-Destructive Schema Versioning

Added `nnm_security_pack_schema_version`. This provides the foundation for
ordered, idempotent database migrations in future releases. Migrations can
now detect the current schema version, apply only required changes, avoid
re-running completed migrations, add new tables safely, add new columns
safely, and support future incremental upgrades.

No destructive schema migration is performed by this release.

### Preserved — Security Pack 1.2.0 Functionality

**Login Security:** login history, login notifications, session IP security
limits.

**Account Protection:** disable password reset, block free email providers,
email 2FA settings.

**Content Protection:** existing content-protection controls.

**Country Restriction:** existing country restriction functionality.

**GeoIP Language & Currency:** MaxMind provider, cURL/API fallback providers,
country-based rules, language selection, currency selection, banner
functionality, default fallback configuration, advanced settings.

**Client Area:** existing Security Settings integration remains available,
including login notifications, disable forgot password / password reset, and
session IP security limits.

**Theme Compatibility:** the existing JavaScript-driven toggle implementation
for Lagom2 compatibility remains intact.

### Database Compatibility

Security Pack 2.0.0 is designed as an incremental upgrade. Existing Security
Pack 1.2.0 tables are retained. No existing table is renamed or removed by
this release. No existing production data is intentionally deleted or
migrated destructively. New infrastructure is added alongside the existing
schema.

New tables: `nnm_security_pack_events`, `nnm_security_pack_schema_version`.

Existing tables remain available for backward compatibility.

### Upgrade Notes

Before upgrading a production installation:

1. Create a normal WHMCS/database backup.
2. Upload the new Security Pack files.
3. Run the module upgrade process.
4. Open Security Diagnostics.
5. Confirm all required checks pass.
6. Review the recent Security Events.
7. If the installation uses Cloudflare or another reverse proxy, configure
   the appropriate Trusted Proxy IP/CIDR ranges.
8. Test: client login, admin login, GeoIP detection, country restriction,
   login notifications, client Security Settings.

**Important:** do not configure arbitrary IP addresses as trusted proxies.
Only add infrastructure that you actually control and that legitimately sits
in front of the WHMCS installation.

### Compatibility

Security Pack 2.0.0 remains based on the existing WHMCS module architecture.
This release is intended to minimize production risk while preparing the
module for the larger Security Pack 2.0 architecture. Existing functionality
is retained rather than replaced.

### Deferred — Security Pack 2.0 Phase 2+

The following larger changes are intentionally not included in 2.0.0. They
will be implemented incrementally after Phase 1 has been validated in
production.

**Security Center UI:** complete Security Center product redesign, modern
admin dashboard, new administration navigation, security overview, security
status cards, dynamic security score, security recommendations.

**Security Activity:** full security activity interface, advanced event
filtering, search, pagination, event detail views, security event analytics.

**Architecture:** provider-based `GeoProviderInterface`, `GeoIpManager`,
centralized rate-limiting service, structured security services, namespaced
`src/Core`, `src/Security`, `src/Geo`, etc., separation of business logic
from templates.

**Client Security Center:** redesigned client security dashboard, active
session management, device management, security activity, security
recommendations, improved client security controls.

**Security Hardening:** a broader security audit is planned covering XSS,
SQL injection, CSRF, authentication bypass, authorization issues, session
security, IP spoofing, trusted-proxy bypass, rate-limit bypass, information
disclosure, unsafe redirects, SSRF, and related attack surfaces.

**Testing:** a comprehensive automated test suite is planned for IP
detection, CIDR matching, trusted proxies, GeoIP, country restrictions,
CSRF, login events, settings migration, upgrade migrations, rate limiting,
and session security.

### Phase 1 Scope

Security Pack 2.0.0 intentionally focuses on three immediate objectives:

1. **Prevent data loss.** Fix the destructive Settings save behavior.
2. **Improve IP security.** Introduce trusted-proxy-aware IP detection.
3. **Build the foundation.** Introduce centralized security events, event
   retention, diagnostics, and schema versioning.

These components provide the foundation for the larger Security Center
architecture without requiring a risky full rewrite of the production module.

### Release Summary

Security Pack 2.0.0 is an infrastructure and hardening release, not the
final Security Center redesign. The release preserves the existing 1.2.0
functionality while addressing a real settings data-loss bug, improving
visitor-IP security, introducing centralized security-event logging, adding
diagnostics, and establishing a safe migration foundation for future 2.0
releases.

**Next major direction:**

```
Security Pack 1.2.0
        │
        ▼
Security Pack 2.0.0 — Phase 1
        │
        ├── Data-loss fix
        ├── Trusted Proxy security
        ├── Security Events
        ├── Diagnostics
        └── Schema Versioning
        │
        ▼
Security Pack 2.1+ — Phase 2+
        │
        ├── Security Center Dashboard
        ├── Security Score
        ├── Activity Center
        ├── New Architecture
        ├── Rate Limiting
        ├── Client Security Center
        ├── Provider-based GeoIP
        └── Full Security Audit
```

## 1.2.0 and earlier

See prior release notes / commit history for the GeoIP Country-Based
Language & Currency feature, MaxMind-primary/curl-fallback provider
architecture, self-contained CSRF protection, client-area Security Settings
integration (Login Notification / Disable Forgot Password Reset / Session IP
Security Limits), and the JS-driven toggle switch fix for Lagom2 theme
compatibility.
