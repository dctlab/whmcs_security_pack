# Changelog — dct_totp_native

## 1.2.0 — Enrollment now shows the "wrong code" error, button relabeled

**Root cause:** confirmed against native `totp.php`'s own `totp_activate()`
(which reads `$params['verifyError']` and renders it in a red alert box):
WHMCS core re-invokes `_activate()` after a failed `_activateverify()`
call and passes the caught exception's message back in as
`$params["verifyError"]`. `dct_totp_native_activate()` never read this
key at all, so submitting a wrong code silently reset the enrollment
form back to the QR screen with no explanation — the rejection was
working correctly (confirmed in 1.0.1/1.1.0), it just wasn't visible to
the user, who saw what looked like nothing happening.

**Fixed:** `dct_totp_native_activate()` now reads `$params["verifyError"]`
and renders it in a `.alert.alert-danger` box above the code field,
matching native's own placement and styling.

**Also changed:** the enrollment submit button now reads "Submit"
(previously "Enable Time-Based Token").

**Testing:** 106/106 (unchanged — this was a template/rendering change
with no new pure-logic branch to unit test), `php -l` clean.

## 1.1.0 — TOTP/HOTP math now delegated to robthree/twofactorauth

**What changed:** `lib/Totp.php` no longer computes RFC 6238/4226
HMAC-based codes itself. It now delegates to
[robthree/twofactorauth](https://github.com/RobThree/TwoFactorAuth)
(MIT licensed, PHP >=8.2, zero required dependencies for its core
class), vendored verbatim at
`lib/vendor/robthree/twofactorauth/` — commit
`85408c4e775dba7c0802f2d928efd921d530bc5b`, tag `v3.0.3`. This is the
most widely used standalone PHP TOTP library (no framework dependency,
actively maintained since 2014); running the actual code-generation
math through it means that math is exercised by many other projects,
not just this one.

**Scope of vendoring:** only the dependency-free core was vendored —
`TwoFactorAuth`, `Algorithm`, `TwoFactorAuthException`, the CSRNG and
local-machine-time providers, and the `IQRCodeProvider` interface.
Every QR-rendering provider shipped by the library was deliberately
excluded — some need extra Composer packages, and the HTTP-based ones
send the secret to a third party. QR codes here still come entirely
from this module's own local `lib/QrGenerator.php`; a new
`lib/NullQrCodeProvider.php` satisfies the library's required
constructor argument without ever being invoked.

**Public API unchanged:** every other file (`Enrollment`, `tests`)
calls the exact same static `Totp::` methods as before — this was an
engine swap underneath an unchanged interface, not a rewrite of every
call site.

**A real bug found in the vendored library, and how it was avoided:**
this module's own RFC 4226 Appendix D test vectors (secret
`"12345678901234567890"`, counter 0 → code `"755224"`) caught a
boundary-case bug in robthree/twofactorauth's `verifyCode()`
convenience method: it initializes `$timeslice = 0` and returns
`$timeslice > 0`, so a genuine match at counter/timeslice 0 is
indistinguishable from "no match" — the return value is `false`
either way. Counter 0 only occurs at or before the Unix epoch and is
never reachable with a real wall-clock timestamp, so this is not a
practical vulnerability, but it is a genuine correctness gap. Fixed by
never calling `verifyCode()` at all: `Totp::matchingStep()` loops over
the tolerance window itself using the library's `getCode()` primitive
(the actual HMAC/base32 computation) and this module's own
`hash_equals()` comparison. Regression tests assert `->verifyCode(`
never appears in `Totp.php`'s source and `hash_equals(` does.

**Requirements:** PHP 8.2+ is now required (robthree/twofactorauth's
own minimum). `dct_totp_native_bootstrap()` throws a clear
`\RuntimeException` on an older PHP before touching any vendor file —
the guard lives in `_bootstrap()`, not `_config()`, so the module stays
listable in the admin UI even on an incompatible host.

**Testing:** 106 assertions, all passing (up from 83) — added: vendor
file provenance/require-order checks, and source-contract assertions
that `Totp.php` never calls `->verifyCode(` and does call
`hash_equals(`. `php -l` clean across every file, including the new
`lib/vendor/` subtree.

## 1.0.1 — CRITICAL: enrollment accepted an incorrect code

**Root cause:** confirmed against native `totp.php`'s own
`totp_activateverify()`: WHMCS core decides enrollment success/failure
purely by whether an exception was thrown — never by inspecting a
returned array's content. `dct_totp_native_activateverify()` returned
`["msg" => "..."]` on both the success and every failure path, with no
exception thrown either way, so WHMCS core treated every submission —
including a wrong/fake code — as a successful activation, while this
module's own `Enrollment` table correctly stayed un-activated (which
would have locked the account out at the next real login). Confirmed
live via a real enrollment attempt with an intentionally incorrect code.

**Fixed:** `dct_totp_native_activateverify()` now throws
`\WHMCS\Exception` on every failure path and returns
`["settings" => [], "msg" => "..."]` on success — matching native's
confirmed `"settings"` contract key. Whether WHMCS also surfaces the
`"msg"` key (used here to deliver the one-time recovery codes) on a
successful call is flagged UNVERIFIED in the code — this needs a real
live test to confirm the recovery codes actually reach the user.

**Testing:** 4 new assertions (83 total, all passing) confirm
`activateverify()` throws on every failure path and returns `"settings"`
on success.

## 1.0.0 — Initial release

New, standalone Security Module — a modern replacement for WHMCS's native
"Time Based Tokens" module, installed alongside it (never overwriting
`modules/security/totp/`).

**Added:**
- RFC 6238 TOTP (`lib/Totp.php`), verified against the official RFC 6238
  Appendix B SHA-1 test vectors.
- Persisted-counter replay protection (`last_used_step`), rejecting any
  code at or below one already accepted — not just within a rolling
  time window.
- Always-local QR code generation (`lib/QrGenerator.php`, a from-scratch
  ISO/IEC 18004 encoder) — no third-party API call, ever.
- 10 single-use recovery codes (`lib/RecoveryCodes.php`), bcrypt-hashed
  at rest, enterable in the same login field as a TOTP code.
- Fixed-window rate limiting (`lib/RateLimiter.php`) on enrollment
  verification and login attempts.
- Optional, off-by-default trusted-device (same-account + same-IP)
  bypass (`lib/Bypass.php`), administrator-controlled duration
  (1-90 days).
- Secret-at-rest encryption via libsodium secretbox
  (`lib/Totp.php::encryptSecret()`/`decryptSecret()`), with a dedicated
  per-install master key (`lib/KeyStore.php`).
- Idempotent, lazy schema creation (`lib/Schema.php`) — no install-time
  migration step required; tables are created on first real use.
- 76-assertion automated test suite (`tests/run.php`): real execution of
  every pure/dependency-free code path, source-contract checks for
  everything that requires a live database, and a `php -l` lint pass.

**Explicitly NOT done in this release** (see README's "Known
limitations"): live end-to-end acceptance testing against a real running
WHMCS install (real admin/client enrollment UI, a real authenticator
app, a real `dologin.php` POST cycle).
