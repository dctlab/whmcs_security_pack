# dct_totp_native — Time-Based Token (Enhanced)

A modern, secure, maintainable replacement for WHMCS's native "Time Based
Tokens" Security Module (`modules/security/totp/totp.php`).

## Why this exists

WHMCS's native TOTP module (confirmed by reading its own decoded source —
never copied, see "What was verified" below) has several real gaps:

- **Replay protection is weak.** It only checks a 5-minute rolling
  "already-used" list. A code stolen and replayed after that window is
  accepted again.
- **QR generation can leak the secret.** Its `totpQrGenerator()` prefers a
  local generator but *silently falls back* to `RemoteQrGenerator`, which
  sends the otpauth:// URI — including the raw secret — to a third-party
  API (`api.qrserver.com`) if local dependencies aren't met.
- **No recovery codes.** Lose the device, and an administrator must
  manually disable 2FA for the account.
- **No rate limiting** on login attempts or enrollment verification.
- **No trusted-device bypass** option for lower-friction repeat logins
  from a known location.

This module preserves native TOTP's actual behavioral contract (same
RFC 6238 algorithm, same bare-controls `challenge()` shape WHMCS's login
page expects) while fixing all five gaps above.

## Installation

Copy `modules/security/dct_totp_native/` into your WHMCS installation's
own `modules/security/` directory. It does **not** touch or replace
`modules/security/totp/` — that directory, and every account already
enrolled in native "Time Based Tokens", is left completely alone. This
module appears as a separate, additional option ("Time-Based Token
(Enhanced)") under **Setup > Security > Two-Factor Authentication**.

No addon module install step, no database migration to run by hand — the
first time any part of this module actually executes (an enrollment
attempt or a login challenge), it creates its own tables automatically
(see `lib/Schema.php`). It has **no dependency on any other addon
module** — it is fully standalone.

## What's different from native, and why

| Area | Native `totp.php` | This module |
|---|---|---|
| Replay protection | 5-minute used-code list (MD5 hash of email+code) | Persisted `last_used_step` (RFC 4226 counter) — rejects any code at or below one already accepted, permanently, not just within a rolling window |
| QR code | Local generator, silently falls back to a remote third-party API that receives the secret | Always local (`lib/QrGenerator.php`, a from-scratch ISO/IEC 18004 encoder) — the secret never leaves the server, no fallback that could leak it |
| Recovery | None | 10 single-use recovery codes (bcrypt-hashed at rest), enterable in the same login field as a TOTP code |
| Rate limiting | None | Fixed-window rate limiting on both enrollment verification and login attempts |
| Trusted-device bypass | None | Optional, administrator-controlled same-account + same-IP bypass (off by default) |
| Secret at rest | Stored via WHMCS core's own `user_settings` storage | Encrypted with libsodium secretbox before storage, using a dedicated per-install master key (`lib/KeyStore.php`) |
| Identity resolution at login | `$params['user_info']['id']` directly | Same field, but explicitly never falls back to ambient PHP session state — WHMCS shares one session between admin and client areas, so a stale unrelated session can otherwise leak into a fresh login's identity resolution |

## What was preserved from native, and confirmed how

Native WHMCS's own `totp.php` (ionCube-encoded; decoded only to read its
*behavioral contract*, never copied — its `lib/Generator/*` classes and
`ga4php.php` legacy shim were **not** read or adapted at all) confirmed
one critical, easy-to-get-wrong detail: `totp_challenge()` returns a bare
`<div><input type="text">...<input type="submit"></div>` — **no `<form>`
tag**. WHMCS's own login page already supplies the enclosing
`<form action="dologin.php">`, its CSRF token, and its submit handling. A
Security Module that nests a second `<form>` inside that outer form
corrupts it. `dct_totp_native_challenge()` matches this exact contract —
verified with a source-level test asserting no `<form>` tag ever appears
in its output (see `tests/run.php`).

## Cryptographic engine

As of 1.1.0, all TOTP/HOTP code generation and secret generation is
delegated to [robthree/twofactorauth](https://github.com/RobThree/TwoFactorAuth)
(MIT licensed, PHP >=8.2, no required dependencies for its core
class) — vendored verbatim at `lib/vendor/robthree/twofactorauth/`
(commit `85408c4e775dba7c0802f2d928efd921d530bc5b`, tag `v3.0.3`).
Only the dependency-free core is vendored; every QR-rendering provider
the library ships was deliberately left out (some need extra Composer
packages, and the HTTP-based ones send the secret to a third party) —
QR codes here always come from this module's own local
`lib/QrGenerator.php`. This module never calls the library's own
`verifyCode()` convenience method — see CHANGELOG 1.1.0 for a real
boundary-case bug found in it and why `Totp::matchingStep()` avoids it.
**Requires PHP 8.2+** (the library's own minimum); `_bootstrap()`
throws a clear error on an older PHP before loading any vendor file.

## Configuration

- **Allow Same-IP Bypass** (off by default): after a successful code
  entry, skip the challenge on later logins from the same account + same
  IP address.
- **Bypass Duration**: 1-90 days, only used if the above is enabled.

## Testing

```
php tests/run.php
```

106 assertions: real execution of the RFC 6238/4226 math (now delegated
to robthree/twofactorauth, see "Cryptographic engine" above) against
the official RFC 6238 Appendix B SHA-1 test vectors and RFC 4226
Appendix D HOTP test vectors, base32 round-tripping, tolerance-window
and replay-determinism checks, libsodium encrypt/decrypt
round-tripping, `RateLimiter`'s pure fixed-window logic, plus
source-contract checks (the bare-controls challenge contract, no
third-party QR call anywhere in the executable code, replay logic uses
`<=` not `<`, secrets are always encrypted before storage, `EventLog`
never references a secret/code variable, every schema table create is
`hasTable()`-guarded, the vendored library's `verifyCode()` is never
called and `hash_equals()` is, vendor file require-order/provenance)
and a `php -l` syntax lint of every file, including the vendored
`lib/vendor/` subtree.

## Known limitations

- WHMCS core has no "user disabled 2FA" callback into a Security Module,
  so if an administrator/client clears `second_factor` via WHMCS's own
  UI, this module's own `mod_dct_totp_native_secrets` row is not
  automatically updated to `disabled`. This mirrors how native `totp.php`
  itself behaves (it has no such callback either) — the account simply
  stops being challenged, and the orphaned row is harmless (no live
  credential exposure; the encrypted secret still requires the server's
  master key to decrypt). An administrator can call
  `Enrollment::disable($userId, $userType, "admin")` directly if explicit
  cleanup is desired.
- The same-IP bypass feature is only as accurate as `$_SERVER['REMOTE_ADDR']`
  — behind a reverse proxy/CDN this may be the proxy's own IP rather than
  the real client's, which can make the bypass window less precise (never
  less secure — it only affects whether the *optional, opt-in* bypass
  matches, never whether a TOTP/recovery code itself is accepted).
- Not yet live-acceptance-tested against a real running WHMCS install
  (enrollment via the actual admin/client UI, a real authenticator app,
  the real `dologin.php` POST cycle). Everything above was verified via
  the automated test suite and direct source review; a live end-to-end
  pass through the actual WHMCS login flow is still outstanding.
