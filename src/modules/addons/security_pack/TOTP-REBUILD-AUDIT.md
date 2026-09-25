# TOTP Rebuild Audit — `modules/security/dct_totp_2fa/` (Security Pack 3.1.17)

This document records what the "REBUILD dct_totp_2fa" ticket required, what was
actually verified against a real reference implementation, what was changed, what
was deliberately left alone, and — per the ticket's own explicit closing
instruction — what has **not** been demonstrated on a real WHMCS installation and
therefore cannot be claimed as proven.

Confidence tags used throughout, per this project's own development discipline:
**VERIFIED** (read directly from real, decoded source or this project's own code
and tests), **PATTERN** (a reasonable implementation choice, not itself a WHMCS
platform guarantee), **UNVERIFIED** (plausible but not confirmed against a live
WHMCS installation).

## 1. The reference implementation

The behavioral baseline supplied for this rebuild was `totp.php`, a 202-line
deZender-decoded copy of WHMCS 9.0.6's real, native `modules/security/totp/totp.php`
— **VERIFIED** genuine (readable PHP source, not ionCube/encoded garbage; a second
copy supplied alongside it, at a different path, was confirmed via `diff` to still
be ionCube-encoded and was not used for anything). This file was read in full and
used only to understand the *contract* WHMCS itself expects from a Security
Module — not copied from. No code from it was reused verbatim anywhere in this
project; every native function's behavior is described below in this project's own
words, from that reading.

## 2. Native WHMCS Security Module contract — what was learned

| Lifecycle point | Native `totp.php` behavior (VERIFIED, from source) |
|---|---|
| `totp_config()` | Returns `FriendlyName`/`ShortDescription`/`Description` only — no algorithm/digit/period fields exposed as configurable. |
| `totp_activate($params)` | Reads `$params['user_info']['username']`, generates/stores a secret via `WHMCS\Session::get/set('totpKey')` + WHMCS's own `encrypt()`/`decrypt()`, renders full enrollment HTML (QR, manual secret, code input) with **no enclosing `<form>`** — this call is embedded inside WHMCS's own activation modal/page, which already supplies the form. |
| `totp_activateverify($params)` | Reads `$params['post_vars']['verifykey']` and `$params['user_info']['email']`; throws `WHMCS\Exception` on a mismatch; on success calls `totp_add_to_used_codes()` (see replay, below) and returns `['settings' => ['secret' => $secret]]`. |
| `totp_get_fields($params)` | Declarative field metadata. **UNVERIFIED** whether WHMCS's real login flow actually consults this, or whether it is legacy/unused, since `totp_challenge()` independently renders full HTML on its own regardless. |
| `totp_challenge($params)` | **The single most important, concretely confirmed fact for this rebuild**: returns ONLY `<div align="center"><input type="text" name="key" maxlength="6" …><br/><input type="submit" value="Login"></div>` — **no `<form>` tag anywhere**. WHMCS's own login page supplies the enclosing `<form action="dologin.php">`, CSRF token, and submit handling. |
| `totp_get_used_otps()` / `totp_add_to_used_codes($email, $code)` | Native replay protection: `md5($email . $code)` is stored in a flat array kept in `WHMCS\Config\Setting::getValue('TOTPUsedOTPs')` (a single global serialized setting, not scoped per-account beyond the email in the hash), pruned to entries less than 300 seconds (5 minutes) old. This is weaker/less structured than what this rebuild implements (see §5) but confirms replay protection is an expected, standard part of the contract, not an invented requirement. |
| `totp_verify($params)` | Reads `$params['post_vars']['key']` and `$params['user_info']['email']`; checks the used-codes list first, then verifies via either a legacy `tokendata` path or `$userSettings['secret']` via `Sonata\GoogleAuthenticator\GoogleAuthenticator::checkCode()`. |
| `totp_loadgaclass()` | Legacy-compatibility shim, not relevant to this rebuild. |
| `totp_getLangString()` | Switches admin vs. client language strings based on `defined('ADMINAREA')`. |

**The one concrete, load-bearing conclusion drawn from this table**: `challenge()`
must never return its own `<form>` tag. Everything else in the native reference
informed understanding of the contract but did not require a code change here,
because Security Pack's existing TOTP architecture (built independently, before
this rebuild) already satisfied the equivalent requirements — see §3.

## 3. What was already correct before this rebuild (preserved, not rebuilt)

Per the ticket's own "NO DUPLICATION RULE" and "study existing architecture first"
instructions, the following were read in full, confirmed correct against the
ticket's requirements, and deliberately left untouched:

- **RFC 6238/4226 math** (`TotpService.php`): SHA-1, 6 digits, 30-second period, ±1
  step clock tolerance, `hash_equals()` constant-time comparison, `random_bytes()`
  secret generation (never `rand()`/`mt_rand()`/`uniqid()`/a predictable seed),
  standard `otpauth://totp/` provisioning URI. **VERIFIED** via direct code
  inspection and this project's own RFC 6238 Appendix B test-vector unit tests
  (`tests/run.php`), which passed before this rebuild and continue to pass after
  it (the `verify()` refactor in §5 is proven zero-regression by the same tests).
- **Secret-at-rest encryption** (`TotpKeyStore.php` + `TotpService::encryptSecret()`/
  `decryptSecret()`): libsodium `sodium_crypto_secretbox` (XSalsa20-Poly1305) with a
  server-side, non-web-accessible 32-byte master key generated via
  `sodium_crypto_secretbox_keygen()`, stored under `core/data/` (the same directory
  already `.htaccess`-protected for the MaxMind database). Refuses to fall back to
  weak/no encryption if libsodium is unavailable or the key is malformed —
  throws instead. Untouched by this rebuild.
- **QR generation** (`TotpQrGenerator.php`): a from-scratch, dependency-free
  ISO/IEC 18004 encoder rendering an inline SVG, deliberately never sending the
  secret to a third-party QR API. Untouched.
- **Enrollment state machine** (`TotpEnrollmentService.php`): pending → active,
  never activates before a successful verification of the enrollment code
  (`beginEnrollment()` / `verifyAndActivate()`). Untouched structurally; only the
  replay-baseline persistence described in §5 was added to `verifyAndActivate()`.
- **User identity resolution**: `dct_totp_2fa_login_identity()` (3.1.14) and
  `dct_totp_2fa_account_identity()` (3.1.15) — both already correctly resolve
  identity from `$params['user_info']['id']` (the one value WHMCS itself supplies
  for a given Security Module call) rather than ambient session state, which a
  real production bug (documented in the 3.1.14/3.1.15 changelog entries) proved
  was necessary. Untouched by this rebuild.
- **Mutual exclusion**: `dct_totp_2fa_activateverify()` already calls
  `TwoFactorAuthenticationService::activateExclusive("totp", …)` on success, so
  activating TOTP already correctly deactivates any other active method
  (Email/WhatsApp) without deleting its enrollment. Untouched.
- **Administrator / same-IP bypass**: `dct_totp_2fa_bypass_active()` already
  delegates to `TwoFactorBypassService::findActive()`, and `dct_totp_2fa_verify()`
  already grants a same-IP bypass via `TwoFactorBypassService::grantSameIpBypass()`
  when enabled. Untouched.
- **Rate limiting**: `TotpEnrollmentService::verifyAndActivate()`/`verifyLogin()`
  already rate-limit via the existing, shared `RateLimiter::hit()` — never a
  second/duplicate rate limiter. Untouched.

## 4. Fixed — the challenge-form contract violation

**Confirmed bug** (VERIFIED against the native reference in §2):
`dct_totp_2fa_challenge()` returned its own nested
`<form action="dologin.php" method="post">…</form>` for the main code-entry path,
and a second, separate nested `<form id="dct_totp_2fa_bypass_form" …>` for the
same-IP bypass auto-submit path — both inside WHMCS's own outer login `<form>`.
This is very likely the true root cause of a long-standing, previously reported
"incorrect and not currently active simultaneously" garbled TOTP login screen
symptom, since a nested form corrupts the outer form's native submit/CSRF/field
handling in ways that are highly browser- and markup-dependent.

**Fix**: both paths now return only bare controls, matching the native reference's
own bare-`<div>`/`<input>`/`<input type="submit">` shape:

- Main path: a bare text input (`name="dct_totp_2fa_code"`) and a bare submit
  button, no `<form>`.
- Bypass path: a bare hidden input (`name="dct_totp_2fa_bypass" value="1"`) plus a
  small inline script that submits the **enclosing** form —
  `document.currentScript.closest("form")`, falling back to `document.forms[0]` for
  older browsers without `Element.closest()` — rather than creating and submitting
  a form of its own.

## 5. Added — OTP replay protection (confirmed gap, now closed)

**Confirmed gap** (VERIFIED by direct code inspection of `TotpEnrollmentService.php`
and `TotpService.php` before this rebuild): neither file contained any mechanism
to reject a previously-accepted code. A captured, valid TOTP code could be
replayed within its ~30-90 second validity window (accounting for the ±1 step
clock-tolerance) and would be accepted a second time.

**Design constraint** (from the ticket's "NO DUPLICATION RULE" and "do NOT create
another database table unless the audit proves one is absolutely necessary"):
this had to be additive to the existing architecture, not a second, parallel
replay-tracking system.

**Implementation**:

- `TotpService::matchingStep(...)`: a new **pure** method (no I/O) that performs
  the identical ±1-step search and `hash_equals()` comparison `verify()` always
  did, but returns the matched RFC 4226 HOTP **counter** (or `null`) instead of a
  bare boolean. `TotpService::verify()` is now defined purely as
  `matchingStep(...) !== null` — a zero-behavioral-regression refactor, proven by
  the existing RFC 6238 test-vector unit tests continuing to pass unchanged.
- `nnm_security_pack_totp2fa.last_used_step`: **one new nullable column** on the
  *existing* TOTP table (not a new table), added via an idempotent
  `hasColumn()`-guarded migration in `security_pack.php`. This is the "additive
  column, not a new database" the NO DUPLICATION RULE calls for.
- `TotpEnrollmentService::verifyLogin()`: now rejects any code whose matched step
  is `<=` the account's stored `last_used_step` (this correctly rejects both an
  exact replay of the same code and an older, previously-superseded code, since
  TOTP counters increase monotonically with wall-clock time), returning a new
  `"replayed"` status and recording a new `2fa.totp.replay_rejected` security
  event (distinct from the generic `2fa.verification.failed`, so a replay attempt
  is distinguishable in the audit log from an honestly-wrong code). On a
  successful, non-replayed verification, the new step is persisted.
- `TotpEnrollmentService::verifyAndActivate()`: also persists an initial
  `last_used_step` baseline on successful enrollment activation, so the very next
  login (even one within the same clock-tolerance window as activation) has a
  real value to compare against rather than an unset column.

**Migration / backward compatibility**: the new column is nullable and starts
`NULL` for every row that already exists at upgrade time — including already-active
enrollments. No secret is touched, re-encrypted, or invalidated by this migration,
and no re-enrollment is required. An account with an existing active enrollment
simply establishes its first `last_used_step` baseline on its next successful
login, exactly as a brand-new enrollment does on activation. **No case was found
where migration is impossible or destructive** — the "STOP and report rather than
destroying enrollment" contingency the ticket asked for was not triggered.

## 6. Added — recovery codes actually wired into TOTP login (confirmed dead code, now fixed)

**Confirmed gap** (VERIFIED via `grep` across the entire addon codebase, excluding
tests): `TwoFactorAuthenticationService::attemptRecoveryCode()` — itself a thin
wrapper over `RecoveryCodeService::attemptConsume()` — had **zero callers**
anywhere in the codebase before this rebuild. Recovery codes could be generated
and displayed (Client Security Center → "regenerate recovery codes"), and their
remaining count could be shown, but there was no code path anywhere that could
actually consume one to complete a login. This means the ticket's requirement #12
("supports recovery codes") was **not previously satisfied** for TOTP (or, as far
as this audit found, for any method).

**Fix**: `dct_totp_2fa_verify()` now inspects the single challenge-field
submission. An exact 6-digit numeric string is tried as a TOTP code (via the
now-replay-protected `TotpEnrollmentService::verifyLogin()`); anything else
(recovery codes are formatted `XXXX-XXXX-XXXX-XXXX` — always contain hyphens/
letters) is tried against the existing, shared
`TwoFactorAuthenticationService::attemptRecoveryCode()` — the exact same
store, `password_hash()`/`password_verify()`-based hashing, single-use
consumption, and `RateLimiter`-based throttling every other 2FA method already
relies on. **No second recovery-code service, table, or hashing scheme was
created.** The challenge field's `maxlength` was widened (6 → 19) and its
digit-only `pattern`/`inputmode` attributes were removed to accommodate this;
`dct_totp_2fa_verify()` no longer strips non-digit characters from the raw
submission before routing it (this stripping is exactly what would have mangled
a recovery code into digits). Note that this change is scoped to
`dct_totp_2fa_verify()` only — `dct_totp_2fa_activateverify()`'s own, separate,
always-6-digit enrollment-code parsing is untouched, since enrollment never
accepts a recovery code.

**Scope note (UNVERIFIED, out of scope for this rebuild)**: whether WHMCS's own
native "Login using Backup Code" link (visible on some lockout screens in this
project's earlier work) is a wholly separate WHMCS-core feature independent of
which Security Module is active, and if so how (or whether) it interacts with
Security Pack's own recovery codes, was not re-investigated as part of this
specific rebuild — the fix above only guarantees that Security Pack's own
recovery codes now work when submitted through **this module's own** challenge
field.

## 7. Database changes

One additive, idempotent migration: `nnm_security_pack_totp2fa.last_used_step`
(nullable `unsignedBigInteger`), guarded by `hasColumn()`. No table was created,
dropped, or renamed. No existing column's type or meaning was changed. No secret
data was touched.

## 8. Security properties (re-confirmed for this rebuild)

- The TOTP secret is never logged, never exposed in the challenge/verify response,
  and remains encrypted at rest via the pre-existing, untouched `TotpKeyStore`/
  libsodium mechanism.
- The submitted code/recovery-code candidate is never logged (only high-level
  security events — enrolled/failed/replayed/used — are recorded, matching the
  existing pattern for every other 2FA method in this codebase).
- `matchingStep()`'s comparison remains `hash_equals()` — constant-time — even
  though it's now compared once per candidate step rather than the boolean
  short-circuit it effectively was before; this is not a timing regression, since
  the number of comparisons performed is unchanged (still exactly
  `2 × toleranceSteps + 1` in the worst case).
- Rate limiting (enrollment verification, login verification, recovery-code
  consumption) is unchanged — all three still go through the single, shared
  `RateLimiter::hit()`.
- Replay rejection is fail-open in exactly one narrow, deliberate sense worth
  disclosing: for an account that has never yet had a successful TOTP login (
  `last_used_step` is `NULL`), the very first accepted code cannot be "replayed"
  against itself before that baseline exists — this matches the native WHMCS
  reference's own behavior (its used-codes list is likewise built up from actual
  successful verifications, not pre-seeded) and is the standard, expected shape
  of this kind of protection.

## 9. Test results

`php tests/run.php`: **599/599 passing** (566 pre-existing + 33 new for this
rebuild: `TotpService::matchingStep()` against the RFC 6238 Appendix B test
vector — exact counter value, null-on-mismatch, null-on-non-numeric, forward/
backward clock-drift counter values, monotonicity, and `verify()`'s zero-
regression equivalence to `matchingStep(...) !== null`; source-level contract
checks confirming `dct_totp_2fa_challenge()` never emits a `<form>` tag anywhere;
confirming the bypass path submits the enclosing form rather than a nested one;
confirming `dct_totp_2fa_verify()` routes 6-digit vs. other submissions correctly
and no longer digit-strips before doing so; confirming no direct
`RecoveryCodeService::` reference exists in `dct_totp_2fa.php` (only via the
shared facade); confirming `TotpEnrollmentService`'s replay-rejection condition,
event name, and baseline-persistence exist in source; confirming the
`last_used_step` migration is `hasColumn()`-guarded and additive-only (a plain
`ALTER`, never a `dropIfExists()`/`create()` of the table); confirming exactly one
`nnm_security_pack_totp2fa` table creation exists in the whole file; confirming
`modules/security/totp/` — WHMCS's own native module directory — was never
created/touched by this project).

`php -l`: clean across every `.php` file under `modules/` (the full addon +
security-module tree).

`node --check`: clean on all touched/existing JavaScript (no JavaScript files
were modified by this specific rebuild — the fix is entirely within
`dct_totp_2fa.php`, `TotpService.php`, `TotpEnrollmentService.php`, and
`security_pack.php`).

## 10. What was NOT verified — live acceptance test

**This is the section the rebuild ticket explicitly required not to be skipped
or glossed over.** The ticket's closing instruction states: *"Do not declare
success until this works on a real WHMCS installation... The feature is complete
only when ENROLLMENT → VERIFICATION → ACTIVATION → LOGOUT → LOGIN → TOTP CHALLENGE
→ VALID CODE → SUCCESSFUL LOGIN has been demonstrated on the real WHMCS
installation."*

This process has no ability to run a real WHMCS installation, a real browser, or a
real authenticator app (Google Authenticator / Microsoft Authenticator / Authy /
1Password / Bitwarden / Duo Mobile). Every item above (§1–§9) is either a
source-level fact confirmed by direct reading of real code, or an automated,
CLI-run unit/contract test — never a live HTTP request against a running WHMCS
site. Specifically **not performed, and not claimable as proven, by this process**:

1. Enrolling a real account's TOTP via the actual WHMCS admin/client "Enable
   Two-Factor Authentication" UI and scanning the rendered QR code with a real
   authenticator app.
2. Submitting the app-generated 6-digit code to `dct_totp_2fa_activateverify()`
   through a real HTTP request and confirming activation.
3. Logging out and back in, confirming `dct_totp_2fa_challenge()` renders
   correctly INSIDE WHMCS's real login form (the specific, concrete thing the
   §4 fix targets) with no visual/functional corruption.
4. Submitting a real, currently-valid code from the authenticator app and
   confirming successful login.
5. Re-submitting that same (now-used) code and confirming it is rejected as a
   replay (the §5 fix) rather than accepted a second time.
6. Submitting a real recovery code and confirming it completes login (the §6
   fix), and confirming that same code is rejected on a second attempt.
7. Confirming the "Time Based Tokens" (or equivalent) label WHMCS's own Admin
   Users tab shows for this account is not, by itself, treated as proof that any
   of the above actually works end-to-end — the ticket explicitly warns against
   exactly this substitution.

An administrator with access to the real WHMCS installation this module targets
must run this 18-step live sequence before this feature can be considered
complete, per the ticket's own standard. Everything in this document up to this
section is accurate and was actually verified — but it verifies the code is
*correctly written*, not that it has been *observed working* on a live system.
