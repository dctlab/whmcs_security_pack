# Security Pack 2.3.0 — Phase 3B Audit Addendum

This addendum covers the Phase 3B (Security Center Navigation, Client
Security Center, Safe State Changes & Final Security Hardening) review. It
supplements, and does not replace, the 2.2.0 audit below — everything the
2.2.0 audit already reviewed/fixed still applies and was re-verified.

## Confirmed and fixed

### 1. GET-based destructive actions (residual finding carried over from
2.2.0's "Known, deliberately deferred" section)
**Files:** `lib/Admin/PasswordDisabledController.php`,
`lib/Admin/IpLimitedClientsController.php`,
`lib/Admin/LangCurrencyController.php`,
`lib/Admin/IpRestrictionsController.php`
**Was:** delete/enable/disable/save/clear-cache actions were reachable via
GET links carrying the CSRF token in the query string. Not exploitable as
classic CSRF (the token is unknown to an attacker), but a genuine
defense-in-depth gap: the token could leak via browser history, a proxy
access log, or an outbound `Referer` header on a page that links offsite.
**Fix:** every one of these actions now (a) requires
`$_SERVER["REQUEST_METHOD"] === "POST"` — a GET request is rejected and
redirected without executing — and (b) still validates
`security_pack_csrf_valid()` as before. All corresponding admin-UI links
were converted to small POST forms with the same visible button/confirm
dialog. No workflow changed for an admin using the UI normally.
**Severity:** Low (defense-in-depth; not independently exploitable given
CSRF was already enforced).
**Verification:** `tests/run.php` adds pure-logic coverage of the
POST-only allowlist decision (`POST` allowed, `GET`/`HEAD` blocked,
non-listed actions unaffected); manually verified each converted
controller with `php -l` and a re-read of the full diff.

## Reviewed and confirmed safe (no change needed)

- **Client Security Center authorization
  (`lib/Client/ClientController.php::security_center()`):** identity is
  read exclusively from `\WHMCS\Authentication\CurrentUser()->user()->id`
  — the method never reads a client/user id from `$_REQUEST`, `$_GET`, or
  `$_POST` anywhere in its body. Every database query it issues
  (login-notification opt-in, password-reset-protection status, recent
  login events) is scoped with `->where("client_id", $clientId)` using
  that session-derived value. Modeled and regression-tested as a pure
  scoping function in `tests/run.php` (a spoofed alternate client id
  passed alongside a real session id cannot widen the returned row set).
- **Security headers do not introduce new attack surface:** the three
  default-on headers (`X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`) are static, non-configurable-value headers — no
  request input is ever interpolated into any header value emitted by
  `core/security_headers.php`. CSP and HSTS remain off unless explicitly
  (and, for HSTS, doubly) opted into by an admin.
- **Navigation grouping (`core/pagebuilder.php`):**
  `NNM_Page_Builder::menulistGrouped()` only reads from the module's own
  hard-coded `$menuGroups` configuration array (set in `security_pack.php`)
  and the existing `$this->menu` array — no request input reaches this
  code path at all, so it introduces no new injection surface. Menu items
  not present in any configured group still render as flat top-level
  links (verified by code inspection), so a misconfigured group can only
  ever fail to visually nest an item — it cannot hide or remove access to
  a controller.
- **`geo_cache.cleared` event recording:** the new
  `security_pack_record_event()` call in `LangCurrencyController::clearCache()`
  passes a static message string and an empty context array — no request
  input involved.
- Re-swept every controller under `lib/Admin/` and `lib/Client/` for
  `echo`/`print` of `$_REQUEST`/`$_GET`/`$_POST` values and for raw SQL
  string concatenation (`whereRaw`, `->query(`, `DB::raw`, string-built
  queries). Found no new occurrences beyond what the 2.2.0 audit already
  reviewed (`LoginLogsController::index()`'s `userid`/`ip_address`
  handling, all going through Capsule's bound-parameter query builder —
  already confirmed safe in the 2.2.0 audit below).

## Known, deliberately deferred (not fixed in this release)

- **Client session management is view-only.** The Client Security
  Center's "Current Session" card cannot list or remotely revoke a
  client's *other* active sessions — WHMCS does not expose a supported,
  addon-safe API for enumerating or terminating another session from an
  addon module, and fabricating a "sessions" list from login-history rows
  (which are not the same thing as live sessions) would be actively
  misleading. The page states this limitation to the client directly.
- **Two-factor-authentication status detection is best-effort.** Different
  WHMCS 8.x/9.x builds expose 2FA status differently (or not at all, to
  addon modules); `security_center()` tries `method_exists()` on the
  current user object, then falls back to checking for a `tbltwofactor`
  table, both wrapped in `try`/`catch`, and shows "not enough data"
  rather than guessing. This may under-report 2FA status as unknown on
  some WHMCS versions rather than risk a false claim either way.
- **Content-Security-Policy remains Report-Only, not enforcing** — see
  `CHANGELOG.md` 2.3.0 "Deferred" for the rationale (no single CSP is
  safe-by-default across arbitrary gateways/themes/widgets).
- **A fully exhaustive, line-by-line audit of every original 1.2.0-era
  controller** was still not performed as a dedicated standalone pass in
  this phase — as in 2.2.0, the review was systematic (every
  request-input-to-output and request-input-to-query code path was
  traced across every controller) rather than a line-by-line read of
  every file end to end. No new issues were found by this pass. If a
  fully exhaustive line-by-line review is wanted, it remains a valid
  follow-up scope.

---

# Security Pack 2.2.0 — Security Audit Notes

Code-level audit performed against the actual 2.1.0 source (not documentation)
as the first step of Phase 3A. This file records what was found and what was
done about it — confirmed issues were fixed in this release, not just
reported.

## Confirmed and fixed

### 1. Reflected XSS — `LoginLogsController::index()`
**File:** `lib/Admin/LoginLogsController.php`
**Was:** `echo isset($_REQUEST["ip_address"]) ? $_REQUEST["ip_address"] : "";` —
the IP-address search field value was echoed straight back into an HTML
attribute with zero escaping. A URL like
`?module=security_pack&c=LoginLogs&ip_address="><script>...` would execute
in an authenticated admin's browser.
**Fix:** wrapped in `htmlspecialchars(..., ENT_QUOTES, "UTF-8")`, matching
every other output in this module.
**Severity:** Medium (admin-only surface, but a real reflected-XSS
primitive with no auth bypass needed beyond an already-authenticated
admin visiting a crafted link).

### 2. CSRF — GET-based destructive delete with no token check
**Files:** `lib/Admin/PasswordDisabledController.php`,
`lib/Admin/IpLimitedClientsController.php`
**Was:** both controllers deleted a database row directly off
`$_REQUEST["delete_id"]` with **no CSRF token check at all** — any page an
authenticated admin's browser loaded (an `<img>` tag, a link in an email
or forum post referencing the exact URL) could silently delete a
disabled-password-reset entry or a client's Session IP Security Limit
range.
**Fix:** both now require and validate the existing Phase 1
`security_pack_csrf_token()`/`security_pack_csrf_valid()` token before
deleting (reusing the existing CSRF system — no second mechanism), and
both now record a `nnm_security_pack_events` entry for the deletion.
**Severity:** Medium (requires getting an authenticated admin's browser to
load a specific URL; no data disclosure, but unauthorized destructive
action).

## Reviewed and confirmed safe (no change needed)

- **SQL injection:** every query in `lib/` and `core/` goes through
  WHMCS's Capsule query builder with bound parameters — no raw SQL string
  concatenation of request input was found anywhere in the module,
  including the new Phase 2 Activity Center filters (search/IP/country/
  date-range) and the new Phase 3A IP Restrictions rule save.
- **cURL GeoIP providers** (`providers/*.php`, now wrapped by
  `CurlApiProvider`): the `$ip` value concatenated into each provider's
  request URL is only ever reachable already validated by
  `filter_var($ip, FILTER_VALIDATE_IP, ...)` upstream (in
  `GeoIpManager::lookup()` and, previously, `security_pack_resolve_country()`)
  — an attacker-controlled string can never reach these URLs unvalidated.
  Confirmed the one other caller, `LangCurrencyController::testLookup()`,
  independently validates with `FILTER_VALIDATE_IP` before calling
  `security_pack_resolve_country()`.
- **File upload** (`LangCurrencyController::uploadMmdb()`): extension is
  checked, and — more importantly — the uploaded file is parsed with the
  real MaxMind DB reader *before* being accepted; a file that isn't a
  valid `.mmdb` is rejected rather than silently saved.
- **Authorization:** admin controllers rely on WHMCS's own addon-module
  authentication (a request only reaches `security_pack_output()` at all
  if WHMCS has already authenticated an admin with module access — this
  module does not, and should not, reimplement that check). Client
  controllers were checked individually: `login_history()` filters by the
  logged-in client's own session ID; `limit_ip_range()`'s insert/delete
  both scope to `user_id = $currentUser->id`, so one client cannot see or
  delete another client's IP ranges; `change_reset_password()` /
  `login_notification_alert()` act only on the current session's own
  user/client ID, never an ID taken from request input.
- **IpUtil CIDR matching:** exercised against malformed IPv4/IPv6,
  out-of-range masks, non-numeric masks, and a battery of injection-style
  payloads (SQL, `<script>`, path traversal, `javascript:`, null bytes,
  CRLF, a 10,000-character string) in `tests/run.php` — every one is
  safely rejected via `filter_var`/`inet_pton` failure, none throws, none
  matches.
- **Trusted Proxy bypass:** `security_pack_detect_visitor_ip()` (Phase 1,
  unchanged in this release) only trusts a forwarded-for header when the
  direct TCP peer matches a configured trusted proxy; with none
  configured, behaviour is the pre-2.0 default (documented, not a new
  finding).

## Known, deliberately deferred (not fixed in this release)

- **Destructive actions triggered via GET, protected only by a CSRF
  token, elsewhere in the module** — `LangCurrencyController`'s
  `override_delete` / `override_enable` / `override_disable` /
  `clear_cache` actions, and the new `IpRestrictionsController`'s
  `enable`/`disable`/`delete` actions, are all GET links carrying the
  CSRF token in the query string. Because the token is required and
  validated, these are **not** exploitable as classic CSRF (an attacker
  cannot know the victim's token), but GET requests for state changes are
  still poor practice — the token can end up in browser history, proxy
  logs, or a Referer header. Converting every such link to a POST+confirm
  form across the whole module is a larger, purely mechanical UI change
  better done as its own pass rather than mixed into this security/
  architecture release; tracked here rather than silently left unnoted.
- **Security headers** (`X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `Content-Security-Policy`, `Strict-Transport-Security`)
  — intentionally not implemented in Phase 3A per its own scope (Step 26);
  `X-Frame-Options` continues to be set by the existing 1.2.0 Content
  Protection "Disable iframe Display" toggle only, which is opt-in.
- A full manual review of every admin-controller HTML output for
  attribute vs. JS-context escaping correctness was done for
  Phase 2/3A-authored code (Dashboard, Activity Center, Diagnostics, IP
  Restrictions) — all use `htmlspecialchars(..., ENT_QUOTES, "UTF-8")`
  consistently. Older 1.2.0-era controllers were spot-checked, not
  exhaustively re-audited line-by-line beyond the two fixes above; if a
  further full line-by-line pass over the original 1.2.0 templates is
  wanted, that can be scoped as a follow-up.
