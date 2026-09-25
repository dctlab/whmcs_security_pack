# Security Pack 2.4.0 — Phase 4 Security Audit Report

**Security Assurance, Exhaustive Legacy Audit, Regression Hardening & CSP Reporting**

This document is the formal findings register and final report for Phase 4.
Feature development was frozen for the duration of this phase — no new
dashboard features, Security Center pages, protection mechanisms,
authentication features, IP features, GeoIP providers, session-management
systems, anomaly detection, analytics, notification channels, or UI
functionality were added. Everything below is audit, fix, and test work
against the existing Security Pack 2.3.0 baseline.

## Executive Summary

The full Security Pack 2.3.0 source tree — every admin controller, the
client controller, every `core/*.php` hook file, every template, the
module's one JavaScript file, the three curl GeoIP providers, and the
in-house MaxMind DB binary reader — was reviewed line-by-line, including
the original 1.2.0-era files that prior phases' audits had only spot-checked
(`core/content_protection.php`, `core/disallow_countries.php`,
`core/geoip_lang_currency.php`, `core/user_security.php`,
`core/loginHistory.php`, `providers/*.php`, `assets/js/user_logs.js`,
`templates/logs.tpl`, `templates/settings.tpl`).

Five confirmed issues were fixed, all Low or Informational severity. No
Critical, High, or Medium severity vulnerability was found. The most
significant finding — a client-area destructive action reachable via GET —
closes the same class of issue Phase 3B fixed for every admin controller,
which had not been extended to the one client-area case that needed it.
Everything else found was genuine defense-in-depth: code that is not
exploitable today given the module's current data flow, hardened anyway
against a future change accidentally introducing a real path to it.

This report does not claim the module is "fully secure" — no audit can
honestly claim that. It states precisely what was reviewed, what was
found, what was fixed, and what remains explicitly out of scope, so that
claim is never implied either.

## Scope

- Baseline reviewed: Security Pack **2.3.0** (125 assertions, 125 passing,
  0 failing, prior to this phase's changes).
- Full repository: `security_pack.php`, `hooks.php`, `core/`, `lib/`,
  `templates/`, `assets/js/`, `lang/`, `providers/`, `tests/`,
  `whmcs.json`.
- Out of scope (unchanged, by design): the WHMCS core platform itself
  (`curlCall()`, `redir()`, `App::*`, `Illuminate\Database\Capsule`,
  Smarty's own template engine) — this module calls into WHMCS core but
  does not, and should not, re-audit or re-implement it.

## Files Audited

Every `.php` file in the module (55 files), every `.tpl` template (3
files), the module's one `.js` file, and its three JSON data files
(`whmcs.json`, `core/countries.json`, `core/country_currency.json` —
validated as well-formed JSON, not further reviewed as they are static
data, not code).

## Controllers Audited

**Admin** (`lib/Admin/`): `ActivityController`, `DashboardController`,
`DiagnosticsController`, `IpLimitedClientsController`,
`IpRestrictionsController`, `LangCurrencyController`, `LoginLogsController`,
`PasswordDisabledController`, `SettingsController` — all 9, including a
full re-read of `SettingsController::index()`'s render body (previously
audited only for its `save()` method) and `LoginLogsController`'s full
`index()`/`user()` methods (previously audited only for the one XSS fix
line).

**Client** (`lib/Client/`): `ClientController` — every public method
re-read line-by-line, including `limit_ip_range()` (the source of this
phase's main finding), `login_history()`, `change_reset_password()`,
`login_notification_alert()`, `security_center()`.

## Templates Audited

`templates/logs.tpl`, `templates/settings.tpl`, `templates/security_center.tpl`
— every dynamic value's HTML/attribute/JS context was traced back to its
PHP source.

## JavaScript Audited

`assets/js/user_logs.js` (the module's only standalone JS file) and every
inline `<script>` block in the three templates above and in
`core/content_protection.php`'s right-click/copy-paste-disable snippets.
No `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`eval`, no dynamic script
loading, no `postMessage` handling anywhere in the module. The two
JS-injected values found (`security_pack_userid`, `security_pack_active`
in `core/loginHistory.php`'s `AdminAreaFooterOutput` hook) are `intval()`'d
and a hardcoded `"active"`/`""` string respectively — never raw request
data.

## Database Audited

Every `Illuminate\Database\Capsule\Manager` call in the module (`lib/`,
`core/`, `security_pack.php`, `hooks.php`) — confirmed zero raw SQL string
concatenation (`whereRaw`, `DB::raw`, `->query(`, `->statement(`) anywhere;
every query uses the parameter-bound query builder. Every migration in
`security_pack_ensure_tables()` re-reviewed for destructive operations —
none found; every table creation is `hasTable()`-guarded and every
settings/schema-version seed is existence-guarded before insert.

## Security Controls Reviewed

SQL injection, XSS (reflected/stored/attribute/JS-context), CSRF,
authorization (admin/client/AJAX/unauthenticated), authentication,
session handling, IP spoofing / trusted-proxy bypass, CIDR handling, GeoIP
(including SSRF), path traversal, open redirects, file upload, filesystem
writes, information disclosure, security headers, sensitive-data logging.

## Findings

### PHASE4-01 — Client-area destructive action reachable via GET
- **Severity:** Low
- **File:** `lib/Client/ClientController.php`, function `limit_ip_range()`;
  rendered from `templates/settings.tpl`
- **Description:** The "remove a Session IP Security Limit range" action
  read `$_REQUEST["remove_ips"]` with no check on `$_SERVER["REQUEST_METHOD"]`,
  and the template rendered it as a plain `<a href="...&remove_ips=...&security_pack_token=...">`
  link — the exact GET-based-destructive-action pattern Phase 3B closed
  for every *admin* controller, but this client-area equivalent was not
  in that sweep's scope and was missed.
- **Impact:** The CSRF token was still required and validated
  (`security_pack_csrf_valid()` already ran unconditionally at the top of
  the method), so this was **not** exploitable as classic CSRF — an
  attacker cannot forge a valid token for a victim's session. The residual
  risk is the same as any GET-based state change: the token can leak via
  browser history, a shared/logged proxy, or a `Referer` header if the
  page is ever linked from elsewhere.
- **Proof/Attack Scenario:** A logged-in client's own browser history or
  a corporate web proxy log could retain
  `index.php?m=security_pack&page=limit_ip_range&remove_ips=3&security_pack_token=<token>`
  in full, including the live CSRF token — not exploitable by a third
  party without also compromising that log/history, but avoidable.
- **Fix:** The action is now POST-only (`$_SERVER["REQUEST_METHOD"] !== "POST"`
  bounces back to the Security Center before anything else runs, including
  before the CSRF check). The template's delete link is now a small POST
  form with the token as a hidden field, matching the pattern used
  everywhere else in the module since Phase 3B.
- **Test:** `tests/run.php` — "client limit_ip_range remove action is
  allowed via POST" / "...is blocked via GET".
- **Status:** FIXED.

### PHASE4-02 — Unescaped session-flash error message in Settings admin page
- **Severity:** Informational
- **File:** `lib/Admin/SettingsController.php`, function `index()`
- **Description:** `echo "<div class=\"alert alert-danger\">" . $error . "</div>";`
  printed `$_SESSION["nnm_error"]` with no `htmlspecialchars()`.
- **Impact:** None today — every call site that sets `$_SESSION["nnm_error"]`
  across the entire module (checked all 5) assigns a hardcoded string
  literal, never request input. Flagged purely because it's inconsistent
  with the escaping discipline used everywhere else in this file and
  every other admin controller, and a future edit could add a call site
  that does interpolate request data into this key without anyone
  noticing the missing escaping here.
- **Fix:** Wrapped in `htmlspecialchars((string) $error, ENT_QUOTES, "UTF-8")`.
- **Test:** Covered indirectly by the existing XSS-payload matrix
  (`sp_test_escape_ip_param`); the fixed line now uses the same primitive.
- **Status:** FIXED.

### PHASE4-03 — Missing type guard on `$_REQUEST["settings"]` in Settings save
- **Severity:** Informational
- **File:** `lib/Admin/SettingsController.php`, function `save()`
- **Description:** `$_REQUEST["settings"]["country_restriction"]` and
  similar array-offset accesses assumed `settings` was always submitted
  as an array (`settings[key]=value`, as the real form does). A crafted
  request with `settings` as a scalar (e.g. `?settings=x`) would trigger
  "illegal string offset" PHP warnings on every check.
- **Impact:** Availability/noise only (PHP warnings, not a crash, not
  fatal) — no data corruption or bypass was possible, since the
  subsequent `in_array($key, self::OWNED_KEYS, true)` allowlist check
  already prevented any unexpected key from being written regardless.
- **Fix:** `$requestSettings = is_array($_REQUEST["settings"] ?? null) ? $_REQUEST["settings"] : [];`
  guards every subsequent access.
- **Test:** `tests/run.php` — "a string 'settings' value...is treated as
  empty", plus null/integer variants.
- **Status:** FIXED.

### PHASE4-04 — Theme-template file write lacked path-containment check
- **Severity:** Informational (defense-in-depth; no known exploit path)
- **File:** `core/user_security.php`, function `security_pack_user_security_page()`
- **Description:** This function appends a Smarty `{include}` line to a
  theme's own `.tpl` file on disk, at a path built from
  `$vars["template"]` and `$vars["templatefile"]` (values supplied by
  WHMCS's own `ClientAreaPage` hook — not raw request input in any
  currently-known WHMCS version). No check confirmed the resolved path
  actually stayed inside `ROOTDIR/templates` before writing to it.
- **Impact:** None demonstrated — `$vars['template']`/`$vars['templatefile']`
  are WHMCS-internal values (the active theme name and template
  identifier), not attacker-controlled request parameters, in every WHMCS
  version this module targets. This is the *only* place in the module
  that writes to a file outside its own directory, which made it worth
  hardening on principle even without a demonstrated path to exploit it.
- **Fix:** Added a `realpath()`-based containment check
  (`strncmp($resolvedTemplateFile, $templatesRoot . DIRECTORY_SEPARATOR, ...) === 0`)
  before the existing `file_exists()`/`file_get_contents()`/`file_put_contents()`
  sequence. Any path that resolves outside `ROOTDIR/templates` is now
  silently skipped rather than written to.
- **Test:** `tests/run.php` — path-containment logic matrix (4 assertions,
  including the "shares a string prefix but isn't a real subdirectory"
  case, e.g. `/whmcs/templates-evil/` vs `/whmcs/templates/`).
- **Status:** FIXED.

### PHASE4-05 — Defense-in-depth escaping added to already-safe template output
- **Severity:** Informational
- **Files:** `templates/logs.tpl`, `templates/settings.tpl`
- **Description:** `{$log.ip_address}`, `{$ip_limit->start_ip}`,
  `{$ip_limit->end_ip}`, and `{$remote_ip}` were rendered without an
  explicit `|escape` modifier.
- **Impact:** None today — every one of these values is constrained to
  `FILTER_VALIDATE_IP`-passing content (or WHMCS-core's own `REMOTE_ADDR`)
  before it is ever written to the database or session that feeds these
  templates; a string containing HTML/JS special characters can never
  reach them under the current code paths (traced `security_pack_detect_visitor_ip()`,
  `ClientController::limit_ip_range()`'s `filter_input(..., FILTER_VALIDATE_IP)`,
  and `logClientLoginHistory()`'s callers).
- **Fix:** Added `|escape` to all four regardless, as defense-in-depth —
  costs nothing, and protects against any future change that relaxes the
  upstream validation without someone noticing these specific template
  lines.
- **Status:** FIXED.

## Reviewed and Confirmed Safe (no change needed)

- **SSRF / GeoIP external requests:** `GeoIpManager::lookup()` rejects any
  IP that fails `IpUtil::isValidIp()` or passes `IpUtil::isPrivateOrReserved()`
  *before* the cache table or any provider is ever touched. `CurlApiProvider`
  and all three `providers/*.php` classes only ever receive an
  already-validated public IP — confirmed by re-reading every call path
  into these classes; there is no route from user input straight to a
  provider URL. `169.254.169.254` (cloud metadata), `127.0.0.1`,
  `::1`, and `fc00::1` were explicitly tested and confirmed rejected
  before ever reaching a provider (see the GeoIP matrix in `tests/run.php`).
- **MaxMind DB upload path traversal:** `LangCurrencyController::uploadMmdb()`
  never derives its destination path from the uploaded filename —
  `security_pack_mmdb_path()` is a hardcoded constant path regardless of
  what the browser sends as the original filename. Content is validated
  by attempting a real parse with the module's own `MaxMindDb\Reader`
  before the file is accepted.
- **`MaxMindDb\Reader` (lib/MaxMindDb/Reader.php):** a from-scratch binary
  format parser; confirmed no `eval`, `unserialize`, dynamic `include`/`require`,
  or shell execution anywhere in it. Only `is_readable()`/`file_get_contents()`
  touch the filesystem, both on the already-upload-validated temp file.
- **Dynamic provider instantiation** (`CurlApiProvider::lookup()`'s
  `new $provider()`): `$provider` is restricted to either the admin-configured
  `providers` setting (JSON array, admin-auth + CSRF required to change)
  or a `glob()` of the module's own `providers/*.php` directory — never
  request input.
- **All destructive admin actions** other than PHASE4-01: already
  POST + CSRF as of Phase 3B; re-verified line-by-line in this phase
  (`PasswordDisabledController`, `IpLimitedClientsController`,
  `LangCurrencyController`, `IpRestrictionsController`).
- **IP fields reaching templates without explicit escaping before this
  phase** (`nnm_security_pack_logins.ip`, `nnm_security_pack_ips.start_ip`/`end_ip`):
  traced every write path — all are `FILTER_VALIDATE_IP`-gated or
  WHMCS-core-controlled before insert, so no HTML/JS-special-character
  payload can reach the database in the first place. Escaping was still
  added (PHASE4-05) as defense-in-depth.
- **Trusted-proxy / forwarded-header spoofing:** `security_pack_detect_visitor_ip()`
  requires `filter_var(..., FILTER_VALIDATE_IP)` on every forwarded-header
  candidate and only trusts a forwarded header at all when Trusted
  Proxies is configured and the direct TCP peer matches one of the
  configured proxies. Re-verified with a malformed/spoofed-header test
  matrix in `tests/run.php`.
- **Sensitive data in Security Events:** grepped every
  `security_pack_record_event()` call site in the module (24 call sites)
  for `password`, `token`, `secret`, `key`, `session`, `authorization`,
  `cookie` in the context payload — none found. The one call that logs a
  broad payload (`SettingsController::save()`'s `"settings.updated"`
  event, which logs the pre-save settings snapshot) was checked against
  the current settings schema — no setting key in this module currently
  holds a password, API key, or session token.
- **File upload validation** (`uploadMmdb`): extension check + real
  binary-format parse before acceptance + fixed destination path — all
  three layers independently sufficient, all three present.
- **Authorization:** admin controllers rely on WHMCS's own addon-module
  gate (a request never reaches `security_pack_output()` without WHMCS
  having already authenticated an admin with module access). Client
  controller methods derive identity exclusively from
  `\WHMCS\Authentication\CurrentUser()`'s session — re-verified for every
  public method in `ClientController`, including the newly-hardened
  `limit_ip_range()`.
- **Redirects:** every `redir()`/`redirSystemURL()`/`App::redirectToRoutePath()`
  call in the module was checked — none accept a request-controlled
  destination; every target is a hardcoded route/query string.
- **Security headers:** every header value emitted by
  `core/security_headers.php` is a fixed string literal — confirmed none
  contain CR/LF (header-injection-safe by construction) and none are
  built from any `$_SERVER`/`$_GET`/`$_POST`/`$_COOKIE` value. CSP
  remains Report-Only in this release, per this phase's explicit
  instruction not to change that during the assurance phase.

## Deferred Issues (with justification)

- **Exhaustive byte-level fuzzing of the custom MaxMind DB binary parser**
  (`lib/MaxMindDb/Reader.php`) — reviewed for unsafe PHP constructs (none
  found) but not fuzzed against malformed/adversarial `.mmdb` byte
  sequences. **Risk:** low — the only entry point is
  `LangCurrencyController::uploadMmdb()`, which requires authenticated
  admin access + CSRF, and any parse failure is caught and rejected
  before the file is ever accepted onto disk. **Planned phase:** revisit
  if/when this module ever accepts `.mmdb` data from an unauthenticated
  or lower-trust source.
- **`core/content_protection.php`'s inline `<script>` string interpolation**
  of admin-configured language strings (right-click/copy-paste-disabled
  messages) into raw JS string literals rather than a JSON-encoded value.
  **Risk:** none today (only admin-controlled translation strings reach
  this, never request input) — not fixed in this phase to keep the
  feature freeze scoped to genuine findings, but flagged as a pattern to
  avoid in any future work that touches this file (prefer
  `json_encode()` over raw string concatenation into a `<script>` block).
- **CSP enforcement mode** — remains Report-Only, unchanged, per this
  phase's explicit Step 22 instruction. Any move to enforcing mode is
  out of scope for the assurance phase and would need to be a deliberate,
  separately-scoped decision (see Phase 4's "Final Instruction").

## Regression Tests

- Every fix above has at least one dedicated regression test in
  `tests/run.php`.
- The full Step 30 security test matrix was added: input (normal / empty
  / whitespace / 10,000-char / Unicode homoglyph / zero-width-joiner /
  SQLi / UNION SELECT / DROP TABLE / path traversal / CRLF injection /
  null byte), authorization (unauthenticated / client A / client B),
  CSRF (missing / invalid / valid token × GET / POST), IP / trusted-proxy
  (IPv4 / IPv6 / spoofed non-IP header / malformed candidates / empty
  list), security headers (static-value / no-user-input / CR-LF-free),
  and GeoIP (public / private / loopback / link-local / IPv6 ULA /
  invalid).
- No existing test was modified or removed — all 125 pre-Phase-4
  assertions are unchanged and still pass.

## Final Test Count

```
Existing tests (2.3.0 baseline): 125
New tests (Phase 4):              47
Total:                           172
Passed:                          172
Failed:                            0
```

## Final Lint Status

`php -l` run against every `.php` file in the module (55 files):
**0 syntax errors.** Every `.json` file validated as well-formed JSON.
The module's one JavaScript file (`assets/js/user_logs.js`) syntax-checked
clean.

## Migration Verification

The 2.4.0 schema-version migration adds **one row** to
`nnm_security_pack_schema_version` (guarded the same way every prior
version's row is — existence-checked before insert, never re-inserted on
repeat activation/upgrade) and **nothing else**. No table is created,
altered, or dropped. No existing setting is modified, seeded, or deleted.
This phase was a code-review/hardening pass, not a data-model change.

## Compatibility Verification

- Every admin route (`?module=security_pack&c=<name>`) and client route
  (`index.php?m=security_pack&page=<action>`) from 1.2.0 through 2.3.0
  continues to work unchanged.
- The one behavioral change — `ClientController::limit_ip_range()`'s
  remove action now requires POST — only affects the delete button on the
  client's own IP Security Limits panel, which is now a form submit
  instead of a link click; the visible UI and confirmation dialog are
  identical, only the underlying HTTP method changed. Bookmarked/old GET
  delete links will no longer work (by design — see PHASE4-01) and will
  bounce back to the Security Center safely rather than erroring.
- No database table, column, or existing settings key was removed,
  renamed, or had its meaning changed.
- Lagom2 theme compatibility: unaffected — the only template changes are
  the delete-link-to-form conversion (no layout/CSS/JS behavior change)
  and the addition of `|escape` modifiers (no visible output change for
  any value that was already IP-format-constrained).

## Residual Risk

No Critical, High, or Medium severity issue is known to remain open. The
items in "Deferred Issues" above are Low/Informational and have
documented justification, risk assessment, and a stated condition for
revisiting them. As with any manual + automated review, the absence of a
*found* issue is not a guarantee of the absence of *any* issue — this
report describes what was actually reviewed and tested, not an
unconditional security guarantee.

---

# Phase 5 / 2.5.0 Security Review — "Advanced Security Center"

**Everything in this section is new.** It documents the security review
for the Security Pack 2.5.0 release, which re-opens feature development
after the Phase 4 assurance freeze above. Nothing in this section
supersedes, edits, or reduces the scope of the Phase 4 findings recorded
above — the 2.4.0 baseline stands as reviewed and fixed at the time it was
written; this section only ever *adds* controls, never removes them.

## Scope

This review covers only the code added or modified for 2.5.0:

- `csp-report.php` — new, standalone, unauthenticated public entry point
  for browser CSP violation reports.
- `lib/Security/CspReportService.php` — new (pure normalization/grouping/
  classification + DB-backed record/purge).
- `lib/Security/SecurityAnomalyService.php` — new (pure rule evaluation +
  DB-backed gather).
- `lib/Security/SecurityAlertService.php` — new (pure severity
  classifiers + DB-backed gather).
- `lib/Admin/CspReportsController.php`, `lib/Admin/AnomaliesController.php`,
  `lib/Admin/AlertsController.php`, `lib/Admin/AnalyticsController.php` —
  new admin controllers.
- `lib/Admin/DiagnosticsController.php` — modified (new 2.5 checks
  appended to the existing check list).
- `lib/Security/SecurityScoreService.php` — modified (new "Security
  Intelligence" category added to the existing `compute()`/
  `gatherFacts()` pair; no new scoring service created).
- `core/security_headers.php` — modified (optional `report-uri`/
  `report-to`/`Reporting-Endpoints` addition to the existing Report-Only
  CSP header).
- `core/csp_reports.php`, `core/security_intelligence.php` — new cron/
  hook wiring.
- `hooks.php` — modified (two new `require`s only).
- `security_pack.php` — modified (three new table migrations, schema
  version bump, one new email template, new menu entries, symmetric
  uninstall cleanup).

Everything else in the module — every file the Phase 4 audit above
already reviewed — was **not** re-reviewed here, since it was not touched
in this phase; Phase 4's findings and fixes remain in effect unchanged.

## New Attack Surface

This phase introduces exactly one genuinely new attack surface: the
public, unauthenticated `csp-report.php` endpoint. This is a deliberate,
necessary exception to "every state-changing action requires
authentication" — browsers submit CSP violation reports for *any*
visitor, including anonymous/guest visitors with no WHMCS session, so an
admin-authenticated route cannot receive them. Every other new surface in
this phase (all four new admin controllers, the Diagnostics extension,
the Security Score extension) is reached exclusively through the
module's existing authenticated admin routing
(`security_pack_output()`), identical to every controller reviewed in
Phase 4 — no new authorization mechanism was introduced or needed.

Given that, the CSP endpoint receives the most scrutiny in this review.

## Security Controls Reviewed

**CSP endpoint (`csp-report.php`):**
- Method allowlist: POST only (405 otherwise).
- Content-Type allowlist: `application/csp-report`, `application/json`,
  `application/reports+json` only (415 otherwise).
- Size bound enforced *before* reading the body (413 on an oversized
  `Content-Length`), and the body read itself is capped
  (`file_get_contents("php://input", false, null, 0, MAX+1)`) rather
  than trusting the `Content-Length` header alone — a client that lies
  about its own `Content-Length` cannot force an unbounded read.
- Strict JSON parsing: non-array decodes and `JSON_ERROR_NONE` failures
  are both rejected (400) rather than silently coerced.
- Every extracted field is bounded to 500 characters
  (`CspReportService::MAX_FIELD_LENGTH`) before storage.
- Rate-limited via the **existing** `RateLimiter::hit()` service, keyed
  `"csp_report:" . REMOTE_ADDR` (30 hits/60s) — no new rate-limiting
  mechanism was written. The key is `REMOTE_ADDR` (the TCP peer address
  WHMCS itself sees), not a client-supplied header, so it cannot be
  bypassed by forging `X-Forwarded-For`/`CF-Connecting-IP`/etc.
- Writes are additionally gated behind the `csp_report_collection`
  setting (off by default) — even when reachable, the endpoint is a
  fast no-op unless an admin has explicitly opted in.
- All logic is wrapped in try/catch; the response is always a fixed
  `204`/`4xx` status with `Content-Length: 0` — no internal error,
  stack trace, or database detail is ever returned to the caller.
- Submitted data is never reflected back to the caller, never used to
  build a file path, shell command, or outbound HTTP request (no SSRF
  surface), and never used to build a SQL query directly (all storage
  goes through Illuminate's parameterized query builder).

**CSP report storage and display:**
- Reports are stored in the new, dedicated `nnm_security_pack_csp_reports`
  table — never mixed into `nnm_security_pack_events` (audit/event data
  stays separate from raw telemetry, as required).
- Grouping is by a deterministic `sha256(effective_directive|origin|source_file)`
  key, so a flood of reports for the same underlying violation increments
  one row's counter rather than creating unbounded rows.
- Every value rendered in `CspReportsController` (including raw
  attacker-influenced report fields like `blocked_uri`/`source_file`) is
  passed through the same `e()` (`htmlspecialchars(..., ENT_QUOTES,
  "UTF-8")`) helper pattern the rest of the module already uses — no new
  escaping mechanism, no gaps found.
- Policy Analysis classification uses only hedged language (`Observed`,
  `Unrecognized`, `Likely third-party`, `Needs review`) — verified by
  test that the classifier never returns `Safe`/`Trusted`/`Verified`.
  Suggested policy additions are rendered as plain preformatted text in a
  clearly labeled "review before enabling" panel — nothing is auto-
  applied to any actual policy, and this module does not itself emit an
  enforcing CSP.

**Anomaly Detection / Analytics / Alerts:**
- `SecurityAnomalyService::evaluate()` is pure and operates only on event
  rows already read from the database — no additional query surface, no
  request-input-controlled query construction.
- `SecurityAnomalyService::gather()` bounds its read to a capped lookback
  window and a hard 20,000-row `limit()` — cannot be driven into an
  unbounded query by data volume.
- `AnalyticsController` and `SecurityAlertService::gather()` use only
  aggregate `COUNT`/`SUM`/`GROUP BY` queries with explicit `LIMIT`s —
  confirmed no code path performs an unbounded `SELECT *` against
  `nnm_security_pack_events` or `nnm_security_pack_csp_reports`. The one
  place a column name is interpolated into a query
  (`AnalyticsController::topBy($column, ...)`) is only ever called with
  one of three hardcoded literals (`ip`, `country_code`, `event_type`) —
  never with request input.
- All four new admin controllers' state-changing actions
  (`CspReportsController::save/clear`, `AnomaliesController::acknowledge/
  dismiss`, `AlertsController::save`) require both `POST` and a valid
  `security_pack_csrf_valid()` token, matching the established pattern.
- Anomaly evidence and reason text are pure, bounded, structurally
  generated strings (counts, IPs already validated via `IpUtil`, rule
  names) — not attacker-controlled free text — and are still
  `e()`-escaped at render time regardless.
- `security_pack_record_event()` calls added this phase
  (`csp.policy.changed`, `csp.report.cleared`, `anomaly.detected`,
  `anomaly.acknowledged`, `anomaly.dismissed`, `alert.configuration.changed`,
  `alert.digest.sent`, `login.client.failed`, `login.admin.failed`) pass
  only fixed strings and small structured context (booleans, counts,
  rule keys, IDs) — the raw CSP report payload is never written into the
  event table.

**Security Score extension:**
- The new "Security Intelligence" category was added to the existing
  `SecurityScoreService::compute()`/`gatherFacts()` pair — confirmed no
  second/parallel scoring service was introduced. `gatherFacts()`'s new
  fact (`open_high_severity_anomalies`) is a single bounded `count()`
  query wrapped in try/catch, consistent with every other fact in that
  method.

## Tests Added

`tests/run.php` grew from 172 to 254 assertions (82 new). Coverage
directly relevant to this security review: CSP payload normalization
against `<script>`/`"><script>`/SQL-injection-shaped/CRLF/10,000-character/
Unicode input (asserting bounded length and that nothing is executed),
grouping-key determinism, classifier hedged-terminology enforcement, pure
reimplementations of the endpoint's method/content-type/body-size
validation logic and retention-purge boundary logic, a rate-limiter
reuse-confirmation assertion, anomaly rule boundary/threshold/suppression-
lifecycle tests with explainability assertions (non-empty reason/evidence/
dedupe-key on every finding), alert severity-classifier boundary tests,
and a routing/authorization regression block confirming every new admin
controller resolves into the exact same authenticated `Admin` namespace
as every pre-existing controller, plus an explicit assertion that the
public CSP endpoint is the only new surface outside that namespace.

## Findings and Fixes

A dedicated regression pass was run against every file listed in Scope,
above, specifically for: SQL injection, XSS, CSRF, authorization bypass,
SSRF, information disclosure, header injection, log injection, resource
exhaustion, and CSP-endpoint rate-limit bypass.

**PHASE5-01 (Low) — `DiagnosticsController::save()` reachable via GET.**
`DiagnosticsController` was modified this phase (new 2.5 checks appended
to `runChecks()`), which put its existing `save()` method in scope for
this review. `save()` validated the CSRF token but — unlike every new
2.5 state-changing action, and unlike the pattern Phase 3B/4 established
for the rest of the module — did not also reject non-POST requests. Not
exploitable as classic CSRF (a valid session-bound token was already
required), but a state-changing action reachable via GET risks the
token leaking through a `Referer` header, browser history, or a server
access log. **Fixed**: `save()` now rejects any non-POST request before
even checking the token, identical to every other 2.5 state-changing
action.

No other issues — Critical, High, Medium, Low, or Informational — were
found in the files listed under Scope.

## Residual Risk

No Critical, High, or Medium severity issue is known to remain open in
the 2.5.0 code reviewed here. As stated in Deferred, above and in
`CHANGELOG.md`: anomaly-detection thresholds are not yet admin-tunable
(defaults only); this is a usability gap, not a security one, since the
defaults are conservative. CSP remains Report-Only by design — this
release adds *reporting*, not *enforcement*, and makes no claim to the
contrary. As with Phase 4, the absence of a *found* issue in this review
is not a guarantee of the absence of *any* issue.

# Phase 6 / 2.6.0 Security Review — "Email Two-Factor Authentication"

**Everything in this section is new.** It documents the security review
for the Security Pack 2.6.0 release, which wires up, extends, and
hardens the Email 2FA scaffold that had existed since an earlier release
but was never actually connected to authentication. Nothing in this
section supersedes, edits, or reduces the scope of the Phase 4 or Phase
5 findings recorded above — this section only ever *adds* controls,
never removes them, and every prior phase's fixes remain in effect
unchanged.

## Scope

This review covers only the code added or modified for 2.6.0:

- `lib/Security/Email2faService.php` — new. The authoritative Email 2FA
  engine: pure OTP generation/hashing/verification/clamp helpers plus
  DB-backed challenge and bypass lifecycle management.
- `core/email_2fa.php` — new. All hook wiring: `UserLogin`,
  `ClientAreaPage`, `AuthAdmin`, `UserEdit`, `UserChangePassword`,
  `AdminClientProfileTabFields`, `DailyCronJob`.
- `email2fa-admin-verify.php` — new, standalone, pre-session public entry
  point (module root) — the one genuinely new unauthenticated attack
  surface this phase adds, and by necessity: WHMCS's `AuthAdmin` hook
  cannot itself pause mid-request to render an interactive page, and no
  documented hook exists to inject custom HTML into WHMCS's own
  pre-session admin login page.
- `lib/Client/ClientController.php` — modified (new `email2fa_enable`,
  `email2fa_activate`, `email2fa_disable`, `email2fa_verify` actions and
  `security_center()` status wiring, following the existing
  action-method/CSRF pattern every other client action already uses).
- `lib/Admin/Email2faController.php` — new admin settings/visibility/
  bypass-management controller, reached exclusively through the
  module's existing authenticated admin routing
  (`security_pack_output()`) — identical authorization guarantee to
  every controller reviewed in Phase 4/5.
- `templates/email2fa_otp.tpl` — new shared OTP entry template.
- `lib/Security/SecurityScoreService.php` — modified (existing
  "Authentication" category extended with two new checks; no new
  scoring service created).
- `lib/Security/SecurityAnomalyService.php` — modified (one new
  deterministic rule, `detectRepeatedEmail2faFailures()`, added to the
  existing `evaluate()`; not AI/ML, same shape as every existing rule).
- `lib/Admin/AnalyticsController.php`, `lib/Admin/DiagnosticsController.php`
  — modified (new metrics/checks appended to existing lists).
- `hooks.php` — modified (one new `require` only).
- `security_pack.php` — modified (three new table migrations, schema
  version bump to `2.6.0`, new admin menu entry, symmetric uninstall
  cleanup).

Everything else in the module — every file the Phase 4 and Phase 5
audits already reviewed — was **not** re-reviewed here, since it was not
touched in this phase.

## New Attack Surface

This phase introduces exactly one genuinely new unauthenticated surface:
`email2fa-admin-verify.php`, the standalone pre-session admin OTP verify
page. Unlike the CSP endpoint added in Phase 5 (which accepts anonymous
telemetry from any visitor), this page is reached only via a redirect
the `AuthAdmin` hook itself issues, after WHMCS's own admin password
check has already succeeded for a specific admin credential and Email
2FA was determined to still be required. It is given the most scrutiny
in this review.

## Security Controls Reviewed

**`AuthAdmin` hook (`core/email_2fa.php`):**
- Never independently re-verifies the submitted password, and never
  returns `true` to force a login through on its own authority — every
  `return true` path either means Email 2FA is not active for this admin
  or a valid, IP-scoped bypass already exists; every other path
  redirects rather than asserting success. This makes the hook safe
  regardless of the exact AND/OR semantics WHMCS uses internally to
  combine hook results with its own core check (those exact semantics
  are not fully documented) — the hook can only ever add a requirement
  on top of core's own decision, never substitute for it.
- The one accepted residual risk here: because `AuthAdmin` fires during
  password authentication itself, an attacker who does not know a valid
  admin password can still cause an OTP challenge to be created by
  submitting a correct username with a guessed password (bounded by
  WHMCS's own login throttling, and further bounded here by
  `createChallenge()`'s own resend-cooldown/max-resends limits). This is
  an accepted, documented trade-off of hooking at this exact point,
  which is the only documented pre-session admin hook available.

**Standalone verify page (`email2fa-admin-verify.php`):**
- Never receives or trusts an admin identity from the URL or query
  string — the only credential is a random, single-use continuation
  token (`bin2hex(random_bytes(32))`), delivered via a dedicated
  `HttpOnly`, `SameSite=Lax` cookie the module sets and reads itself
  (deliberately not WHMCS's own session, whose bootstrap behavior in
  this specific pre-session context could not be verified through
  documentation), resolved server-side via a SHA-256 hash comparison
  against the `continuation_hash` column, additionally bound to the
  requesting IP.
- Carries its own CSRF protection independent of the module's normal
  session-based `security_pack_csrf_valid()` helper (this page runs
  before any WHMCS session exists): a separate double-submit cookie
  (`sp_e2fa_csrf`), compared with `hash_equals()`.
- All dynamic output is escaped via `htmlspecialchars(..., ENT_QUOTES,
  "UTF-8")` before being echoed into hand-built HTML (this page is not a
  Smarty template, so Smarty's own escaping does not apply here) —
  verified against `<script>`, `"><script>`, and quote-breaking inputs
  in the message/status strings this page renders.
- Never itself establishes a WHMCS admin session or marks anyone
  authenticated; on success it clears its own cookies and redirects to
  WHMCS's normal `admin/login.php` so the admin completes the (now
  Email-2FA-cleared) password login through WHMCS's own code path. It
  therefore cannot be used to bypass admin authentication outright —
  only to clear the Email 2FA requirement ahead of a second password
  submission.
- All redirect targets on this page are hardcoded relative paths; none
  are derived from request input, so it introduces no open redirect.

**OTP engine (`Email2faService.php`):**
- OTPs are generated with `random_int()` (never `rand()`, `mt_rand()`,
  `time()`, or `uniqid()`), hashed at rest with PHP's password hashing
  API, and verified with `password_verify()` — never a raw `===`
  comparison of secret material, and never a plaintext store.
- Single-use enforced structurally: `evaluateOtpSubmission()` returns
  `"consumed"` for any challenge already marked consumed, independent of
  whether the submitted code happens to be correct — replaying an old,
  already-successful OTP always fails.
- Attempt-limited: `attemptCount >= maxAttempts` is checked before the
  OTP comparison itself and returns `"locked"`, so a request past the
  cap is rejected without ever touching `password_verify()` again for
  that challenge.
- All database access goes through the Capsule query builder with
  parameter binding throughout this file and every other file in scope
  — no raw string concatenation into SQL was found anywhere in this
  phase's code.
- Every `security_pack_record_event()` call in this phase's code was
  checked individually: none pass an OTP value, an OTP hash, a
  continuation token, a password, or a session/CSRF token — only
  `user_id`, `user_type`, `purpose`, boolean/status/reason labels, and
  actor labels.
- Error/status outcomes (`invalid`, `expired`, `consumed`, `locked`,
  `no_challenge`, `rate_limited`) are the same generic set surfaced
  identically across the admin, client-login, and client-activation
  flows — none of them reveal whether a given email address or account
  is enrolled.

**CSRF / method enforcement:**
- Every state-changing Email 2FA action in `ClientController.php` and
  `Email2faController.php` requires both `REQUEST_METHOD === "POST"` and
  a valid `security_pack_csrf_valid()` token, matching the pattern every
  other 2.x state-changing action in this module already uses (the
  pattern Phase 4 established for admin actions, Phase 5 for its new
  controllers).
- The OTP itself is never accepted from a query string — the
  verification form (`templates/email2fa_otp.tpl`) submits it as a
  hidden POST field, and the standalone admin verify page's form does
  the same.

## Findings and Fixes

**PHASE6-01 (Medium) — Visitor-IP resolution mismatch between challenge
creation and the standalone admin verify page.**
`core/email_2fa.php`'s `AuthAdmin` hook resolves the visitor IP via the
module's shared, Trusted-Proxy-aware resolver
(`security_pack_detect_visitor_ip($settings["ip_source"] ?? "auto")`,
the same function every other IP-sensitive feature in this module uses)
and stores that value on the challenge row. `email2fa-admin-verify.php`
originally resolved IP via a local helper that read only
`$_SERVER["REMOTE_ADDR"]`, and `findChallengeByContinuationToken()`
requires an exact match between the two. On any deployment sitting
behind a reverse proxy, load balancer, or CDN with an "IP Source" other
than `remoteaddr` configured (a normal, supported configuration
elsewhere in this module), the two paths would resolve different IP
values for the same admin, causing every admin login requiring Email
2FA to fail with "This verification link has expired or is no longer
valid" — a functional lockout on the very login path this feature is
meant to secure, not an exploitable weakness in the other direction (an
attacker cannot forge `REMOTE_ADDR`). **Fixed**: the verify page now
calls the same shared `security_pack_detect_visitor_ip()` resolver
(falling back to `REMOTE_ADDR` only if that function is unexpectedly
unavailable), so challenge creation and challenge lookup always agree on
the same IP, consistent with this module's stated rule of never
introducing a second IP parser.

**PHASE6-02 (Low, fixed) — Non-atomic attempt-count increment allowed a
narrow race.**
`Email2faService::verify()` read a challenge row's `attempt_count`,
evaluated the submission in PHP, then wrote `attempt_count = <value just
read> + 1` in a separate statement. Two concurrent verification requests
against the same challenge could both read the same `attempt_count`
before either write landed, letting a determined attacker gain a small
number of extra guesses past the configured cap per race window (further
bounded by the existing per-IP `RateLimiter` on the verify action
itself, so this was never an unbounded brute-force path). **Fixed**: the
increment is now written as an atomic conditional update
(`WHERE id = ? AND attempt_count = <value just evaluated>`), so a
losing concurrent write affects zero rows instead of silently landing an
uncounted attempt.

No other Critical, High, or Medium severity issue was found in the files
listed under Scope.

## Residual Risk (accepted, not fixed, in this release)

- **`RateLimiter::hit()`'s own counter increment is not atomic** (the
  same read-then-write pattern as PHASE6-02, but in the module's
  pre-existing, shared rate-limiting service, not code introduced by
  this phase). This affects the Email 2FA send/verify rate limits along
  with every other feature that already relies on `RateLimiter`. Impact
  is bounded (a small number of extra hits per concurrent burst,
  further bounded by database round-trip latency in practice) and
  changing a widely-depended-on, already test-covered shared service
  this late in this phase's work was judged higher-risk than the
  residual exposure itself. Recorded here as a known limitation rather
  than silently left undocumented; a candidate fix (an atomic increment
  evaluated post-write, e.g. `hits = hits + 1` at the SQL level) is
  noted for a future maintenance pass.
- **Cookie `Secure` flag depends on `$_SERVER["HTTPS"]` being set
  correctly by the web server.** On deployments that terminate TLS at a
  reverse proxy without forwarding an equivalent signal to PHP, the
  continuation-token and CSRF cookies this feature sets would be issued
  without the `Secure` flag even though the site is served over HTTPS.
  Both cookies are still `HttpOnly` and `SameSite=Lax`, and exploitation
  would require an active network attacker able to force a plaintext
  HTTP request to the same host — the same category of trust this
  module already documents for its IP-source detection (which likewise
  depends on correct proxy/header configuration). Not fixed in this
  release; an admin-configurable "trust this deployment is always HTTPS"
  setting, mirroring the existing Trusted Proxies control, is a
  candidate follow-up.
- The admin-side hard gate and the client-side session gate are, by
  design and as documented extensively in `CHANGELOG.md`, **not
  equivalent security strength** — this is not a residual bug but an
  explicit, disclosed architectural limitation stemming from WHMCS
  documenting no pre-session client-area authentication hook. A client
  session briefly exists before the Email 2FA step completes; an
  administrator evaluating this feature for a security-sensitive client
  population should read the Security section of the 2.6.0
  `CHANGELOG.md` entry before assuming otherwise.
- OTP mail delivery bypasses WHMCS's own configured mail
  provider/SMTP relay for this one message type (see "Email Delivery" in
  `CHANGELOG.md`) — a disclosed functional trade-off, not a security
  weakness, made because no documented WHMCS-facing API was found for
  excluding the BCC recipient from a provider-routed send.

As with every prior phase, the absence of a *found* issue in this
review is not a guarantee of the absence of *any* issue.

# Phase 7 / 2.6.1 Security Review — "Email 2FA as a Native WHMCS Security Module"

**Everything in this section is new.** It documents the investigation
and review behind the 2.6.1 architecture correction: replacing 2.6.0's
hybrid Hooks-based enforcement (AuthAdmin hard gate for admins,
UserLogin/ClientAreaPage session gate for clients) with a native WHMCS
"Security Module" (`modules/security/dct_email_2fa`), the same module
type WHMCS's own built-in Time-Based Tokens/Duo/YubiKey 2FA methods use.
Nothing in this section supersedes, edits, or reduces the scope of the
Phase 4, 5, or 6 findings recorded above. The OTP engine itself
(`Email2faService`) is unchanged by this phase and is not re-reviewed
here — see Phase 6 for its review.

## Why this correction was made

2.6.0 concluded that WHMCS's documented Authentication Hooks
(`ClientLoginShare`/`UserLogin`/`UserLogout`/`AuthAdmin`) expose no
pre-session client-area login hook, and built an honestly-disclosed
asymmetric model as a result. That conclusion about the Hooks API was
correct. It was incomplete because it did not account for a separate
WHMCS module type — Security Modules — that WHMCS itself uses for its
own built-in 2FA methods, and that third-party modules also use for the
same purpose, genuinely intervening between password validation and
completed authentication for both admin and client logins. A working
reference implementation of exactly this module type, already installed
and activated in this WHMCS instance for WhatsApp-based verification,
was provided as evidence and used as the primary source for this
investigation.

## Investigation performed

Before writing any implementation code, the following was checked
directly rather than assumed:

- **`developers.whmcs.com`'s module documentation** was inspected
  directly. It documents exactly five module types: Gateway, Merchant
  Gateway, Provisioning, Domain Registrar, and Addon. It does **not**
  document a Security Module / Two-Factor Authentication provider type.
  This confirms, rather than merely repeats, the disclosure already
  present in the supplied reference module's own header comment: the
  `modules/security/` interface is undocumented.
- **`docs.whmcs.com`'s Two-Factor Authentication pages** (8.11 through
  9.0) were checked for any function/interface documentation. They
  cover only end-user/administrator *usage* tutorials ("Enable 2FA
  Globally", "Enable 2FA for Admins", "Enable 2FA for Clients", "Require
  2FA") — no developer/module-interface content.
- **WHMCS's own public REST API documentation**
  (`api-beta.developers.whmcs.com`) was checked as independent
  corroborating evidence for the underlying claim that client logins
  genuinely have a distinct pre-completion 2FA step in WHMCS's own
  architecture (not merely a claim specific to the admin side): it
  documents a `POST /user/session/verify` endpoint and an HTTP 412
  status specifically for "Two-Factor Authentication is required or the
  provided Two-Factor Authentication token is invalid" — confirming
  WHMCS's own client login flow has a genuine password-accepted/
  2FA-still-pending intermediate state at the API level, independent of
  the Security Module question.
- **Multiple independent third-party WHMCS security modules** were
  located and their public READMEs/structure inspected (a WHMCS-specific
  OTP-by-SMS/email module, an Unecast-based admin 2FA module, and
  others), all independently confirming the same pattern: install under
  `modules/security/<name>/`, activate via Setup > Security >
  Two-Factor Authentication, intercept the login flow after credential
  validation and before granting access. This corroborates the general
  shape of the interface beyond the one supplied reference file, even
  though full source code for these additional examples could not be
  retrieved (GitHub raw-content fetches were blocked by
  robots.txt/404s during this investigation).
- **WHMCS core source itself was not available** for direct tracing —
  this module's licensing does not expose its internals to this tooling.
  This is the same limitation the supplied reference module's own header
  discloses, and it is repeated, not hidden, in this module's own header
  and in the CHANGELOG.

## What was concluded, and what remains genuinely unverified

Concluded with reasonable confidence (multiple independent, mutually
consistent sources): the `modules/security/` module type exists, is
real, is exactly what WHMCS's own built-in 2FA methods use, is
installed via `modules/security/<name>/<name>.php`, is activated via
Setup > Security > Two-Factor Authentication, and provides functions
following the pattern `<name>_config()`, `<name>_activate($params)`,
`<name>_activateverify($params)`, `<name>_challenge($params)`,
`<name>_verify($params)` — genuinely intervening between password
validation and completed authentication, for both admin and client
logins.

**NOT independently verified** (same caveat the reference module's own
header discloses, carried forward honestly rather than hidden): the
*exact* internal semantics of how WHMCS discovers and invokes these
functions, the complete contents of `$params` in every context, how
WHMCS's own session-establishment interacts with a pending challenge,
and whether WHMCS 9.0.x specifically changed anything about this
interface relative to older versions. This implementation's `$params`
usage (`user_info.id`, `post_vars.*`, and the config-field names it
declares) mirrors the supplied working reference exactly. **This must be
tested end-to-end — activation and login, for both an admin and a
client account — in a staging copy of this WHMCS install before relying
on it in production.** This is stated here, in the module's own file
header, and in CHANGELOG.md, deliberately in more than one place given
the severity of getting authentication code wrong.

## Scope

This review covers only the code added or modified for 2.6.1:

- `modules/security/dct_email_2fa/dct_email_2fa.php` — new. The native
  Security Module: `dct_email_2fa_config()`, `dct_email_2fa_activate()`,
  `dct_email_2fa_activateverify()`, `dct_email_2fa_challenge()`,
  `dct_email_2fa_verify()`, plus pure helpers
  (`dct_email_2fa_settings_from_params()`, `dct_email_2fa_context()`,
  `dct_email_2fa_ip()`, `dct_email_2fa_bypass_active()`,
  `dct_email_2fa_resolve_account_email()`).
- `core/email_2fa.php` — modified: the `UserLogin`, `ClientAreaPage`, and
  `AuthAdmin` enforcement hooks were **removed**. `UserEdit`,
  `UserChangePassword`, `AdminClientProfileTabFields`, and
  `DailyCronJob` remain, unchanged in behavior.
- `email2fa-admin-verify.php` — **deleted** (superseded; its
  responsibility is now handled natively by WHMCS calling
  `dct_email_2fa_challenge()`/`dct_email_2fa_verify()` directly).
- `templates/email2fa_otp.tpl` — **deleted** (the security module
  returns raw HTML strings directly, per the reference interface's
  pattern, rather than routing through a Smarty `templatefile`).
- `lib/Client/ClientController.php` — modified: the `email2fa_enable`,
  `email2fa_activate`, `email2fa_disable`, and `email2fa_verify` actions
  were **removed**; `security_center()`'s Email 2FA section is now
  read-only status display only.
- `templates/security_center.tpl` — modified: the Email 2FA
  enable/disable/activate buttons were replaced with a single "Manage"
  link to WHMCS's native `{$WEB_ROOT}/security` screen (the same link
  already used for WHMCS's own built-in 2FA status row).
- `lib/Admin/Email2faController.php` — modified: the settings form and
  `save()` action were removed; enrollment overview and administrator
  manual bypass management are unchanged.
- `lib/Security/SecurityScoreService.php` — modified: the "Authentication"
  category's Email 2FA scoring now measures real adoption (active
  account counts) instead of a settings flag that no longer exists.
- `lib/Admin/DiagnosticsController.php` — modified: the Email 2FA checks
  now report the native module file's presence instead of a settings
  flag.
- `security_pack.php` — modified: version bump, a `2.6.1` schema-version
  marker row (no table changes), and an updated code comment on the now
  legacy-and-unused `continuation_hash` column.

Everything else — the entire `Email2faService` engine, its tables, its
rate limiting, its bypass logic, its audit event types, its BCC-safe
mail delivery — is byte-for-byte unchanged from 2.6.0 and was not
re-reviewed here; see Phase 6 for that review.

## Security Controls Reviewed

**`dct_email_2fa_activate()`/`dct_email_2fa_activateverify()`:**
- Never lets a user supply an arbitrary activation email address —
  always resolves the account's own WHMCS email (`tblusers.email` for
  clients, `tbladmins.email` for admins) via
  `dct_email_2fa_resolve_account_email()`, never from request input.
- Never marks an account active on form submission alone —
  `activateverify()` requires `Email2faService::verify()` to return
  `"valid"` before calling `completeActivation()`, identical to 2.6.0's
  activation flow (Step 6: never implicitly trust an address without a
  live round trip).

**`dct_email_2fa_challenge()`/`dct_email_2fa_verify()`:**
- Bypass handling is symmetric and independently re-checked: the
  challenge screen's auto-submitting "trusted sign-in" form is rendered
  only after `dct_email_2fa_bypass_active()` confirms an active bypass,
  and `verify()` re-runs the exact same check independently rather than
  trusting the presence of the hidden `dct_email_2fa_bypass` field — a
  forged/replayed POST of that field alone cannot grant access without a
  genuinely active, correctly-scoped (user + IP, or user-only for
  administrator-manual) bypass already on record.
- IP resolution uses the shared `security_pack_detect_visitor_ip()`
  resolver via `dct_email_2fa_ip()` — the exact fix Phase 6 already made
  for the (now-removed) standalone admin verify page is preserved here,
  not regressed.
- OTP submission continues to flow entirely through
  `Email2faService::verify()` — single-use, attempt-capped, rate-limited
  — with no new code path around it; this module adds no new OTP
  comparison logic of its own.
- A successful verification calls `Email2faService::grantSameIpBypass()`
  immediately, matching the documented refresh-not-extend bypass policy
  from Phase 6, unchanged.
- `dct_email_2fa_context()` mirrors the reference module's session-marker
  resolution exactly (`$_SESSION["adminid"]` then `$_SESSION["uid"]`,
  falling back to a `tbladmins` existence check only when a fallback id
  is explicitly supplied) — this is the same signal the reference
  module already relies on in this exact WHMCS instance, not a new,
  unverified assumption.

**Removed surfaces:**
- `email2fa-admin-verify.php` (a standalone, pre-session, publicly
  reachable PHP entry point) is deleted outright rather than left
  dormant — its own attack surface (reviewed and hardened in Phase 6) no
  longer exists to reason about at all, since WHMCS now calls this
  module's functions directly rather than redirecting to a separate
  page.
- The `AuthAdmin` hook enforcement (reviewed in Phase 6: never
  independently re-verifies the password, never returns `true` to force
  a login) is removed along with the entry point it protected — the
  native module's `verify()` function takes over the equivalent
  responsibility, always returning a strict `bool`, never a value that
  could be misinterpreted as "grant access" by accident (verified by
  reading every `return` statement in `dct_email_2fa_verify()`: every
  path returns either `false`, the literal result of
  `dct_email_2fa_bypass_active()` (itself always `bool`), or `true` only
  after `Email2faService::verify()` returned `"valid"`).

## Findings

No Critical, High, or Medium severity issue was found in the files
listed under Scope, beyond the residual uncertainty already disclosed
above (the undocumented nature of the interface itself, which is a
disclosed limitation of the approach, not a specific code defect).

## Residual Risk (carried forward and new)

- **The `modules/security/` interface's exact WHMCS-internal semantics
  remain unverified beyond working precedent.** This is the central,
  explicitly-disclosed risk of this entire architecture correction. It
  is mitigated, not eliminated, by: closely mirroring a working
  reference implementation already active in this exact WHMCS instance;
  every function's return values being deliberately conservative
  (`verify()` never returns anything other than a strict bool derived
  from an already-reviewed decision path); and the explicit instruction,
  repeated in three places (this file, CHANGELOG.md, the module's own
  header comment), to test end-to-end in staging before production use.
- All residual risks carried forward from Phase 6 concerning
  `Email2faService` itself (the non-atomic `RateLimiter::hit()` counter,
  the `Secure` cookie flag's dependency on correct proxy configuration —
  though note the cookie-related item no longer applies to the removed
  `email2fa-admin-verify.php`'s own cookies specifically, since that
  file no longer exists) remain accepted, unchanged, and documented in
  Phase 6 above.
- OTP mail delivery still bypasses WHMCS's configured mail
  provider/SMTP relay for this one message type (see CHANGELOG.md
  "Email Delivery", Phase 6) — unchanged by this phase.

As with every prior phase, the absence of a *found* issue in this
review is not a guarantee of the absence of *any* issue — and this
phase in particular rests on a genuinely unverifiable internal WHMCS
interface, which is why staging verification before production use is
stated as a requirement, not a suggestion.

## Post-release fix — 2.6.1.1: over-length MySQL index identifier

Reported by the user immediately after upgrading in production:

```
PDOException: SQLSTATE[42000]: Syntax error or access violation: 1059
Identifier name 'nnm_security_pack_email2fa_challenges_user_id_user_type_purpose_status_index'
is too long
```

**Root cause**: `nnm_security_pack_email2fa_challenges`'s migration
declared `$table->index(["user_id", "user_type", "purpose", "status"])`
with no explicit index name. Laravel's schema builder auto-generates an
index name of the form `<table>_<col1>_<col2>_..._index` when none is
given. With this table's name and four indexed columns, that
auto-generated name is 76 characters — MySQL's hard identifier-length
limit is 64. The `CREATE TABLE` statement was rejected outright by
MySQL, which failed the entire `security_pack_ensure_tables()` call
(and therefore the whole module upgrade) with an uncaught
`PDOException`, since this specific statement is not wrapped in its own
try/catch (unlike the DB-backed methods elsewhere in this module, which
deliberately are).

This was missed during 2.6.1's own review because the length check was
never actually performed — the table/column names were chosen for
clarity, not measured against the 64-character limit before shipping.
Two smaller unnamed indexes on the sibling bypasses table (61-62
characters) happened to stay just under the limit by chance, not by
design; had they been declared with one more column, or a longer column
name, they would have failed the exact same way.

**Fix**: every index/unique-key declaration on the two Email 2FA tables
(`nnm_security_pack_email2fa_challenges`,
`nnm_security_pack_email2fa_bypasses`) now passes an explicit, short
index name (e.g. `sp_e2fa_chal_lookup_idx`) instead of relying on
Laravel's auto-generated one — this removes the dependency on table/
column name length entirely for these tables. No schema/data change
beyond the index names themselves; the underlying indexed columns are
identical.

**Regression test added** (`tests/run.php`): a source-level check that
parses every `->index(...)`/`->unique(...)` call in `security_pack.php`
and computes what MySQL's actual identifier length would be — whether
explicitly named or Laravel-auto-generated from `<table>_<cols>_<type>`
— and fails if any exceeds 64 characters. This is a static analysis of
the migration source itself (no live database needed, consistent with
the rest of this suite), and was verified to actually catch the
original bug: temporarily reverting the fix locally reproduces exactly
this test failure, with the exact 76-character identifier named in the
failure message. This check runs on every future migration change, not
just this one — any new unnamed multi-column index on a long table name
is now caught by `php tests/run.php` before it ever reaches a live
install.

**Scope check**: every other unnamed index already present in
`security_pack.php` before this fix (on `nnm_security_pack_ip_rules` and
`nnm_security_pack_anomalies`) was checked and confirmed to be well
under the 64-character limit (44-51 characters) — this was an
Email-2FA-specific issue caused by that table's longer name, not a
module-wide pattern.

## Post-release fix — 2.6.3: Email 2FA "no mail received" (delivery diagnostics)

**Reported**: after successfully upgrading to 2.6.2 and reaching Email
2FA activation, the client-area screen displayed "We've sent a
verification code to w•••••••••••@gmail.com..." but no OTP email ever
arrived.

**Investigation**: two independent problems were found in the delivery
path, both scoped strictly to messaging/diagnostics — no change to the
OTP generation, hashing, verification, rate-limiting, or Global-BCC-
exclusion logic already reviewed in Phase 6/Phase 7.

1. `dct_email_2fa_activate()` and `dct_email_2fa_challenge()`
   (`modules/security/dct_email_2fa/dct_email_2fa.php`) called
   `Email2faService::beginActivation()` / `::createChallenge()` — both
   of which already return a `status` key of `sent`, `send_failed`, or
   `rate_limited` — but discarded that value and always rendered the
   same "we sent a code" copy. A hard delivery failure was therefore
   presented identically to success, with no signal to the end user or
   to support staff that anything had gone wrong.
2. `Email2faService::sendOtpEmail()` called PHP's `mail()` behind the
   `@` suppression operator and discarded the boolean result beyond a
   single `delivered` flag in one event log entry — there was no record
   anywhere of *why* a send failed (wrong server MTA config, PHP
   `mail()` disabled, DNS/relay rejection, etc.).

In this project's own reproduction of the reported bug, `mail()` fails
because the environment has no local mail transport agent at all
(`sh: /usr/sbin/sendmail: not found`) — this is a realistic stand-in for
a production host that relies entirely on an external SMTP relay
configured *within WHMCS itself* (Setup > General Settings > Mail),
since `sendOtpEmail()` deliberately does not use that relay (see the
2.6.0 CHANGELOG "Email Delivery" note and `sendOtpEmail()`'s own class
doc comment for why: WHMCS's own mail pipeline is exactly what applies
the Global BCC recipient, and excluding that recipient for OTP mail
specifically was a hard requirement of the original specification).

**Fix**:
- Both call sites now branch on the real returned `status` and show an
  honest, differentiated message for `sent` / `send_failed` /
  `rate_limited` (and a generic fallback for `error`) rather than one
  unconditional success message.
- `sendOtpEmail()` now calls `error_clear_last()` immediately before and
  `error_get_last()` immediately after the suppressed `mail()` call, and
  logs the captured transport-level reason (never the OTP, never beyond
  what identity fields were already logged) via
  `security_pack_record_event("email_2fa.otp.mail_transport_error", ...,
  "warning")` on failure — refactored into a shared private `rawSend()`
  helper so this diagnostic capture applies uniformly to every caller.
- `sendOtpEmail()` now also passes `mail()`'s envelope-sender parameter
  (`-f<address>`) whenever WHMCS's configured "Email" setting is present
  and valid — a missing envelope sender is a common cause of outright
  rejection or silent dropping by MTAs/relays enforcing sender
  verification, and this does not add any `Bcc`/`Cc` header, so the
  Global BCC exclusion guarantee is unaffected.
- A new public `Email2faService::sendTestEmail(string $to): array`
  method reuses the exact same `rawSend()` transport (not a parallel
  implementation) to send a harmless, clearly-labelled test message and
  return `{sent, reason}` — exposed via a new "Send Test Email" action
  on the addon's Diagnostics page, so an admin can confirm real
  end-to-end delivery capability independent of a live login/activation
  attempt, and get the real failure reason immediately if it doesn't
  work.
- The existing "Email 2FA — OTP Delivery" Diagnostics check now also
  reads WHMCS's own `MailType` configuration value and, when it is not
  plain PHP `mail`, adds an explicit note that ordinary WHMCS email
  working does not by itself prove Email 2FA delivery will work (since
  that relay is not used by this path), pointing the admin at "Send
  Test Email".

**What was deliberately NOT changed**: the choice to send OTP mail via
raw `mail()` rather than through WHMCS's own mail pipeline remains
unchanged — no documented, stable WHMCS API was found (in this or the
2.6.1 investigation) for constructing/dispatching a message through
WHMCS's configured mail provider while explicitly excluding the Global
BCC recipient, and that exclusion is a non-negotiable requirement from
the original specification. Sites without a working local mail
transport agent, and relying entirely on an SMTP relay configured
inside WHMCS, will still need that local transport working (e.g.
`sendmail`/`postfix`/`msmtp` configured to relay outbound) for Email
2FA mail specifically — this is disclosed as a known limitation in
CHANGELOG.md's 2.6.3 "Deferred" section, and reflected in the new
Diagnostics warning text, rather than silently left unresolved.

**Regression tests added** (`tests/run.php`): (1) `sendTestEmail()`'s
return contract (`{sent: bool, reason: ?string}`) is asserted for both
an invalid destination and a syntactically valid one, and its reason
text is asserted to never contain the string "OTP" (confirming test
sends stay a distinct message, not a repurposed real one-time code
send); (2) a source-pattern check confirms `dct_email_2fa.php` branches
on a real `send_failed` status at least twice (covering both the
activation and login-challenge screens), guarding against the exact
"unconditional success message" regression described above being
silently reintroduced by a future edit.

## Post-release change — 2.7.0: Email 2FA OTP mail switched to WHMCS's own mail system (explicit instruction, security-relevant reversal)

**Trigger**: explicit user instruction, verbatim: "use WHMCS Mail SYSTEM
do not use PHP mail()." Issued directly, in the context of diagnosing
the 2.6.3 "no mail received" report.

**What this reverses**: the original 82-step Email 2FA specification
included a hard, explicit requirement that WHMCS's Global BCC recipient
(General Settings > Mail > BCC Messages) must NEVER receive a copy of an
Email 2FA one-time code. Every release from 2.6.0 through 2.6.3 honored
this by sending OTP mail via raw PHP `mail()`, deliberately bypassing
WHMCS's own templated mail-send pipeline (the only thing that applies
Global BCC). This instruction directly and knowingly reverses that
requirement — the decision was made by explicit user direction, not
unilaterally by this module, and is disclosed here, in `sendOtpEmail()`'s
own doc comment, and in `CHANGELOG.md`'s `## 2.7.0` entry, consistent
with this project's established policy of disclosing rather than
silently making security-relevant trade-off changes.

**Implementation**: `Email2faService::sendOtpEmail()` now calls
`sendAdminMessage()` (admin accounts) or `sendMessage()` (client
accounts) — the exact same WHMCS functions already proven to work in
this production environment via `core/loginHistory.php`'s login
notifications. Both route through WHMCS's own configured mail transport
(General Settings > Mail — plain PHP mail, SMTP, etc.), which is why
this is expected to actually fix delivery on a host that has no local
mail transport agent but does have a working SMTP relay configured
inside WHMCS.

**New disclosed uncertainty — client-account resolution**: `sendMessage()`
requires a genuine `tblclients.id`, but this module's identity model is
the WHMCS User (one User can own/access multiple Client accounts, and
WHMCS documents no "default"/"primary" account for a User — confirmed
absent from `docs.whmcs.com`'s Users and Client Accounts page during
this investigation). `Email2faService::resolveClientIdForUser()` resolves
one via the `tblusers_clients` junction table — its existence and
role as the User↔Client link is corroborated by independent WHMCS
Community developer discussion, **not** official WHMCS documentation —
falling back to a `tblclients` row with a matching `email` if that
lookup finds nothing, and failing closed with a clear, logged reason if
both fail (never silently guessing or picking an arbitrary account).
This is the same "docs + community corroboration + explicit disclosure,
never presented as verified fact" methodology used for the
`modules/security/` interface investigation in 2.6.1 — the residual
risk here is structurally the same class: an internal WHMCS data
relationship reconstructed from community precedent rather than
confirmed against live core source, and it should be verified in
staging (via the new "Send Test Email" client-path Diagnostics action)
before being relied on for real client accounts in production.

**Security posture change, summarized for audit purposes**:
- REMOVED guarantee: OTP codes are never included in Global BCC.
- ADDED guarantee: OTP delivery now uses WHMCS's own configured mail
  transport (SMTP relay, etc.), removing the "requires a working local
  MTA" dependency the raw `mail()` approach had.
- Content integrity: OTP mail is now genuinely Smarty-rendered by
  WHMCS's own engine rather than manually placeholder-substituted — a
  net improvement in correctness/consistency with how every other WHMCS
  email template works, with no change to what data is placed in the
  template (still only the OTP digits, a validity-minutes integer, and
  one of two fixed purpose-label strings — no user-controlled input is
  newly introduced into the render path).
- No change to OTP generation, hashing, verification, rate limiting, or
  bypass logic — this change is scoped strictly to the transport layer.

**Regression tests updated** (`tests/run.php`): `sendTestEmail()`'s
tests were updated for its new `(userType, userId)` signature and now
assert the `{sent, reason}` fail-closed contract for both the admin and
client paths in an environment where `sendAdminMessage()`/`sendMessage()`
are unavailable (no live WHMCS session in this CLI runner) — confirming
neither path throws when the underlying WHMCS functions don't exist,
and that a test send's reason text never contains "OTP" (no accidental
resemblance to a real one-time-code disclosure).
