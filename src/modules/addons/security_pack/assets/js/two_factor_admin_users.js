/**
 * Security Pack — Admin Client Profile > Users tab integration.
 *
 * Fixes: the native WHMCS "Two Factor Auth Method" column on the admin
 * Client Profile > Users tab only reflects WHMCS's own native 2FA state
 * (`tblusers.second_factor`), so an account with an active Security
 * Pack method (Email/DCTLAB WhatsApp/TOTP) shows "N/A". This script
 * finds that native table by its ACTUAL column header text (never a
 * guessed page URL/structure), resolves each row's real WHMCS User ID,
 * and looks it up in a mapping the server already computed and injected
 * as a page global — see core/two_factor_admin_display.php. Fail-soft
 * throughout: any missing element, unresolved User ID, or absent/
 * unrecognized mapping entry leaves the native cell completely
 * untouched.
 *
 * 3.1.16 — "FINAL ADMIN USERS 2FA DISPLAY FIX": this is now PURE DOM
 * PRESENTATION. Through 3.1.11 this script made a fetch() request to an
 * admin AJAX endpoint for each row's status — that request 404'd on the
 * reported install (its Admin Client Profile page is client-side-routed
 * to a friendly "/client/{id}/..." URL, and no derivation of the real
 * admin base path reliably avoided inheriting that routed path). Per
 * the explicit "DO NOT add another AJAX fallback / DO NOT use
 * window.location / DO NOT create another URL guess" instruction, the
 * fetch() call, the endpoint-URL global, and the CSRF token global are
 * all REMOVED. `window.security_pack_2fa_users` (a plain
 * `{userId: {method, state}}` object the server already built — see the
 * hook above) is read synchronously; there is no network request left
 * to fail, time out, or resolve against the wrong URL. Every row/User-ID
 * detection selector below is UNCHANGED from 3.1.10/3.1.7, since a live
 * DOM trace already confirmed those were correct — the AJAX call was
 * always the only broken part.
 *
 * Row/User-ID detection history (unchanged since 3.1.10):
 *  - Real user rows carry `class="user-item"` (confirmed live markup:
 *    `<tr class="user-item">`). `processTable()` selects
 *    `tbody tr.user-item` FIRST — this automatically excludes the known
 *    hidden `rowPendingInvites` row (and any other non-`.user-item` row)
 *    without needing `isSkippableRow()` at all. If a table has NO
 *    `.user-item` rows (a different theme/markup this wasn't confirmed
 *    against), this falls back to scanning every `tbody tr`, filtered by
 *    `isSkippableRow()`, rather than silently processing nothing.
 *  - Real rows expose the WHMCS User ID directly via `data-user-id`
 *    (confirmed live markup: `<span class="name" data-user-id="666037">`,
 *    the matching `.email` span, and the Manage User button all carry
 *    it). `extractUserId()` checks `.name[data-user-id]` (then any
 *    `[data-user-id]`) FIRST. A broader multi-candidate scan (hidden
 *    input / href / formaction / onclick "userid=" parsing) is consulted
 *    only as a FALLBACK when no `data-user-id` is present; if more than
 *    one candidate is found and they disagree, the row is left alone
 *    rather than guessed at.
 *  - A hidden `<tr id="rowPendingInvites" class="hidden">` row (and any
 *    other row WHMCS itself has hidden) is never treated as a malformed
 *    real row and never looked up.
 *  - Opt-in debug logging via `?sp2fa_debug=1` in the admin URL — off by
 *    default, never logs anything sensitive (no OTP/secret/token/
 *    credential — only table/row/User-ID/mapping-lookup diagnostics).
 */
(function () {
    "use strict";

    var TARGET_HEADER = "Two Factor Auth Method";
    var DEBUG = /(?:^|[?&])sp2fa_debug=1(?:&|$)/.test(window.location.search);
    var PROCESSED_ATTR = "data-sp2fa-processed";

    function log() {
        if (!DEBUG || !window.console || !window.console.debug) {
            return;
        }
        var args = ["[DCTLAB Security Pack 2FA overlay]"].concat(Array.prototype.slice.call(arguments));
        window.console.debug.apply(window.console, args);
    }

    function findTargetColumnIndex(table) {
        var headerCells = table.querySelectorAll("thead th");
        for (var i = 0; i < headerCells.length; i++) {
            if ((headerCells[i].textContent || "").trim() === TARGET_HEADER) {
                return i;
            }
        }
        return -1;
    }

    function idFromAttr(el, attrNames) {
        for (var i = 0; i < attrNames.length; i++) {
            if (el.hasAttribute && el.hasAttribute(attrNames[i])) {
                var v = parseInt(el.getAttribute(attrNames[i]), 10);
                if (v > 0) {
                    return v;
                }
            }
        }
        return 0;
    }

    function idsFromUrlLike(value) {
        var found = [];
        if (!value) {
            return found;
        }
        var re = /[?&]userid=(\d+)/g;
        var m;
        while ((m = re.exec(value)) !== null) {
            found.push(parseInt(m[1], 10));
        }
        return found;
    }

    /**
     * The confirmed live markup exposes the real WHMCS User ID directly
     * and unambiguously via `data-user-id` on `.name`/`.email` spans
     * (and the Manage User button) inside the row — e.g.
     * `<span class="name" data-user-id="666037">`. Checked FIRST, as the
     * single most-trusted source, preferring the specific
     * `.name[data-user-id]` element over a generic `[data-user-id]`
     * match.
     */
    function extractUserIdFromConfirmedMarkup(row) {
        var nameEl = row.querySelector(".name[data-user-id]");
        var el = nameEl || row.querySelector("[data-user-id]");
        if (!el) {
            return 0;
        }
        var id = parseInt(el.getAttribute("data-user-id"), 10);
        return id > 0 ? id : 0;
    }

    /**
     * FALLBACK ONLY — used when the row has no confirmed `data-user-id`
     * markup (see extractUserIdFromConfirmedMarkup() above), e.g. a
     * different theme/markup. Resolves the real WHMCS User ID for a
     * table row — NEVER the selected Client ID. Checks every plausible
     * place WHMCS's own row actions might carry it: explicit data
     * attributes, a hidden "userid" form field, any
     * href/formaction/action/onclick containing "userid=". If more than
     * one DISTINCT candidate value is found, the row is ambiguous and is
     * left alone rather than guessed at.
     */
    function extractUserId(row) {
        var confirmed = extractUserIdFromConfirmedMarkup(row);
        if (confirmed > 0) {
            return confirmed;
        }

        var candidates = [];

        var dataAttrEl = row.querySelector("[data-userid],[data-user-id],[data-uid]");
        if (dataAttrEl) {
            var fromData = idFromAttr(dataAttrEl, ["data-userid", "data-user-id", "data-uid"]);
            if (fromData > 0) {
                candidates.push(fromData);
            }
        }

        var hiddenInput = row.querySelector("input[name='userid']");
        if (hiddenInput) {
            var fromInput = parseInt(hiddenInput.value, 10);
            if (fromInput > 0) {
                candidates.push(fromInput);
            }
        }

        var urlCarriers = row.querySelectorAll("a[href], form[action], button[formaction], [onclick]");
        for (var i = 0; i < urlCarriers.length; i++) {
            var el = urlCarriers[i];
            ["href", "action", "formaction", "onclick"].forEach(function (attr) {
                if (el.hasAttribute(attr)) {
                    idsFromUrlLike(el.getAttribute(attr)).forEach(function (id) {
                        candidates.push(id);
                    });
                }
            });
        }

        var unique = candidates.filter(function (v, idx) {
            return candidates.indexOf(v) === idx;
        });

        if (unique.length === 1) {
            return unique[0];
        }
        if (unique.length > 1) {
            log("ambiguous User ID candidates in row, leaving it unchanged:", unique);
        }
        return 0;
    }

    /**
     * WHMCS's own Users table can contain rows that are NOT real user
     * rows at all — e.g. a hidden "rowPendingInvites" row (confirmed via
     * live debugging: `<tr id="rowPendingInvites" class="hidden">`).
     * These must never be treated as a malformed/erroring real row and
     * must never trigger a mapping lookup — checked BEFORE any
     * cell-count validation or extraction is attempted. Deliberately
     * broader than just the one confirmed ID: any row WHMCS itself has
     * hidden (via the "hidden" class, the native `hidden` attribute, or
     * an explicit `display:none`) is skipped the same way, since none of
     * those represent a currently-visible real user row either.
     */
    function isSkippableRow(row) {
        if (row.id === "rowPendingInvites") {
            return true;
        }
        if (row.hidden) {
            return true;
        }
        if (row.classList && row.classList.contains("hidden")) {
            return true;
        }
        if (row.style && row.style.display === "none") {
            return true;
        }
        return false;
    }

    /**
     * 3.1.16: the server-provided mapping entry's own `state` field
     * decides the icon — never text-sniffing the (now server-supplied,
     * already human-readable) label string. The current server-side
     * mapping (TwoFactorController::buildSecondFactorMapping()) only
     * ever emits `state: "active"`, but this stays forward-compatible
     * with "pending"/"inactive" if a future version ever emits those.
     */
    function labelForMappingEntry(entry) {
        if (!entry || typeof entry.method !== "string" || entry.method === "") {
            return null;
        }
        // 3.1.26: Policy panel "Require Two-Factor Authentication" badge
        // — this user did not resolve to any recognized active method
        // (buildSecondFactorMappingWithPolicy() only ever emits this
        // state when the site-wide policy is on), so replace the
        // native "N/A" with an explicit, distinct badge rather than the
        // ambiguous native text — never inherits the ✓/⚠/○ method-name
        // format below since there is no method name to show.
        if (entry.state === "required_not_enrolled") {
            return "⚠ Required — Not Enrolled";
        }
        if (entry.state === "pending") {
            return "⚠ " + entry.method;
        }
        if (entry.state === "inactive") {
            return "○ " + entry.method;
        }
        return "✓ " + entry.method;
    }

    function processTable(table) {
        if (table.hasAttribute(PROCESSED_ATTR)) {
            return;
        }
        var colIndex = findTargetColumnIndex(table);
        if (colIndex === -1) {
            return;
        }
        log("Users table found", table);
        table.setAttribute(PROCESSED_ATTR, "1");

        // Confirmed live markup — real user rows carry class="user-item".
        // Prefer that exact, confirmed selector; it automatically
        // excludes rowPendingInvites and any other non-user row without
        // needing isSkippableRow() at all. Only if NO ".user-item" rows
        // exist (a different theme/markup this wasn't confirmed against)
        // fall back to scanning every "tbody tr" and filtering with
        // isSkippableRow().
        var rows = table.querySelectorAll("tbody tr.user-item");
        var usingFallbackRowScan = false;
        if (!rows.length) {
            rows = table.querySelectorAll("tbody tr");
            usingFallbackRowScan = true;
        }
        log("User rows detected:", rows.length, usingFallbackRowScan ? "(fallback: tr.user-item not found, scanning all tbody tr)" : "(tr.user-item)");
        if (!rows.length) {
            return;
        }

        // 3.1.16: no network request — the mapping is already available
        // synchronously as a page global (see core/two_factor_admin_display.php).
        // If it's missing entirely (hook didn't run / no admin session /
        // client id not resolved), there's nothing to look up — leave
        // every native cell untouched rather than guessing.
        var mapping = window.security_pack_2fa_users;
        if (!mapping || typeof mapping !== "object") {
            log("No server-provided mapping (window.security_pack_2fa_users) — leaving native values untouched");
            return;
        }

        for (var r = 0; r < rows.length; r++) {
            if (usingFallbackRowScan && isSkippableRow(rows[r])) {
                log("Skipping known non-user row (hidden/placeholder, e.g. rowPendingInvites) — not an error", rows[r]);
                continue;
            }
            var cells = rows[r].querySelectorAll("td");
            if (cells.length <= colIndex) {
                log("Malformed row (fewer cells than the header expects) — leaving it unchanged", rows[r]);
                continue;
            }
            var userId = extractUserId(rows[r]);
            if (!userId) {
                log("Could not resolve a WHMCS User ID for a row — leaving its Two Factor Auth Method cell unchanged");
                continue;
            }
            log("User ID detected:", userId);
            var entry = mapping[String(userId)];
            var display = labelForMappingEntry(entry);
            if (display === null) {
                log("No mapping entry (or unrecognized/empty) for User ID", userId, "— leaving native value untouched");
                continue;
            }
            log("method:", entry.method, "state:", entry.state);
            cells[colIndex].textContent = display;
            log("cell updated", cells[colIndex]);
        }
    }

    function scan() {
        var tables = document.querySelectorAll("table:not([" + PROCESSED_ATTR + "])");
        for (var t = 0; t < tables.length; t++) {
            processTable(tables[t]);
        }
    }

    function init() {
        log("overlay initialized", DEBUG ? "(debug logging on)" : "");
        scan();

        // WHMCS/Lagom2 may render or replace the Users tab table content
        // AFTER this script's initial run (async tab content). Re-scan on
        // DOM mutations, but only ever act on NOT-YET-processed tables —
        // no polling loop, no repeated calls for a table already handled.
        if (window.MutationObserver) {
            var scheduled = false;
            var observer = new MutationObserver(function () {
                if (scheduled) {
                    return;
                }
                scheduled = true;
                window.setTimeout(function () {
                    scheduled = false;
                    scan();
                }, 250);
            });
            observer.observe(document.body, { childList: true, subtree: true });
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
