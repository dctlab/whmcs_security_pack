<?php

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — Admin Client Profile > Users tab integration.
 *
 * WHMCS's own native "Users" tab on the admin Client Profile page has a
 * "Two Factor Auth Method" column that only ever reflects WHMCS's OWN
 * native Security Module-based 2FA state (`tblusers.second_factor`). It
 * has no knowledge of Security Pack's own Email/DCTLAB WhatsApp/TOTP
 * enrollment, so an account with one of those methods active shows
 * "N/A" there. WHMCS ships no documented extension point that lets an
 * addon rewrite an existing native admin table's cell content
 * (AdminClientProfileTabFields only APPENDS new field rows — see
 * core/email_2fa.php — it cannot alter an existing column), so this is
 * handled the same way this project's other native-table overlays are
 * (see core/loginHistory.php): a small, fail-soft JavaScript file finds
 * the native table by its actual column header text, resolves each
 * row's real WHMCS User ID, and updates the cell.
 *
 * 3.1.6-3.1.11 built that overlay around an AJAX request to a small
 * admin-session-gated endpoint (TwoFactorController::ajaxUsersTwoFactorStatus(),
 * now REMOVED). That endpoint 404'd on the reported install — its
 * Admin Client Profile page is client-side-routed to a friendly
 * "/client/{id}/..." URL, and neither a relative fetch URL nor an
 * absolute URL computed server-side from $_SERVER["SCRIPT_NAME"]
 * reliably avoided inheriting that routed path.
 *
 * 3.1.16 — "FINAL ADMIN USERS 2FA DISPLAY FIX": removes the AJAX
 * request entirely, per the explicit "DO NOT create another URL guess /
 * DO NOT add another AJAX fallback" instruction. There is no round-trip
 * left to get wrong: this hook now computes the ENTIRE
 * `{userId: {method, state}}` mapping SERVER-SIDE — for the real WHMCS
 * Users belonging to the client currently being viewed — and injects it
 * as a JSON page global (`window.security_pack_2fa_users`). The client
 * is identified via `$_REQUEST["userid"]`, WHMCS's own long-standing
 * Client Profile parameter name — the SAME parameter
 * core/loginHistory.php already reads for the identical "which client's
 * tab is this" purpose, so this is an established, already-relied-upon
 * pattern in this codebase, not a new guess. The JS overlay
 * (assets/js/two_factor_admin_users.js) is now pure DOM presentation:
 * find the table, find the column, find each row's real User ID via the
 * same confirmed-markup selectors as before, look that ID up in the
 * already-injected mapping, write the cell. No fetch(), no endpoint
 * URL, no CSRF token needed for this display at all.
 *
 * Per Section "DATA SOURCE": the mapping is built directly from WHMCS's
 * own native `tblusers.second_factor` column (see
 * TwoFactorController::buildUsersTwoFactorMappingForClient() /
 * labelFromSecondFactorModule()) — not from
 * TwoFactorAuthenticationService::status() — since that native column is
 * exactly what this native display, and WHMCS's own Manage User modal
 * ("Two-Factor Authentication: ON"), are themselves keyed on. A user
 * whose second_factor value isn't one of Security Pack's own three
 * known security-module names is OMITTED from the mapping entirely —
 * never included with a guessed label — so the JS overlay leaves that
 * row's native "N/A" exactly as WHMCS rendered it.
 *
 * Per Section "SECURITY": the injected mapping is gated on a real admin
 * session, is built ONLY from User IDs resolved server-side for the
 * client actually being viewed (never an arbitrary/attacker-supplied
 * ID — see TwoFactorController::resolveUserIdsForClient()), and
 * contains only a WHMCS User ID, a human-readable method label, and a
 * state string — never an OTP, hash, secret, recovery code, or any
 * other credential. `json_encode()` uses the HEX_* flags so the
 * embedded JSON can never break out of its `<script>` context.
 *
 * The injected `<script src>` for the JS itself still carries a
 * deterministic `?v=<version>` query string built from the addon's own
 * `security_pack_config()["version"]` (3.1.11's deployment-cache
 * defense — never a random/time-based value).
 *
 * 3.1.18 — CONFIRMED LIVE REGRESSION FIX: 3.1.16 shipped, was deployed,
 * and the "N/A" bug was STILL reproduced live for a confirmed-active
 * dct_totp_2fa user, with the admin browser's address bar showing a
 * clean, query-string-free path: "/client/{id}/users" — no
 * "?userid={id}" anywhere in the URL. Root cause: `$_REQUEST["userid"]`
 * is only ever populated from an actual query-string/POST parameter;
 * WHMCS's own friendly router for this page does NOT appear to
 * back-fill $_REQUEST from the routed path segment on this install, so
 * $clientId silently resolved to 0 and the mapping was always empty —
 * indistinguishable, from the JS's fail-soft perspective, from "hook
 * never ran". This was the same class of client-side-routing mismatch
 * 3.1.9/3.1.11 already hit once for the (now-removed) AJAX endpoint URL,
 * just on the server side of this hook instead of the client side.
 *
 * Fix: {@see security_pack_2fa_resolve_viewed_client_id()} now tries
 * $_REQUEST["userid"] FIRST (unchanged — preserves any install where the
 * classic query-string form is actually present, e.g. via a bookmarked
 * old-style URL), and falls back to parsing the numeric client ID
 * directly out of the current request's own URL path
 * ("/client/{id}/...", matching the exact "/client/666037/users" shape
 * reproduced live) when no usable $_REQUEST value was found. This is
 * NOT the "another URL guess for an AJAX endpoint" the original ticket
 * forbade — there is still no AJAX request anywhere in this file; this
 * only reads the CLIENT ID being viewed from the URL WHMCS itself
 * already routed this authenticated admin session to (the adminid
 * session check above still gates the whole hook), the same way
 * WHMCS's own router derived it in the first place.
 *
 * 3.1.19 — SECOND CONFIRMED LIVE BUG, independent of 3.1.18's fix: 3.1.18
 * was deployed and the column STILL showed "N/A" for the same confirmed
 * install/user. Root cause: the `<script src="...">` tag for
 * two_factor_admin_users.js was built as a RELATIVE URL
 * ("../modules/addons/security_pack/assets/js/two_factor_admin_users.js").
 * A relative URL resolves against the CURRENT BROWSER URL's path depth —
 * not the physical file location on disk. On an old-style, one-segment
 * admin URL ("/ish_myadmin/clientssummary.php?userid=666037") "../"
 * correctly climbs one level to the WHMCS root and finds "modules/...".
 * But on this install's THREE-segment friendly URL
 * ("/ish_myadmin/client/666037/users") "../" only climbs OUT OF the
 * "users" segment, landing on
 * ".../ish_myadmin/client/modules/addons/..." — a URL that does not
 * exist, so the browser 404s loading the script and it never runs. The
 * inline `<script>var security_pack_2fa_users = {...};</script>` tag
 * (no `src`, unaffected by this) still executes fine — so the mapping
 * WAS correctly present as a page global the whole time, but nothing was
 * ever loaded to read it and update the table, which looks identical
 * from the page's perspective to "the hook never ran" — the same
 * symptom as 3.1.18's bug, but a completely different, independent root
 * cause underneath it. Neither this nor 3.1.18's bug would have been
 * caught by this suite's existing source-regex tests, since both are
 * about how a BROWSER resolves a URL relative to its OWN current
 * address, not something visible from reading the PHP/JS source text in
 * isolation.
 *
 * Fix: {@see security_pack_2fa_asset_base_url()} builds an ABSOLUTE
 * script `src` instead of a relative one, preferring WHMCS's own
 * configured `SystemURL` setting (`\WHMCS\Config\Setting::getValue()`)
 * — the same authoritative base URL WHMCS itself uses to build its own
 * absolute asset URLs, entirely independent of how many friendly-router
 * path segments deep the current browser URL happens to be — and
 * falling back to deriving the WHMCS root from `$_SERVER["SCRIPT_NAME"]`
 * (the actual executing front-controller file, which stays fixed
 * regardless of the friendly `REQUEST_URI` a rewrite rule presents to
 * the browser) only if that setting is unavailable.
 */
function security_pack_2fa_asset_base_url(): string
{
    if(class_exists("\\WHMCS\\Config\\Setting")) {
        try {
            $systemUrl = (string) \WHMCS\Config\Setting::getValue("SystemURL");
            if($systemUrl !== "") {
                return rtrim($systemUrl, "/");
            }
        } catch (\Throwable $e) {
        }
    }
    $scriptName = isset($_SERVER["SCRIPT_NAME"]) && is_string($_SERVER["SCRIPT_NAME"]) ? $_SERVER["SCRIPT_NAME"] : "";
    if($scriptName !== "") {
        $adminDir = rtrim(str_replace("\\", "/", dirname($scriptName)), "/");
        $root = rtrim(str_replace("\\", "/", dirname($adminDir === "" ? "/" : $adminDir)), "/");
        return $root; // "" correctly means "site root" for the caller below
    }
    return "";
}

function security_pack_2fa_resolve_viewed_client_id(): int
{
    if(isset($_REQUEST["userid"]) && is_numeric($_REQUEST["userid"])) {
        $fromRequest = (int) $_REQUEST["userid"];
        if($fromRequest > 0) {
            return $fromRequest;
        }
    }
    // Fallback: the friendly-routed Client Profile URL always carries the
    // client ID as a "/client/{id}/..." path segment. Check every
    // superglobal that plausibly holds the current request's raw path,
    // in order of reliability, and stop at the first numeric match.
    foreach (["REQUEST_URI", "PATH_INFO", "REDIRECT_URL", "PHP_SELF"] as $key) {
        $candidate = isset($_SERVER[$key]) && is_string($_SERVER[$key]) ? $_SERVER[$key] : "";
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

add_hook("AdminAreaFooterOutput", 1, function ($vars) {
    if(!class_exists("\\WHMCS\\Module\\Addon\\Security_Pack\\Admin\\TwoFactorController")) {
        return "";
    }
    // Section "SECURITY" / "unauthorized/non-admin context fails safely":
    // the mapping must be generated only for the authorized admin
    // viewing the page. Fails closed (empty mapping) rather than
    // throwing or leaking anything if this hook is ever reached without
    // a real admin session.
    if(empty($_SESSION["adminid"]) || (int) $_SESSION["adminid"] <= 0) {
        return "";
    }

    // The Admin Client Profile page carries the CLIENT id either as a
    // classic $_REQUEST["userid"] query parameter or, on this install's
    // friendly-routed URLs (confirmed live: "/client/{id}/users" with no
    // query string at all), as a "/client/{id}/..." path segment — see
    // security_pack_2fa_resolve_viewed_client_id() above (3.1.18). Any
    // other admin page (neither form present) simply resolves to an
    // empty mapping below — the JS overlay then does nothing, exactly as
    // if this hook had never run.
    $clientId = security_pack_2fa_resolve_viewed_client_id();
    $mapping = $clientId > 0
        ? \WHMCS\Module\Addon\Security_Pack\Admin\TwoFactorController::buildUsersTwoFactorMappingForClient($clientId)
        : [];

    $assetVersion = function_exists("security_pack_config")
        ? (string) (security_pack_config()["version"] ?? "")
        : "";
    // 3.1.19: ABSOLUTE URL, never relative — see the docblock above
    // security_pack_2fa_asset_base_url() for why a relative "../" src
    // silently 404'd on this install's friendly-routed Client Profile
    // URLs.
    $assetSrc = security_pack_2fa_asset_base_url() . "/modules/addons/security_pack/assets/js/two_factor_admin_users.js"
        . ($assetVersion !== "" ? "?v=" . rawurlencode($assetVersion) : "");

    // JSON_FORCE_OBJECT: an empty mapping still serializes as "{}", never
    // "[]", so the JS's `mapping[id]` lookup is always well-defined. The
    // HEX_* flags escape "<", ">", "&", "'", """ so this can never break
    // out of the surrounding <script> tag even via a stored label.
    $mappingJson = json_encode(
        $mapping,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_FORCE_OBJECT
    );
    if($mappingJson === false) {
        $mappingJson = "{}";
    }

    return "<script>var security_pack_2fa_users = " . $mappingJson . ";</script>"
        . "<script type=\"text/javascript\" src=\"" . htmlspecialchars($assetSrc, ENT_QUOTES, "UTF-8") . "\"></script>";
});
