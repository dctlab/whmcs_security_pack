<?php

declare(strict_types=1);

// Security Pack 2.3 — Security Headers.
//
// Emits a small, conservative set of HTTP response headers. The
// existing X-Frame-Options toggle (1.2.0's "Disable iframe Display",
// core/content_protection.php) is left exactly as-is — this file does
// NOT duplicate it. All headers here are individually admin-configurable
// (Settings tab); the three with no realistic compatibility risk default
// ON (seeded once during the 2.3.0 migration, see security_pack.php);
// CSP and HSTS default OFF and stay off unless explicitly enabled.

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

function security_pack_apply_security_headers()
{
    if(headers_sent()) {
        return;
    }
    $settings = security_pack_settings();

    if(isset($settings["sh_nosniff"])) {
        header("X-Content-Type-Options: nosniff");
    }
    if(isset($settings["sh_referrer_policy"])) {
        header("Referrer-Policy: strict-origin-when-cross-origin");
    }
    if(isset($settings["sh_permissions_policy"])) {
        // Deliberately minimal and narrow — only powerful APIs this
        // WHMCS install has no legitimate built-in use for. Does not
        // touch "fullscreen" or "payment", which some gateway/checkout
        // integrations may legitimately need.
        header("Permissions-Policy: geolocation=(), camera=(), microphone=()");
    }
    if(isset($settings["sh_csp"])) {
        // Intentionally does not attempt to author a fully restrictive
        // CSP for the entire WHMCS install (payment gateways, third-
        // party JS widgets, and theme-specific assets vary too much per
        // site for a safe one-size-fits-all policy) — Report-Only mode
        // with a permissive default lets an admin who understands their
        // own site's asset origins observe violations before ever
        // enforcing anything, rather than this module silently breaking
        // checkout or the admin UI the moment it's turned on. Still
        // REPORT-ONLY as of 2.5 — nothing in this release switches CSP
        // to enforcing mode.
        $policy = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;";
        if(!empty($settings["csp_report_collection"]) && $settings["csp_report_collection"] !== "0") {
            // Security Pack 2.5 — CSP Reports. Collection is a separate
            // admin opt-in from CSP itself: enabling Report-Only mode
            // alone never adds a report-uri, so no report ever leaves
            // the browser unless an admin has also explicitly turned on
            // collection (Settings > CSP Reports). report-uri is
            // deprecated but still the only directive every current
            // browser actually honours for Report-Only mode; report-to
            // requires an additional Reporting-Endpoints header most
            // browsers don't yet pair with CSP the same way, so both are
            // sent for the widest safe coverage.
            $reportUrl = "/modules/addons/security_pack/csp-report.php";
            $policy .= " report-uri " . $reportUrl . "; report-to security-pack-csp;";
            header("Reporting-Endpoints: security-pack-csp=\"" . $reportUrl . "\"");
        }
        header("Content-Security-Policy-Report-Only: " . $policy);
    }
    if(isset($settings["sh_hsts"]) && isset($settings["sh_hsts_confirm_https"])) {
        // Only ever sent if the admin has BOTH turned it on AND
        // explicitly confirmed the whole site is HTTPS-only — sending
        // HSTS to a site still reachable over plain HTTP can lock
        // visitors out entirely for the max-age duration.
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
}

add_hook("ClientAreaHeaderOutput", 1, function ($vars) {
    security_pack_apply_security_headers();
});

// AdminAreaHeaderOutput: registering a callback for a hook point that a
// given WHMCS build doesn't fire is harmless (add_hook() just stores the
// callback; nothing calls it if the hook point never triggers), so this
// is safe on any WHMCS 8.x/9.x version without a version check.
add_hook("AdminAreaHeaderOutput", 1, function ($vars) {
    security_pack_apply_security_headers();
});
