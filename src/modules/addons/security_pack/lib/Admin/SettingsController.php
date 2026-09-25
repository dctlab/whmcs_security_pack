<?php


// file for php version 74.
namespace WHMCS\Module\Addon\Security_Pack\Admin;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack — Settings (module-wide toggles: Login History, Login
 * Notification, Advanced Security Options, Email 2FA length/window,
 * Content Protection, Country Restriction's master switch + whitelist,
 * GeoIP Language & Currency's master switch + cache/cookie windows, and
 * Security Headers).
 *
 * PHASE 3.5 (2026-08-24): migrated to the templates/admin/ presentation
 * layer, same pattern validated on Dashboard/Alerts/Activity/Analytics/
 * Diagnostics. index() builds a view-model (one entry per field this
 * page renders, grouped into sections) instead of echoing HTML directly.
 *
 * 2026-08-27: the Country Restriction panel's GEO Providers field (the
 * freeipapi.com/geojs.io/ipapi.co multi-select), its provider-discovery
 * loop, and the "choose a provider before enabling" save() validation
 * were all removed — Country Restriction (and GeoIP Language & Currency)
 * now resolve exclusively against the MaxMind database; see
 * GeoIpManager's own docblock. "providers" was also dropped from
 * OWNED_KEYS since this form no longer has anything to save it from.
 */
class SettingsController
{
    /**
     * Every checkbox/select/text field this specific admin form (index())
     * is capable of rendering. Used by save() to know which settings keys
     * it is allowed to touch — anything NOT in this list (e.g. keys owned
     * by LangCurrencyController's Advanced Settings / Default Fallback
     * panels, CountryRestrictionController's Mode/country-list/unknown-
     * policy fields (2.8), or the Diagnostics page) is left completely
     * untouched.
     */
    private const OWNED_KEYS = [
        "login_history", "client_history", "admin_history", "auto_delete", "auto_delete_days",
        "login_notification", "admin_login_notification", "login_notification_default", "allow_disable_notification",
        "sh_nosniff", "sh_referrer_policy", "sh_permissions_policy", "sh_csp", "sh_hsts", "sh_hsts_confirm_https",
        "password_reset", "ip_range_limits", "block_free_emails", "disable_activity_log",
        "email_2fa_length", "email_2fa_minutes",
        "right_click", "copy_paste", "iframe",
        "country_restriction", "whitelist",
        "lang_currency", "lc_banner", "geo_cache_days", "lc_cookie_days",
    ];

    public function index()
    {
        $settings = security_pack_settings();

        $errorMessage = null;
        if(isset($_SESSION["nnm_error"])) {
            $errorMessage = (string) $_SESSION["nnm_error"];
            unset($_SESSION["nnm_error"]);
        }

        $content = TemplateRenderer::render("settings", [
            "errorMessage" => $errorMessage,
            "token" => security_pack_csrf_token(),
            "loginHistory" => $this->buildLoginHistorySection($settings),
            "loginNotification" => $this->buildLoginNotificationSection($settings),
            "advancedSecurity" => $this->buildAdvancedSecuritySection($settings),
            "systemActivityLog" => $this->buildSystemActivityLogSection($settings),
            "email2fa" => $this->buildEmail2faSection($settings),
            "contentProtection" => $this->buildContentProtectionSection($settings),
            "countryRestriction" => $this->buildCountryRestrictionSection($settings),
            "geoLangCurrency" => $this->buildGeoLangCurrencySection($settings),
            "securityHeaders" => $this->buildSecurityHeadersSection($settings),
        ]);

        echo TemplateRenderer::assetTags();
        echo TemplateRenderer::render("layout", [
            "pageTitle" => "DCTLAB Security Pack Settings",
            "pageDescription" => "Configure DCTLAB Security Pack protection and behavior.",
            "pageActionsHtml" => "",
            "content" => $content,
        ]);
    }

    private function buildLoginHistorySection($settings): array
    {
        $enabled = isset($settings["login_history"]);
        return [
            "title" => "Login History",
            "tooltip" => "Enable logging all clients/admins login history also show them in client area too.",
            "panelClass" => "nnm_login_history",
            "masterToggle" => ["name" => "login_history", "checked" => $enabled],
            "rows" => [
                ["type" => "toggle", "name" => "client_history", "label" => "Show History", "tooltip" => "Allow clients to can see they login history in client area.", "checked" => isset($settings["client_history"])],
                ["type" => "toggle", "name" => "admin_history", "label" => "Admin Logins", "tooltip" => "Log admins login history too.", "checked" => isset($settings["admin_history"])],
                ["type" => "toggle", "name" => "auto_delete", "label" => "Auto Delete Logs", "tooltip" => "Automatically delete the login history logs older than X days.", "checked" => isset($settings["auto_delete"])],
                ["type" => "number", "name" => "auto_delete_days", "label" => "Auto Delete Logs Days", "tooltip" => "Automatically delete login history days.", "value" => $settings["auto_delete_days"] ? intval($settings["auto_delete_days"]) : 30, "min" => 1, "suffix" => "Days"],
            ],
        ];
    }

    private function buildLoginNotificationSection($settings): array
    {
        $notificationOptions = ["0" => "Disabled", "1" => "All Logins", "2" => "New Device Login"];
        return [
            "title" => "Login Notification",
            "tooltip" => "Enable login email notification to clients/admins get email when login to your WHMCS.",
            "rows" => [
                ["type" => "select", "name" => "login_notification", "label" => "Client Login Notification", "tooltip" => "When you choose the New Device Login Alert notification module will check client login history, you need to enable login history to can use this option.", "options" => $notificationOptions, "value" => isset($settings["login_notification"]) ? (string) $settings["login_notification"] : "0"],
                ["type" => "select", "name" => "admin_login_notification", "label" => "Admin Login Notification", "tooltip" => "When you choose the New Device Login Alert notification module will check admin login history, you need to enable login history to can use this option.", "options" => $notificationOptions, "value" => isset($settings["admin_login_notification"]) ? (string) $settings["admin_login_notification"] : "0"],
                ["type" => "toggle", "name" => "login_notification_default", "label" => "Enabled Default", "tooltip" => "Enable login notification by default and clients/admins can disable if you allowed..", "checked" => isset($settings["login_notification_default"])],
                ["type" => "toggle", "name" => "allow_disable_notification", "label" => "Allow Disable", "tooltip" => "Allow clients to can disable login notification in client area.", "checked" => isset($settings["allow_disable_notification"])],
            ],
        ];
    }

    private function buildAdvancedSecuritySection($settings): array
    {
        return [
            "title" => "Advanced Security Options",
            "rows" => [
                ["type" => "toggle", "name" => "password_reset", "label" => "Disable Password Reset", "tooltip" => "Allow clients to can disable forget password reset in client area.", "checked" => isset($settings["password_reset"])],
                ["type" => "toggle", "name" => "ip_range_limits", "label" => "IP Security Limits", "tooltip" => "Allow clients to can limit login to selected IP ranges.", "checked" => isset($settings["ip_range_limits"])],
                ["type" => "toggle", "name" => "block_free_emails", "label" => "Block Free Email Providers", "tooltip" => "Block popular free email providers for example : Gmail, Yahoo, Hotmail, ...", "checked" => isset($settings["block_free_emails"])],
            ],
        ];
    }

    /**
     * 2026-08-27: master on/off switch for whether DCTLAB Security Pack
     * writes its own entries (audit trail, diagnostic markers) into
     * WHMCS's native System Activity Log (Utilities > Logs > Activity
     * Log). Every call this addon makes to WHMCS's logActivity() is
     * routed through security_pack_log_activity() (hooks.php), which
     * checks this exact setting — see that function's own docblock.
     *
     * Default is ON (unset = logging happens, matching every existing
     * install's current behavior); checking the box turns writes off.
     * WHMCS's own native logging, and any OTHER module's/hook's direct
     * logActivity() calls, are completely unaffected either way.
     */
    private function buildSystemActivityLogSection($settings): array
    {
        return [
            "title" => "System Activity Log",
            "tooltip" => "Controls whether DCTLAB Security Pack writes its own entries into WHMCS's native Activity Log (Utilities > Logs > Activity Log). Does not affect WHMCS's own logging or any other module.",
            "rows" => [
                ["type" => "toggle", "name" => "disable_activity_log", "label" => "Disable System Activity Log", "tooltip" => "When enabled, Security Pack stops writing its own audit/diagnostic entries into WHMCS's Activity Log. Off by default — logging happens as it always has.", "checked" => isset($settings["disable_activity_log"])],
            ],
        ];
    }

    private function buildEmail2faSection($settings): array
    {
        return [
            "title" => "Email Two-Factor Authentication",
            "tooltip" => "Email 2FA setting, you need to enable 2FA in WHMCS Two-Factor Authentication settings page.",
            "rows" => [
                ["type" => "number", "name" => "email_2fa_length", "label" => "Code Length", "tooltip" => "Put generated 2FA code length", "value" => $settings["email_2fa_length"] ? intval($settings["email_2fa_length"]) : 6, "min" => 4],
                ["type" => "number", "name" => "email_2fa_minutes", "label" => "Valid For", "tooltip" => "Put maximum X minutes that client need to fill 2FA code, leave blank or 0 to be unlimited", "value" => $settings["email_2fa_minutes"] ? intval($settings["email_2fa_minutes"]) : 10, "min" => 1, "suffix" => "Minutes"],
            ],
        ];
    }

    private function buildContentProtectionSection($settings): array
    {
        return [
            "title" => "Content Protection",
            "rows" => [
                ["type" => "toggle", "name" => "right_click", "label" => "Disable Right Click", "tooltip" => "No right click or context menu.", "checked" => isset($settings["right_click"])],
                ["type" => "toggle", "name" => "copy_paste", "label" => "Disable Copy/Paste", "tooltip" => "Disallow clients to can copy or paste.", "checked" => isset($settings["copy_paste"])],
                ["type" => "toggle", "name" => "iframe", "label" => "Disable iframe Display", "tooltip" => "Disallow clients to can show your WHMCS in iframes.", "checked" => isset($settings["iframe"])],
            ],
        ];
    }

    /**
     * Mode, the country list, and the unknown-country policy are managed
     * on CountryRestrictionController's own page (Security Pack 2.8) —
     * this panel keeps only the enable toggle and Whitelist IP.
     *
     * 2026-08-27 — per explicit request, the GEO Providers field (the
     * freeipapi.com/geojs.io/ipapi.co multi-select) was removed from
     * this panel entirely: Country Restriction (and GeoIP Language &
     * Currency, which shares the same GeoIpManager) now resolves
     * exclusively against the MaxMind database uploaded on the Language
     * & Currency page — see GeoIpManager's own docblock for the matching
     * change on the resolution side. The provider-discovery loop that
     * used to build this field's options is gone with it; nothing else
     * in this section changed.
     */
    private function buildCountryRestrictionSection($settings): array
    {
        return [
            "checked" => isset($settings["country_restriction"]),
            "whitelist" => $settings["whitelist"] ?? "",
        ];
    }

    private function buildGeoLangCurrencySection($settings): array
    {
        return [
            "langCurrency" => isset($settings["lang_currency"]),
            "lcBanner" => isset($settings["lc_banner"]),
            "geoCacheDays" => $settings["geo_cache_days"] ?? "7",
            "lcCookieDays" => $settings["lc_cookie_days"] ?? "365",
        ];
    }

    /**
     * Same conservative defaults as the original (Step 18/20 of the 2.3
     * spec, docblock preserved): X-Content-Type-Options/Referrer-Policy/
     * Permissions-Policy default ON; CSP/HSTS default OFF and stay off
     * unless explicitly enabled. X-Frame-Options is intentionally NOT
     * duplicated here — already controlled by Content Protection's
     * "Disable iframe Display" toggle above, one authoritative setting.
     */
    private function buildSecurityHeadersSection($settings): array
    {
        $safeHeaders = [
            ["name" => "sh_nosniff", "label" => "X-Content-Type-Options: nosniff", "description" => "Stops browsers from guessing (\"sniffing\") a file's content type — no known compatibility risk.", "checked" => isset($settings["sh_nosniff"])],
            ["name" => "sh_referrer_policy", "label" => "Referrer-Policy: strict-origin-when-cross-origin", "description" => "Limits how much of your URL is sent as a Referer header to other sites — no known compatibility risk.", "checked" => isset($settings["sh_referrer_policy"])],
            ["name" => "sh_permissions_policy", "label" => "Permissions-Policy (camera/microphone/geolocation off by default)", "description" => "Disables a small set of powerful browser APIs this WHMCS install has no legitimate use for — no known compatibility risk.", "checked" => isset($settings["sh_permissions_policy"])],
        ];
        return [
            "safeHeaders" => $safeHeaders,
            "csp" => ["checked" => isset($settings["sh_csp"])],
            "hsts" => ["checked" => isset($settings["sh_hsts"])],
            "hstsConfirmHttps" => ["checked" => isset($settings["sh_hsts_confirm_https"])],
        ];
    }

    public function save()
    {
        if(isset($_POST["save"])) {
            if(!security_pack_csrf_valid()) {
                $_SESSION["nnm_error"] = "Your session token expired — please try saving again.";
                redir("module=security_pack&c=settings", "addonmodules.php");
            }
            // Security Pack 2.4 (Phase 4, Step 12): a crafted request can
            // submit "settings" as a non-array (e.g. ?settings=x rather
            // than settings[key]=value) — accessing array offsets on that
            // would previously emit PHP warnings for every check below.
            // Treat anything that isn't actually an array as "no settings
            // submitted" rather than let it reach array-offset access.
            $requestSettings = is_array($_REQUEST["settings"] ?? null) ? $_REQUEST["settings"] : [];
            // Security Pack 2.8: the country list itself moved to
            // CountryRestrictionController's own save().
            //
            // 2026-08-27: the "choose a GEO Provider before enabling"
            // requirement that used to live here is gone along with the
            // GEO Providers field itself — Country Restriction now
            // resolves purely against the MaxMind database (see
            // GeoIpManager's docblock), so there is no longer a provider
            // selection to require before turning it on. An empty
            // country list was already a valid, safe (no-op) state, not
            // a validation error.

            // NON-DESTRUCTIVE SAVE (Security Pack 2.0): this used to
            // TRUNCATE the entire dctlab_security_pack settings table and
            // reinsert only the keys submitted by THIS form — which
            // silently wiped out every setting owned by any other admin
            // page (GeoIP Language & Currency's Advanced Settings/Default
            // Fallback panels, Diagnostics, etc.) every time this form was
            // saved. Now each key this form owns is individually
            // upserted when checked/filled, or deleted when an owned
            // checkbox is left unchecked — every other setting in the
            // table is left completely alone.
            $submitted = $requestSettings;
            $before = ["settings" => security_pack_settings()];
            foreach ($submitted as $key => $setting) {
                if(!in_array($key, self::OWNED_KEYS, true)) {
                    // Defensive: ignore any unexpected key rather than let
                    // a crafted request write to a setting this form
                    // doesn't own.
                    continue;
                }
                if(is_array($setting)) {
                    $setting = json_encode(array_values($setting));
                } else {
                    $setting = (string) $setting;
                }
                \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->updateOrInsert(["setting" => $key], ["setting" => $key, "value" => $setting]);
            }
            // Unchecked checkboxes never appear in $_REQUEST at all, so an
            // owned key that was NOT submitted this time means the admin
            // just turned it off — remove it (checkbox settings are only
            // ever tested with isset(), so "absent" is the off state).
            foreach (self::OWNED_KEYS as $key) {
                if(!array_key_exists($key, $submitted)) {
                    \Illuminate\Database\Capsule\Manager::table("dctlab_security_pack")->where("setting", $key)->delete();
                }
            }
            if(function_exists("security_pack_record_event")) {
                security_pack_record_event("settings.updated", "DCTLAB Security Pack settings were updated from the admin Settings tab.", ["before" => $before]);
            }
        }
        redir("module=security_pack&c=settings&saved=1", "addonmodules.php");
    }
}
