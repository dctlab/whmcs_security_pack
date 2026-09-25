<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\OtpEngine;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * DctWhatsAppNotificationsBridge
 *
 * Security Pack 3.1 — real integration with the actual DCTLAB WhatsApp
 * platform: https://github.com/dctlab/WHMCS-WhatsApp-Notifications
 * ("dct_whatsapp_notifications" addon module).
 *
 * REPLACES the 3.0.0 `DctlabWhatsAppClient` — that class was a best-effort,
 * explicitly-disclosed-as-UNVERIFIED raw HTTP client against a guessed
 * "DCTLAB API" shape, because no real DCTLAB reference was available at
 * build time. It has been deleted, not deprecated — a second WhatsApp
 * transport would violate this project's non-duplication rule now that a
 * real, confirmed integration point exists.
 *
 * This bridge mirrors — as closely as the WHMCS security-module contract
 * allows — the actual reference `modules/security/dct2fa/dct2fa.php`
 * module the user runs in production (itself built against this addon),
 * cross-checked line-by-line against the addon's real source
 * (`src/Core/...`) cloned directly from the GitHub repo above:
 *
 *  - CLIENT logins: resolve a real `tblclients.id`, then send through the
 *    addon's own customizable "TwoFactorAuthentication" notification
 *    (Notifications -> TwoFactorAuthentication in that addon's admin UI) —
 *    `Dct\HookNotification\Core\Notification\Application\NotificationFactory::
 *    getInstance()->makeByCode('TwoFactorAuthentication')` then
 *    `NotificationSender::getInstance()->send($notification, [...])`, exactly
 *    as `dct2fa_send_code()` does. Falls back to a plain direct message if
 *    the notification isn't found/enabled, or the send doesn't report SENT
 *    — a login must never be blocked by a missing/broken template.
 *  - ADMIN logins: ALWAYS the plain direct message path — WHMCS admin
 *    accounts are not WHMCS clients, and the addon's whole notification/
 *    template system (client name/email merge fields, opt-out preferences,
 *    delivery reporting) is built around a real client record existing.
 *  - Plain-message platform selection follows the addon's own
 *    `Settings::WA2FA_PLATFORM` setting (Settings -> Module -> "2FA
 *    Delivery Platform" in that addon): a specific choice tries only that
 *    platform; "auto" (default) tries Meta, then Botms.in, then Baileys,
 *    stopping at the first success — same order/semantics as
 *    `dct2fa_send_plain_message()`.
 *
 * WHERE THIS DEVIATES FROM THE dct2fa.php REFERENCE, AND WHY:
 *  - dct2fa.php passes `$_SESSION['uid']` directly as the notification's
 *    `client_id`. This project's own `WhatsAppTwoFactorService` already
 *    disclosed (3.0.0) that `$_SESSION['uid']`/the security-module `user_
 *    info.id` is a WHMCS **User** id, which is not guaranteed to equal a
 *    `tblclients.id` — and built `resolveClientIdForUser()` specifically
 *    to resolve the real client record rather than assume equality. That
 *    existing, more careful resolver is reused here (passed in by the
 *    caller) instead of re-deriving/relaxing it to match the reference's
 *    simpler assumption — the reference's own shortcut is not copied.
 *  - Everything else (bootstrap path, notification code, hook-params keys,
 *    platform fallback order, Meta template component shape) matches the
 *    real addon source exactly, verified by cloning
 *    github.com/dctlab/WHMCS-WhatsApp-Notifications directly and reading
 *    Settings.php / PlatformSettingsFactory.php / PlatformApiClientFactory.php
 *    / NotificationSender.php / NotificationFactory.php /
 *    TwoFactorAuthenticationNotification.php.
 *
 * If the `dct_whatsapp_notifications` addon is not installed (or its
 * vendor/autoload.php is missing — e.g. `composer install` was never run
 * for it), every method here fails closed (returns false) rather than
 * fatal-erroring a login — the exact same "never let a broken dependency
 * lock someone out of authenticating in a way that shows a white screen"
 * discipline the rest of this module already follows.
 */
class DctWhatsAppNotificationsBridge
{
    private const ADDON_FOLDER = "dct_whatsapp_notifications";

    private static bool $booted = false;
    private static bool $available = false;

    /**
     * 2026-08-23 — diagnostic fix: WHY this class's own header docblock
     * describes as fail-closed ("every method here fails closed... rather
     * than fatal-erroring") turned out, on this exact failure path, to
     * ALSO fail SILENT — a real gap, not the intended behavior. If the
     * addon's own files aren't found (or class_exists() fails after
     * requiring them), bootstrap() used to just set $available=false and
     * return with NO log entry anywhere: lkn_hn_log() itself lives in the
     * very helpers.php that failed to load, so the one place this bridge
     * would normally log a reason was exactly the thing unavailable. That
     * produced a report of "no message sent, AND no log entry anywhere" —
     * which is this exact bootstrap failure, not some deeper platform-send
     * problem. Fixed by recording the reason here via
     * security_pack_record_event() instead — Security Pack's OWN logger,
     * which (unlike lkn_hn_log()) has no dependency on the other addon
     * having loaded, so it logs even in the total-bootstrap-failure case.
     */
    private static ?string $unavailableReason = null;

    /**
     * Locates and loads the addon's autoloader/helpers exactly once per
     * request. Safe to call repeatedly — every public method calls this
     * first. Never throws; sets self::$available instead.
     */
    private static function bootstrap(): void
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        $addonDir = self::addonDir();
        $autoload = $addonDir . "/vendor/autoload.php";
        $helpers = $addonDir . "/src/Core/Shared/Infrastructure/helpers.php";

        if (!is_file($autoload) || !is_file($helpers)) {
            self::$unavailableReason = "The \"dct_whatsapp_notifications\" addon was not found at the expected path (" . $addonDir . "). Missing: "
                . implode(" and ", array_filter([!is_file($autoload) ? "vendor/autoload.php (composer install may not have been run for that addon)" : null, !is_file($helpers) ? "src/Core/Shared/Infrastructure/helpers.php" : null]))
                . ". Confirm the addon's files are actually present in modules/addons/dct_whatsapp_notifications on THIS server (not just in a local dev copy) and that composer install has been run there.";
            self::logUnavailable();
            return;
        }

        try {
            require_once $autoload;
            require_once $helpers;
            self::$available = class_exists(\Dct\HookNotification\Core\Notification\Application\Services\NotificationSender::class);
            if (!self::$available) {
                self::$unavailableReason = "The \"dct_whatsapp_notifications\" addon's files loaded, but its NotificationSender class was not found afterward — the addon may be a different/incompatible version than this bridge expects.";
                self::logUnavailable();
            }
        } catch (\Throwable $e) {
            self::$available = false;
            self::$unavailableReason = "Loading the \"dct_whatsapp_notifications\" addon's autoloader/helpers threw: " . $e->getMessage();
            self::logUnavailable();
        }
    }

    /** Fires exactly once per request, the first time bootstrap() fails — see $unavailableReason's docblock. */
    private static function logUnavailable(): void
    {
        if (function_exists("security_pack_record_event")) {
            security_pack_record_event(
                "2fa.whatsapp.dctlab_addon_unavailable",
                "WhatsApp 2FA could not send a code because the \"dct_whatsapp_notifications\" addon is not usable right now: " . self::$unavailableReason,
                [],
                "warning"
            );
        }
    }

    /**
     * Absolute path to `modules/addons/dct_whatsapp_notifications` — a
     * sibling of `modules/addons/security_pack`, matching the addon's own
     * documented installation layout (and dct2fa.php's own `__DIR__ .
     * '/../../addons/dct_whatsapp_notifications'` for the module tree).
     */
    private static function addonDir(): string
    {
        // __DIR__ = .../modules/addons/security_pack/lib/Security/TwoFactor/Providers
        // dirname(__DIR__, 5) = .../modules/addons — the addon's sibling directory.
        return dirname(__DIR__, 5) . "/" . self::ADDON_FOLDER;
    }

    /** True once the addon's classes are confirmed loadable. */
    public static function isAvailable(): bool
    {
        self::bootstrap();
        return self::$available;
    }

    /**
     * Sends a WhatsApp 2FA code. This is the ONE entry point
     * WhatsAppTwoFactorService calls — it never talks to the addon
     * directly.
     *
     * @param string   $userType  WhatsAppTwoFactorService::TYPE_CLIENT | TYPE_ADMIN
     * @param int|null $clientId  A real tblclients.id (already resolved by
     *                            the caller via resolveClientIdForUser()) —
     *                            a CANDIDATE for the templated client path,
     *                            only actually used when its own stored
     *                            phone matches $phoneNumber (see
     *                            clientOwnsPhone()'s docblock); null (or
     *                            userType===admin) always falls through to
     *                            the plain-message path.
     */
    public static function sendCode(string $userType, ?int $clientId, string $phoneNumber, string $code, int $validMinutes): bool
    {
        self::bootstrap();
        if (!self::$available) {
            return false;
        }

        // 3.1.5 hardening: a defense-in-depth outer try/catch around the
        // ENTIRE public entry point, on top of the per-platform try/catch
        // already inside sendViaTemplatedNotification()/sendPlainMessage().
        // A production TypeError was reported from deep inside the addon's
        // own NotificationSender -> NotificationPlatformResolver ->
        // PlatformFactory chain (PlatformFactory::make() receiving a null
        // $platform — almost always means the addon's "TwoFactorAuthentication"
        // notification is enabled but has no delivery platform actually
        // assigned to it in that addon's own Notifications settings; check
        // that addon-side configuration). Whatever the exact cause, a 2FA
        // OTP send attempt must NEVER be capable of fatally crashing a
        // login/activation request — every code path here now returns
        // false on any unexpected failure instead of letting it escape.
        try {
            // 2026-09-23 hardening (defense-in-depth, see clientOwnsPhone()'s
            // docblock): the templated path addresses the addon's own
            // NotificationSender by $clientId ALONE — it never actually
            // looks at $phoneNumber. If $clientId does not really own
            // $phoneNumber (a stale/second resolution, a client record
            // edited between resolution and send, or any future caller
            // that resolves $clientId less carefully than today's
            // WhatsAppTwoFactorService::resolveClientIdForUser() does),
            // the templated path would silently deliver this code to
            // WHOEVER'S phone number is actually on that client id's
            // record — never $phoneNumber. Gated here so the templated
            // path is only ever used when it is PROVEN to already be
            // addressing the same destination $phoneNumber is — otherwise
            // it falls straight through to sendPlainMessage($phoneNumber),
            // which always sends to the correct, already-verified number.
            if ($userType === "client" && $clientId !== null && $clientId > 0 && self::clientOwnsPhone($clientId, $phoneNumber)) {
                if (self::sendViaTemplatedNotification($clientId, $code, $validMinutes)) {
                    return true;
                }
                // Falls through to the plain-message path below — a missing/
                // broken template must never block a login.
            }

            return self::sendPlainMessage($phoneNumber, $code, $validMinutes);
        } catch (\Throwable $e) {
            if (function_exists("lkn_hn_log")) {
                lkn_hn_log("DCTLAB Security Pack 2FA: sendCode() unexpected error", [], ["exception" => $e->__toString()]);
            }
            if (function_exists("security_pack_record_event")) {
                security_pack_record_event(
                    "2fa.whatsapp.dctlab_send_unexpected_error",
                    "An unexpected error occurred while sending a WhatsApp 2FA code through the DCTLAB WhatsApp Notifications addon — the OTP send failed, but authentication was not blocked. Check the dct_whatsapp_notifications addon's own Notifications configuration (the \"TwoFactorAuthentication\" notification may be enabled with no delivery platform assigned).",
                    ["user_type" => $userType, "exception" => get_class($e)],
                    "warning"
                );
            }
            return false;
        }
    }

    /**
     * Defense-in-depth safety gate for the templated send path (see the
     * 2026-09-23 note in sendCode()) — confirms $clientId's OWN stored
     * `tblclients.phonenumber` is actually the SAME number this OTP is
     * FOR ($phoneNumber, already independently resolved/verified by the
     * caller) before letting sendCode() hand the addon's
     * NotificationSender a bare $clientId to address by itself.
     *
     * Companion, not a replacement, for
     * WhatsAppTwoFactorService::pickUnambiguousClientId() — that fix
     * stops $clientId from being resolved wrong in the first place; this
     * one stops a wrong (or now-stale) $clientId from ever being trusted
     * to pick its own delivery address downstream, in this file, the one
     * place that actually turns a client id into a live WhatsApp send.
     * Uses OtpEngine::normalizePhoneForComparison() so differing
     * formatting of the same real number (+91 vs a leading 0 vs no
     * prefix) still matches — a normalization MISmatch is treated as
     * "not proven safe" (fails to the plain-message path), same
     * fail-soft posture as every other lookup in this class.
     */
    private static function clientOwnsPhone(int $clientId, string $phoneNumber): bool
    {
        try {
            $storedPhone = (string) (\Illuminate\Database\Capsule\Manager::table("tblclients")->where("id", $clientId)->value("phonenumber") ?? "");
            if ($storedPhone === "") {
                return false;
            }
            return OtpEngine::normalizePhoneForComparison($storedPhone) !== ""
                && OtpEngine::normalizePhoneForComparison($storedPhone) === OtpEngine::normalizePhoneForComparison($phoneNumber);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Mirrors dct2fa_send_code()'s client-only branch: resolve the
     * "TwoFactorAuthentication" notification and dispatch it through the
     * addon's own NotificationSender (client name/opt-out/delivery
     * reporting all apply, same as any other notification in that addon).
     */
    private static function sendViaTemplatedNotification(int $clientId, string $code, int $validMinutes): bool
    {
        try {
            $notification = \Dct\HookNotification\Core\Notification\Application\NotificationFactory::getInstance()
                ->makeByCode("TwoFactorAuthentication");

            if ($notification === null) {
                if (function_exists("lkn_hn_log")) {
                    lkn_hn_log("DCTLAB Security Pack 2FA: TwoFactorAuthentication notification not found/enabled", [], []);
                }
                return false;
            }

            $result = \Dct\HookNotification\Core\Notification\Application\Services\NotificationSender::getInstance()->send(
                $notification,
                [
                    "client_id" => $clientId,
                    "verification_code" => $code,
                    "code_valid_minutes" => $validMinutes,
                ]
            );

            return $result instanceof \Dct\HookNotification\Core\Platforms\Common\PlatformNotificationSendResult
                && $result->status === \Dct\HookNotification\Core\NotificationReport\Domain\NotificationReportStatus::SENT;
        } catch (\Throwable $e) {
            if (function_exists("lkn_hn_log")) {
                lkn_hn_log("DCTLAB Security Pack 2FA: template-based send error", [], ["exception" => $e->__toString()]);
            }
            return false;
        }
    }

    /**
     * Mirrors dct2fa_send_plain_message(): a plain, non-customizable
     * message sent directly via whichever platform(s) Settings::
     * WA2FA_PLATFORM selects — always used for admin logins, and as the
     * fallback for clients.
     */
    private static function sendPlainMessage(string $phoneNumber, string $code, int $validMinutes): bool
    {
        $message = "Your verification code is: {$code}\n\nThis code expires in {$validMinutes} minute(s). Do not share it with anyone.";

        $configuredPlatform = function_exists("lkn_hn_config")
            ? (self::configValue("WA2FA_PLATFORM") ?: "auto")
            : "auto";

        $order = self::platformAttemptOrder($configuredPlatform);

        foreach ($order as $platform) {
            try {
                if ($platform === "meta" && self::sendViaMeta($phoneNumber, $code)) {
                    return true;
                }
                if ($platform === "botms" && self::sendViaBotms($phoneNumber, $message)) {
                    return true;
                }
                if ($platform === "baileys" && self::sendViaBaileys($phoneNumber, $message)) {
                    return true;
                }
            } catch (\Throwable $e) {
                if (function_exists("lkn_hn_log")) {
                    lkn_hn_log("DCTLAB Security Pack 2FA: {$platform} send error", [], ["exception" => $e->__toString()]);
                }
            }
        }

        if (function_exists("lkn_hn_log")) {
            lkn_hn_log("DCTLAB Security Pack 2FA: no platform available to send code", ["phoneNumber" => $phoneNumber, "configuredPlatform" => $configuredPlatform], []);
        }

        return false;
    }

    /**
     * Pure — no addon/WHMCS dependency, unit-testable directly. Given the
     * addon's `WA2FA_PLATFORM` setting value, returns the ordered list of
     * platforms to attempt. "auto" (or anything unrecognized) tries all
     * three in the same Meta -> Botms -> Baileys order the reference
     * module uses; a specific choice tries only that one platform.
     *
     * @return string[]
     */
    public static function platformAttemptOrder(string $configuredPlatform): array
    {
        $known = ["meta", "botms", "baileys"];
        if (in_array($configuredPlatform, $known, true)) {
            return [$configuredPlatform];
        }
        return $known;
    }

    /**
     * Pure — no addon/WHMCS dependency, unit-testable directly. The addon
     * stores the selected Meta "Authentication" template as
     * "name|language" (see lkn_hn_fetch_meta_authentication_templates());
     * tolerates a bare name (no "|") for settings saved before that
     * encoding existed, same as dct2fa_send_via_meta().
     *
     * @return array{0: string, 1: ?string} [templateName, languageCode]
     */
    public static function parseStoredTemplateValue(string $storedValue): array
    {
        $parts = explode("|", $storedValue, 2);
        return [$parts[0], $parts[1] ?? null];
    }

    private static function sendViaMeta(string $phoneNumber, string $code): bool
    {
        if (!self::configValue("WP_META_ENABLE")) {
            return false;
        }
        $templateValue = (string) (self::configValue("WP_2FA_TEMPLATE_NAME") ?? "");
        if ($templateValue === "") {
            return false;
        }

        [$templateName, $langCode] = self::parseStoredTemplateValue($templateValue);

        $settings = \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformSettingsFactory::makeMetaWhatsAppSettings();
        $client = (new \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformApiClientFactory())->makeMetaWhatsAppClient($settings);

        $components = [
            ["type" => "body", "parameters" => [["type" => "text", "text" => $code]]],
        ];

        $buttonType = self::configValue("WP_2FA_TEMPLATE_HAS_BUTTON");
        if ($buttonType === "copy_code") {
            $components[] = [
                "type" => "button", "sub_type" => "copy_code", "index" => "0",
                "parameters" => [["type" => "coupon_code", "coupon_code" => $code]],
            ];
        } elseif ($buttonType === "url") {
            $components[] = [
                "type" => "button", "sub_type" => "url", "index" => "0",
                "parameters" => [["type" => "text", "text" => $code]],
            ];
        }

        $langCode = $langCode ?: ($settings->defaultMsgTemplateLang ?: "en_US");

        $response = $client->sendMessageTemplate($phoneNumber, $templateName, $components, $langCode);

        return isset($response->httpStatusCode) && $response->httpStatusCode >= 200 && $response->httpStatusCode < 300;
    }

    private static function sendViaBotms(string $phoneNumber, string $message): bool
    {
        if (!self::configValue("BOTMS_ENABLE")) {
            return false;
        }
        $settings = \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformSettingsFactory::makeBotmsSettings([]);
        $client = (new \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformApiClientFactory())->makeBotmsClient($settings);

        if (!$client->areSettingsFilled()) {
            return false;
        }

        $response = $client->sendTextMessage($phoneNumber, $message);
        return $response->httpStatusCode >= 200 && $response->httpStatusCode < 300;
    }

    private static function sendViaBaileys(string $phoneNumber, string $message): bool
    {
        if (!self::configValue("BAILEYS_ENABLE")) {
            return false;
        }
        $settings = \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformSettingsFactory::makeBaileysSettings([]);
        $client = (new \Dct\HookNotification\Core\Platforms\Common\Infrastructure\PlatformApiClientFactory())->makeBaileysClient($settings);

        $response = $client->sendTextMessage($phoneNumber, $message);
        return isset($response->httpStatusCode) && $response->httpStatusCode >= 200 && $response->httpStatusCode < 300;
    }

    /** Thin wrapper around the addon's own `lkn_hn_config(Settings::X)` helper. */
    private static function configValue(string $settingCaseName)
    {
        if (!function_exists("lkn_hn_config") || !enum_exists(\Dct\HookNotification\Core\Shared\Infrastructure\Config\Settings::class)) {
            return null;
        }
        $case = constant(\Dct\HookNotification\Core\Shared\Infrastructure\Config\Settings::class . "::" . $settingCaseName);
        return lkn_hn_config($case);
    }
}
