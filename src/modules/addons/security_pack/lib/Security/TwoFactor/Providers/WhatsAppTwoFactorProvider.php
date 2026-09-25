<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorProviderInterface;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\WhatsAppTwoFactorService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers\DctWhatsAppNotificationsBridge;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

class WhatsAppTwoFactorProvider implements TwoFactorProviderInterface
{
    public function methodKey(): string
    {
        return "whatsapp";
    }

    public function label(): string
    {
        return "DCTLAB WhatsApp";
    }

    /**
     * As of 3.1, "configured" means the real DCTLAB WhatsApp integration
     * (the "dct_whatsapp_notifications" addon) is actually installed and
     * loadable — there is no longer a base-URL/API-key pair owned by this
     * module itself to check (see DctWhatsAppNotificationsBridge).
     */
    public function isConfigured(array $settings): bool
    {
        return DctWhatsAppNotificationsBridge::isAvailable();
    }

    public function isActive(int $userId, string $userType): bool
    {
        return WhatsAppTwoFactorService::isActive($userId, $userType);
    }

    public function isPending(int $userId, string $userType): bool
    {
        $row = WhatsAppTwoFactorService::getConfig($userId, $userType);
        return $row !== null && $row->status === "pending";
    }

    public function disable(int $userId, string $userType, string $actor): void
    {
        WhatsAppTwoFactorService::disable($userId, $userType, $actor);
    }
}
