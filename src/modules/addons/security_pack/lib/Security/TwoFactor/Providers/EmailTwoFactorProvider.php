<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\Email2faService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorProviderInterface;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — thin adapter over the EXISTING, unmodified
 * Email2faService (Section 2: extend, do not duplicate). Contains no
 * OTP logic of its own.
 */
class EmailTwoFactorProvider implements TwoFactorProviderInterface
{
    public function methodKey(): string
    {
        return "email";
    }

    public function label(): string
    {
        return "Email Verification";
    }

    public function isConfigured(array $settings): bool
    {
        return true; // always available — uses WHMCS's own mail pipeline, no external credentials required
    }

    public function isActive(int $userId, string $userType): bool
    {
        return Email2faService::isActive($userId, $userType);
    }

    public function isPending(int $userId, string $userType): bool
    {
        $row = Email2faService::getConfig($userId, $userType);
        return $row !== null && $row->status === "pending";
    }

    public function disable(int $userId, string $userType, string $actor): void
    {
        Email2faService::disable($userId, $userType, $actor);
    }
}
