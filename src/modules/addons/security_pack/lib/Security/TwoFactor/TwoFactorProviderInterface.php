<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — the ONE provider abstraction shared by all three
 * 2FA methods (Section 6). Deliberately thin: it only covers the
 * cross-cutting status/enrollment questions TwoFactorAuthenticationService
 * needs to orchestrate (Section 5 — "the [orchestration] service must
 * NOT contain provider-specific implementation details"). The actual
 * OTP/TOTP challenge-and-verify logic for each method stays entirely
 * inside that method's own service (Email2faService,
 * WhatsAppTwoFactorService, TotpService) and its own WHMCS Security
 * Module — this interface is not a re-implementation of that logic.
 */
interface TwoFactorProviderInterface
{
    /** Stable machine key: "email" | "whatsapp" | "totp". */
    public function methodKey(): string;

    /** Human label for UI/status display. */
    public function label(): string;

    /** Does this provider have what it needs to function (e.g. WhatsApp API credentials configured)? */
    public function isConfigured(array $settings): bool;

    /** Is this method actively enrolled+active for this user? */
    public function isActive(int $userId, string $userType): bool;

    /** Is this method enrolled but still pending verification? */
    public function isPending(int $userId, string $userType): bool;

    /** Disable/remove this method's enrollment for this user (admin/self-service reset). */
    public function disable(int $userId, string $userType, string $actor): void;
}
