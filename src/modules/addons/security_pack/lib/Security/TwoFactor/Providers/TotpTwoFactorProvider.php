<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\Providers;

use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\NativeTotpStatusBridge;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TotpEnrollmentService;
use WHMCS\Module\Addon\Security_Pack\Security\TwoFactor\TwoFactorProviderInterface;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

class TotpTwoFactorProvider implements TwoFactorProviderInterface
{
    public function methodKey(): string
    {
        return "totp";
    }

    public function label(): string
    {
        return "Time-Based Token";
    }

    public function isConfigured(array $settings): bool
    {
        return function_exists("sodium_crypto_secretbox"); // TOTP always works once libsodium is present — no external service dependency
    }

    /**
     * 2026-08-27 — production bug fix: this used to read ONLY the legacy
     * dct_totp_2fa-backed table (TotpEnrollmentService). Investigation of
     * a live TOTP bug report found this install actually runs a separate,
     * standalone Security Module — modules/security/dct_totp_native, with
     * its own independent table — and that dct_totp_2fa has zero real
     * enrollments here. Every screen this provider feeds (admin Security
     * Overview counts, "Manage a User's Two-Factor Authentication",
     * mutual-exclusion, reporting) was therefore blind to every real TOTP
     * enrollment on this install.
     *
     * Fix: when a user has a row in dct_totp_native's own table (see
     * NativeTotpStatusBridge), that row is authoritative — it is the
     * live, currently-running TOTP module. Only when no such row exists
     * (this identity was never touched by dct_totp_native — e.g. a
     * different install still genuinely using dct_totp_2fa) does this
     * fall back to the legacy table, so nothing that already worked
     * against dct_totp_2fa regresses.
     */
    public function isActive(int $userId, string $userType): bool
    {
        $nativeRow = NativeTotpStatusBridge::getConfig($userId, $userType);
        if($nativeRow !== null) {
            return $nativeRow->status === "active";
        }
        return TotpEnrollmentService::isActive($userId, $userType);
    }

    public function isPending(int $userId, string $userType): bool
    {
        $nativeRow = NativeTotpStatusBridge::getConfig($userId, $userType);
        if($nativeRow !== null) {
            return $nativeRow->status === "pending";
        }
        $row = TotpEnrollmentService::getConfig($userId, $userType);
        return $row !== null && $row->status === "pending";
    }

    /**
     * Disables whichever table(s) actually have a row for this identity —
     * both, if somehow both exist — so an admin's "disable 2FA" action
     * never leaves either module's tracking looking active/pending.
     */
    public function disable(int $userId, string $userType, string $actor): void
    {
        if(NativeTotpStatusBridge::getConfig($userId, $userType) !== null) {
            NativeTotpStatusBridge::disable($userId, $userType, $actor);
        }
        if(TotpEnrollmentService::getConfig($userId, $userType) !== null) {
            TotpEnrollmentService::disable($userId, $userType, $actor);
        }
    }
}
