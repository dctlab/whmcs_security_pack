<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

use RobThree\Auth\Providers\Qr\IQRCodeProvider;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * RobThree\Auth\TwoFactorAuth's constructor requires an IQRCodeProvider,
 * but Security Pack never calls its getQRCodeImageAsDataUri() — the
 * actual scannable QR image is rendered by Security Pack's OWN
 * TotpQrGenerator (a from-scratch, dependency-free local SVG encoder,
 * embedded inline rather than as a data-uri <img>), specifically so
 * that no external HTTP-based provider (QRServerProvider,
 * ImageChartsQRCodeProvider, QRicketProvider — every one of which sends
 * the otpauth:// URI, including the secret, to a third party) can ever
 * be reached from this code path, and so that neither of RobThree's own
 * optional local-rendering providers (BaconQrCodeProvider,
 * EndroidQrCodeProvider) needs to be vendored as an extra dependency.
 *
 * This class exists purely to satisfy the constructor's type
 * requirement. If it is ever actually invoked, that itself is a sign
 * something is wrong (a code path calling getQRCodeImageAsDataUri()
 * that shouldn't exist), so it fails loudly rather than silently
 * returning a blank image.
 */
class NullQrCodeProvider implements IQRCodeProvider
{
    public function getQRCodeImage(string $qrText, int $size): string
    {
        throw new \RuntimeException("NullQrCodeProvider::getQRCodeImage() should never be called — DCTLAB Security Pack renders QR codes via its own local TotpQrGenerator, never via RobThree\\Auth\\TwoFactorAuth::getQRCodeImageAsDataUri().");
    }

    public function getMimeType(): string
    {
        return "image/svg+xml";
    }
}
