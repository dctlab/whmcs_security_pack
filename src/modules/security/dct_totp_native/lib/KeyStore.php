<?php

declare(strict_types=1);

namespace WHMCS\Module\Security\DctTotpNative;

if (!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * dct_totp_native — server-side master key for TOTP secret-at-rest
 * encryption.
 *
 * Every enrolled TOTP secret is encrypted before it is ever written to
 * the database (see Totp::encryptSecret()). This class owns that
 * encryption key's lifecycle: it generates a random 32-byte libsodium
 * secretbox key on first use and stores it in this module's own
 * `data/` directory, protected by an .htaccess `Require all denied`
 * (written alongside it on first use, defense-in-depth even though
 * `modules/security/*` is not normally web-routable). The key is never
 * exposed to clients, never logged, and never hard-coded in the
 * codebase.
 *
 * OPERATIONAL NOTE FOR ADMINISTRATORS: this file
 * (`modules/security/dct_totp_native/data/totp_master.key`) IS the
 * encryption key for every enrolled TOTP secret on this install. Back
 * it up along with the database. If it is lost, previously-encrypted
 * TOTP secrets cannot be decrypted and every enrolled user must
 * re-enroll (their recovery codes remain valid and can be used to sign
 * in while they do).
 */
class KeyStore
{
    public static function keyPath(): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "totp_master.key";
    }

    private static function htaccessPath(): string
    {
        return dirname(self::keyPath()) . DIRECTORY_SEPARATOR . ".htaccess";
    }

    /** Load the master key, generating and persisting a new one on first use. Returns null if it cannot be read/written. */
    public static function getKey(): ?string
    {
        if (!function_exists("sodium_crypto_secretbox_keygen")) {
            return null;
        }
        $path = self::keyPath();
        if (is_readable($path)) {
            $key = file_get_contents($path);
            if ($key !== false && strlen($key) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                return $key;
            }
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $htaccess = self::htaccessPath();
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n");
        }
        $key = sodium_crypto_secretbox_keygen();
        $written = @file_put_contents($path, $key);
        if ($written === false) {
            return null;
        }
        @chmod($path, 0640);
        return $key;
    }
}
