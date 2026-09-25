<?php

declare(strict_types=1);

namespace WHMCS\Module\Addon\Security_Pack\Security\TwoFactor;

if(!defined("WHMCS")) {
    exit("This file cannot be accessed directly");
}

/**
 * Security Pack 3.0 — server-side master key for TOTP secret-at-rest
 * encryption (Section 14).
 *
 * Requirements from the spec: use a server-side key, never expose it to
 * clients, never hard-code it in the repository, document key
 * management. This class generates a random 32-byte libsodium secretbox
 * key on first use and stores it in `core/data/` — the SAME directory
 * already protected by a "Require all denied" .htaccess for the MaxMind
 * database file (confirmed present since the GeoIP work), so no new
 * exposure surface is introduced. The key file itself is never
 * web-accessible, never logged, and is generated with random_bytes(),
 * not derived from anything guessable.
 *
 * Operational note for administrators: this file
 * (`core/data/totp_master.key`) IS the encryption key for every
 * enrolled TOTP secret. Back it up along with the database. If it is
 * lost, previously-encrypted TOTP secrets cannot be decrypted and every
 * enrolled user must re-enroll TOTP (their recovery codes or another
 * enrolled method remain unaffected).
 */
class TotpKeyStore
{
    public static function keyPath(): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . ".."
            . DIRECTORY_SEPARATOR . "core" . DIRECTORY_SEPARATOR . "data" . DIRECTORY_SEPARATOR . "totp_master.key";
    }

    /** Load the master key, generating and persisting a new one on first use. Returns null if it cannot be read/written. */
    public static function getKey(): ?string
    {
        if(!function_exists("sodium_crypto_secretbox_keygen")) {
            return null;
        }
        $path = self::keyPath();
        if(is_readable($path)) {
            $key = file_get_contents($path);
            if($key !== false && strlen($key) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                return $key;
            }
        }
        $dir = dirname($path);
        if(!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $key = sodium_crypto_secretbox_keygen();
        $written = @file_put_contents($path, $key);
        if($written === false) {
            return null;
        }
        @chmod($path, 0640);
        return $key;
    }
}
