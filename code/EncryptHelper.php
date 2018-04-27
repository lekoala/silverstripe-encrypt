<?php
namespace LeKoala\SilverStripeEncrypt;

use SilverStripe\Core\Config\Config;
use Tuupola\Base62Proxy;
use SilverStripe\Control\Director;

/**
 * @link https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql
 * @link https://paragonie.com/book/pecl-libsodium/read/09-recipes.md
 */
class EncryptHelper
{

    /**
     * Get app encryption key
     *
     * @return string
     */
    public static function getKey()
    {
        // A base62 decoded key
        if (defined('ENCRYPT_SHARED_KEY')) {
            return ENCRYPT_SHARED_KEY;
        }

        // Generate the key for this server
        $relativePath = Config::inst()->get('LeKoala\SilverStripeEncrypt\EncryptHelper', 'secret_key_path');
        $keyPath = Director::baseFolder() . '/' . $relativePath;

        if (is_file($keyPath)) {
            $raw = file_get_contents($keyPath);
            $key = Base62Proxy::decode($raw);
        } else {
            $key = random_bytes(\Sodium\CRYPTO_AUTH_KEYBYTES);
            file_put_contents($keyPath, Base62Proxy::encode($key));
        }

        return $key;
    }

    /**
     * Encrypt a value with sodium_crypto_secretbox using app key and random nonce
     *
     * @param string $value
     * @return array An array containing : nonce, encrypted_value, value, binary_value
     */
    public static function encryptValue($value)
    {
        // A single key is used both to encrypt/sign and verify/decrypt messages.
        // For this reason, it is critical to keep the key confidential.
        // ? we could improve this by using a unique key for each record
        $key = self::getKey();

        // The nonce doesn't have to be confidential,
        // but it should never ever be reused with the same key. The easiest way to generate a nonce is to use random_bytes().
        $nonce = random_bytes(24);
        $encryptedValue = sodium_crypto_secretbox($value, $nonce, $key);

        $result = [
            'nonce' => $nonce,
            'encrypted_value' => $encryptedValue,
            'value' => $value,
            'binary_value' => bin2hex($nonce . $encryptedValue), // Easy to store in a field
        ];
        return $result;
    }

    /**
     * Decrypt a value (a result of binary_value as returned by encryptValue)
     *
     * @param string $value
     * @return string
     */
    public static function decryptBinaryValue($value)
    {
        $key = self::getKey();
        $decoded = hex2bin($value);
        $nonce = mb_substr($decoded, 0, 24, '8bit');
        $cipher = mb_substr($decoded, 24, null, '8bit');
        $decodedValue = sodium_crypto_secretbox_open($cipher, $nonce, $key);

        return $decodedValue;
    }

    /**
     * Get a searchable index
     *
     * @param string $value
     * @param string $indexValue
     * @return string
     */
    public static function getBlindIndex($value, $indexValue)
    {
        function getSSNBlindIndex(string $ssn, string $indexKey) : string
        {
            return bin2hex(
                sodium_crypto_pwhash(
                    32,
                    $value,
                    $indexValue,
                    \Sodium\SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                    \Sodium\SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
                )
            );
        }
    }

    public static function isHexadecimal($value)
    {
        return ctype_xdigit($value);
    }
}
