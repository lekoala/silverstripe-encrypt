<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\Core\Environment;
use ParagonIE\CipherSweet\CipherSweet;
use SilverStripe\ORM\FieldType\DBText;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\ORM\FieldType\DBHTMLText;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;

/**
 * @link https://ciphersweet.paragonie.com/php
 * @link https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql
 * @link https://paragonie.com/book/pecl-libsodium/read/09-recipes.md
 */
class EncryptHelper
{
    const BORING = "brng";
    const MODERN = "nacl";
    const FIPS = "fips";

    /**
     * @var CipherSweet
     */
    protected static $ciphersweet;

    /**
     * @var array
     */
    protected static $field_cache = [];

    /**
     * @var string
     */
    protected static $forcedEncryption = null;

    /**
     * @param string $forcedEncryption brng|nacl|fips
     * @return void
     */
    public static function setForcedEncryption($forcedEncryption)
    {
        self::$forcedEncryption = $forcedEncryption;
    }

    /**
     * Attempting to pass a key of an invalid size (i.e. not 256-bit) will result in a CryptoOperationException being thrown.
     * The recommended way to generate a key is to use this method
     *
     * @return string Something like 4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc
     */
    public static function generateKey()
    {
        return Hex::encode(random_bytes(32));
    }

    /**
     * Get app encryption key
     * Encryption key should be provided in your $_ENV or .env file
     *
     * @return string
     */
    public static function getKey()
    {
        $key = Environment::getEnv('ENCRYPTION_KEY');
        if (!$key) {
            $key = self::generateKey();
            throw new Exception("Please define an ENCRYPTION_KEY in your environment. You can use this one: $key");
        }
        return $key;
    }

    /**
     * @return StringProvider
     */
    public static function getProviderWithKey()
    {
        return new StringProvider(
            self::getKey()
        );
    }

    /**
     * @return BackendInterface
     */
    public static function getRecommendedBackend()
    {
        if (version_compare(phpversion(), '7.2', '<')) {
            return new FIPSCrypto();
        }
        return new BoringCrypto();
    }

    /**
     * @param string $encryption
     * @return BackendInterface
     */
    public static function getBackendForEncryption($encryption = null)
    {
        if (!$encryption) {
            return self::getRecommendedBackend();
        }
        switch ($encryption) {
            case self::BORING:
                return new BoringCrypto();
            case self::MODERN:
                return new ModernCrypto();
            case self::FIPS:
                return new FIPSCrypto();
        }
        throw new Exception("Unsupported encryption $encryption");
    }


    /**
     * @return CipherSweet
     */
    public static function getCipherSweet()
    {
        if (self::$ciphersweet) {
            return self::$ciphersweet;
        }
        $provider = self::getProviderWithKey();
        if (self::$forcedEncryption) {
            $backend = self::getBackendForEncryption(self::$forcedEncryption);
        } else {
            $backend = self::getRecommendedBackend();
        }
        self::$ciphersweet = new CipherSweet($provider, $backend);
        return self::$ciphersweet;
    }

    /**
     * @return BackendInterface
     */
    public static function getCipherSweetBackend()
    {
        return self::getCipherSweet()->getBackend();
    }

    /**
     * Check if a value is encrypted
     *
     * @param string $value
     * @return boolean
     */
    public static function isEncrypted($value)
    {
        $prefix = substr($value, 0, 5);
        return in_array($prefix, ["brng:", "nacl:", "fips:"]);
    }

    /**
     * @param string $value
     * @return boolean
     */
    public static function isFips($value)
    {
        if (strpos($value, 'fips:') === 0) {
            return true;
        }
        return false;
    }

    /**
     * @param string $value
     * @return boolean
     */
    public static function isNacl($value)
    {
        if (strpos($value, 'nacl:') === 0) {
            return true;
        }
        return false;
    }

    /**
     * @param string $value
     * @return boolean
     */
    public static function isBoring($value)
    {
        if (strpos($value, 'brng:') === 0) {
            return true;
        }
        return false;
    }

    /**
     * @param string $value
     * @return string
     */
    public static function getEncryption($value)
    {
        if (self::isBoring($value)) {
            return self::BORING;
        }
        if (self::isNacl($value)) {
            return self::MODERN;
        }
        if (self::isFips($value)) {
            return self::FIPS;
        }
        return false;
    }

    /**
     * Check if a field is encrypted on a class
     * This relies on a field class starting with Encrypted
     *
     * @param string $class
     * @param string $field
     * @return boolean
     */
    public static function isEncryptedField($class, $field)
    {
        $key = $class . '_' . $field;
        if (isset(self::$field_cache[$key])) {
            return self::$field_cache[$key];
        }

        $fields = $class::config()->db;

        if (isset($fields[$field])) {
            $dbClass = $fields[$field];
            self::$field_cache[$key] = strpos($dbClass, 'Encrypted') !== false;
        } else {
            self::$field_cache[$key] = false;
        }
        return self::$field_cache[$key];
    }

    /**
     * A simple encryption
     * @param string $value
     * @return string
     */
    public static function encrypt($value)
    {
        // Do not encrypt twice
        $encryption = self::getEncryption($value);
        if ($encryption) {
            return $value;
        }
        $provider = self::getProviderWithKey();
        $backend = self::getBackendForEncryption($encryption);
        return $backend->encrypt($value, $provider->getSymmetricKey());
    }

    /**
     * A simple decryption
     * @param string $value
     * @return string
     */
    public static function decrypt($value)
    {
        // Only decrypt what we can decrypt
        $encryption = self::getEncryption($value);
        if (!$encryption) {
            return $value;
        }
        $provider = self::getProviderWithKey();
        $backend =  self::getBackendForEncryption($encryption);
        return $backend->decrypt($value, $provider->getSymmetricKey());
    }

    /**
     * Return a map of fields with their encrypted counterpart
     *
     * @return array
     */
    public static function mapEncryptionDBField()
    {
        return [
            DBHTMLText::class => EncryptedDBHTMLText::class,
            DBText::class => EncryptedDBText::class,
            DBVarchar::class => EncryptedDBVarchar::class,
        ];
    }

    /**
     * Compute Blind Index Information Leaks
     *
     * @link https://ciphersweet.paragonie.com/security
     * @param array $indexes
     * @param int $R
     * @return float
     */
    public static function coincidenceCount(array $indexes, $R)
    {
        $exponent = 0;
        $count = count($indexes);
        for ($i = 0; $i < $count; ++$i) {
            $exponent += min($indexes[$i]['L'], $indexes[$i]['K']);
        }
        return (float) max(1, $R) / pow(2, $exponent);
    }

    /**
     * Send a decrypted file
     *
     * @param File $file
     * @return void
     */
    public static function sendEncryptedFile(File $file)
    {
        header('Content-disposition: attachment; filename="' . basename($file->getFilename()) . '"');
        header('Content-type: application/octetstream');
        header('Pragma: no-cache');
        header('Expires: 0');
        $file->sendDecryptedFile();
    }
}
