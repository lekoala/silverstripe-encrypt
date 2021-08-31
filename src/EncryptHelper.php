<?php

namespace LeKoala\Encrypt;

use Exception;
use InvalidArgumentException;
use SilverStripe\Assets\File;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\Core\ClassInfo;
use SilverStripe\ORM\DataObject;
use SilverStripe\Core\Environment;
use ParagonIE\CipherSweet\CipherSweet;
use SilverStripe\ORM\FieldType\DBText;
use SilverStripe\ORM\FieldType\DBVarchar;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\FieldType\DBHTMLText;
use SilverStripe\ORM\FieldType\DBComposite;
use ParagonIE\CipherSweet\Backend\FIPSCrypto;
use ParagonIE\CipherSweet\Backend\BoringCrypto;
use ParagonIE\CipherSweet\Backend\ModernCrypto;
use ParagonIE\CipherSweet\Contract\BackendInterface;
use ParagonIE\CipherSweet\Planner\FieldIndexPlanner;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use SilverStripe\Control\Director;

/**
 * @link https://ciphersweet.paragonie.com/php
 * @link https://paragonie.com/blog/2017/05/building-searchable-encrypted-databases-with-php-and-sql
 * @link https://paragonie.com/book/pecl-libsodium/read/09-recipes.md
 */
class EncryptHelper
{
    use Configurable;

    const DEFAULT_OUTPUT_SIZE = 15;
    const DEFAULT_DOMAIN_SIZE = 127;
    const BORING = "brng";
    const MODERN = "nacl";
    const FIPS = "fips";

    /**
     * @config
     * @var string
     */
    private static $forced_encryption = null;

    /**
     * @config
     * @var bool
     */
    private static $automatic_rotation = true;

    /**
     * @var boolean
     */
    private static $automatic_decryption = true;

    /**
     * @var string
     */
    private static $aad_source = "ID";

    /**
     * @var CipherSweet
     */
    protected static $ciphersweet;

    /**
     * @var array
     */
    protected static $field_cache = [];

    /**
     * @return string
     */
    public static function getForcedEncryption()
    {
        return self::config()->forced_encryption;
    }

    /**
     * @param string $forcedEncryption brng|nacl|fips
     * @return void
     */
    public static function setForcedEncryption($forcedEncryption)
    {
        if ($forcedEncryption && !in_array($forcedEncryption, ["brng", "nacl", "fips"])) {
            throw new InvalidArgumentException("$forcedEncryption is not supported");
        }
        self::config()->forced_encryption = $forcedEncryption;
    }

    /**
     * This would only work if you changed from algorithm
     * @return bool
     */
    public static function getAutomaticRotation()
    {
        return self::config()->automatic_rotation;
    }

    /**
     * @param bool $setAutomaticRotation
     * @return void
     */
    public static function setAutomaticRotation($automaticRotation)
    {
        self::config()->automatic_rotation = $automaticRotation;
    }

    /**
     * @return bool
     */
    public static function getAutomaticDecryption()
    {
        return self::config()->automatic_decryption;
    }

    /**
     * @param bool $automaticDecryption
     * @return void
     */
    public static function setAutomaticDecryption($automaticDecryption)
    {
        self::config()->automatic_decryption = $automaticDecryption;
    }

    /**
     * @return string
     */
    public static function getAadSource()
    {
        return self::config()->aad_source;
    }

    /**
     * @param bool $aadSource
     * @return void
     */
    public static function setAadSource($aadSource)
    {
        self::config()->aad_source = $aadSource;
    }

    /**
     * @link https://ciphersweet.paragonie.com/php/blind-index-planning
     * @return array
     */
    public static function planIndexSizes()
    {
        $dataObjects = ClassInfo::subclassesFor(DataObject::class);
        $indexes = [];
        foreach ($dataObjects as $dataObject) {
            if (!class_uses(HasEncryptedFields::class)) {
                continue;
            }
            $index[$dataObject] = self::planIndexSizesForClass($dataObject);
        }
        return $indexes;
    }

    /**
     * @param string $dataObject
     * @return array
     */
    public static function planIndexSizesForClass($class)
    {
        $sng = singleton($class);
        $encryptedFields = self::getEncryptedFields($class);
        // By default, plan for a large number of rows
        $estimatedPopulation = $class::config()->estimated_population ?? PHP_INT_MAX;
        $planner = new FieldIndexPlanner();
        $planner->setEstimatedPopulation($estimatedPopulation);
        $indexes = [];
        foreach ($encryptedFields as $encryptedField => $encryptedClass) {
            if (!is_subclass_of($encryptedClass, DBComposite::class)) {
                continue;
            }
            $dbObject = $sng->dbObject($encryptedField);
            $outputSize = $dbObject->getOutputSize() ?? self::DEFAULT_OUTPUT_SIZE;
            $domainSize = $dbObject->getDomainSize() ?? self::DEFAULT_DOMAIN_SIZE;
            $planner->addExistingIndex($encryptedField . "BlindIndex", $outputSize, $domainSize);
            // The smaller of the two values will be used to compute coincidences
            $indexes[] = ["L" => $outputSize, "K" => $domainSize];
        }
        $coincidenceCount = round(self::coincidenceCount($indexes, $estimatedPopulation));
        $recommended = $planner->recommend();
        $recommended['indexes'] = count($indexes);
        // If there is no coincidence, it means the index is not safe for use because it means
        // that two identical plaintexts will give the same output
        $recommended['coincidence_count'] = $coincidenceCount;
        $recommended['coincidence_ratio'] = $coincidenceCount / $estimatedPopulation * 100;
        $recommended['estimated_population'] = $estimatedPopulation;
        return $recommended;
    }

    /**
     * @link https://github.com/paragonie/ciphersweet/issues/62
     * @param array $ciphertext
     * @return array
     */
    public static function removeNulls($ciphertext)
    {
        foreach ($ciphertext as $k => $v) {
            if ($v === null) {
                $ciphertext[$k] = '';
            }
        }
        return $ciphertext;
    }

    /**
     * Attempting to pass a key of an invalid size (i.e. not 256-bit) will result in a CryptoOperationException being thrown.
     * The recommended way to generate a key is to use this method
     *
     * @return string A 64 chars string like 4e1c44f87b4cdf21808762970b356891db180a9dd9850e7baf2a79ff3ab8a2fc
     */
    public static function generateKey()
    {
        return Hex::encode(random_bytes(32));
    }

    /**
     * @return array Two 64 chars strings
     */
    public static function generateKeyPair()
    {
        $key_pair = sodium_crypto_box_keypair();
        $public_key = sodium_crypto_box_publickey($key_pair);
        $private_key = sodium_crypto_box_secretkey($key_pair);

        return [
            'public_key' => Hex::encode($public_key),
            'private_key' => Hex::encode($private_key),
        ];
    }

    /**
     * Get app encryption key
     * Encryption key should be provided in your $_ENV or .env file
     *
     * @return string
     */
    public static function getKey()
    {
        // Try our path variable
        $keyPath = Environment::getEnv('ENCRYPTION_KEY_PATH');
        $key = null;
        if ($keyPath) {
            $key = file_get_contents($keyPath);
            if (!$key || !is_string($key)) {
                throw new Exception("Could not read key from $keyPath");
            }
        }
        // Try regular env key
        if (!$key) {
            $key = Environment::getEnv('ENCRYPTION_KEY');
        }
        if (!$key) {
            $key = self::generateKey();
            if (Director::isDev()) {
                $envFile = rtrim(Director::baseFolder(), '/') . "/.env";
                if (is_file($envFile) && is_writable($envFile)) {
                    file_put_contents($envFile, 'ENCRYPTION_KEY="' . $key . '"', FILE_APPEND);
                    return $key;
                }
            }
            throw new Exception("Please define an ENCRYPTION_KEY in your environment. You can use this one: $key");
        }
        return $key;
    }

    /**
     * @return string
     */
    public static function getOldKey()
    {
        return Environment::getEnv('OLD_ENCRYPTION_KEY');
    }

    /**
     * @param string $key
     * @return StringProvider
     */
    public static function getProviderWithKey($key = null)
    {
        if ($key === null) {
            $key = self::getKey();
        }
        return new StringProvider($key);
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
     * @param BackendInterface $backend
     * @param string $key
     * @return CipherSweet
     */
    public static function getEngineForEncryption($encryption = null, $key = null)
    {
        return self::getEngine(self::getBackendForEncryption($encryption), $key);
    }

    /**
     * @param BackendInterface $backend
     * @param string $key
     * @return CipherSweet
     */
    public static function getEngine(BackendInterface $backend, $key = null)
    {
        $provider = self::getProviderWithKey($key);
        return new CipherSweet($provider, $backend);
    }

    /**
     * @param BackendInterface $backend
     * @param KeyProviderInterface $provider
     * @return CipherSweet
     */
    public static function getEngineWithProvider(BackendInterface $backend, KeyProviderInterface $provider)
    {
        return new CipherSweet($provider, $backend);
    }

    /**
     * @param KeyProviderInterface $provider
     * @return CipherSweet
     */
    public static function getCipherSweet($provider = null)
    {
        if (self::$ciphersweet) {
            return self::$ciphersweet;
        }
        if ($provider === null) {
            $provider = self::getProviderWithKey();
        }
        if (self::getForcedEncryption()) {
            $backend = self::getBackendForEncryption(self::getForcedEncryption());
        } else {
            $backend = self::getRecommendedBackend();
        }
        self::$ciphersweet = new CipherSweet($provider, $backend);
        return self::$ciphersweet;
    }

    /**
     * @return void
     */
    public static function clearCipherSweet()
    {
        self::$ciphersweet = null;
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
     * Filters parameters from database class config
     * @return string
     */
    protected static function filterDbClass($dbClass)
    {
        $pos = strpos($dbClass, '(');
        if ($pos !== false) {
            $dbClass = substr($dbClass, 0, $pos);
        }
        return $dbClass;
    }

    /**
     * @param string $class
     * @param bool $dbFields Return actual database field value instead of field name
     * @return array An associative array with the name of the field as key and the class as value
     */
    public static function getEncryptedFields($class, $dbFields = false)
    {
        $fields = $class::config()->db;
        $list = [];
        foreach ($fields as $field => $dbClass) {
            $dbClass = self::filterDbClass($dbClass);
            $key = $class . '_' . $field;
            if (isset($fields[$field])) {
                self::$field_cache[$key] = strpos($dbClass, 'Encrypted') !== false;
                if (self::$field_cache[$key]) {
                    // Sometimes we need actual db field name
                    if ($dbFields && is_subclass_of($dbClass, DBComposite::class)) {
                        $list[$field . "Value"] = $dbClass;
                    } else {
                        $list[$field] = $dbClass;
                    }
                }
            } else {
                self::$field_cache[$key] = false;
            }
        }
        return $list;
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
     * @link https://ciphersweet.paragonie.com/php/blind-index-planning
     * @link https://ciphersweet.paragonie.com/security
     * @param array $indexes an array of L (output size) / K (domaine size) pairs
     * @param int $R the number of encrypted records that use this blind index
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
     * Alias of sendDecryptedFile
     * @deprecated
     * @param File $file
     * @return void
     */
    public static function sendEncryptedFile(File $file)
    {
        self::sendDecryptedFile($file);
    }

    /**
     * Send a decrypted file
     *
     * @param File $file
     * @return void
     */
    public static function sendDecryptedFile(File $file)
    {
        header('Content-disposition: attachment; filename="' . basename($file->getFilename()) . '"');
        header('Content-type: application/octetstream');
        header('Pragma: no-cache');
        header('Expires: 0');
        $file->sendDecryptedFile();
    }
}
