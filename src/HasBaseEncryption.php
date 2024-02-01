<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\ORM\DataObject;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

trait HasBaseEncryption
{
    /**
     * @var Exception
     */
    protected $encryptionException;

    /**
     * @var string
     */
    protected $encryptionAad = '';

    /**
     * @var string
     */
    protected $previousEncryptionAad = '';

    /**
     * @return Exception
     */
    public function getEncryptionException()
    {
        return $this->encryptionException;
    }

    /**
     * @param CipherSweet $engine
     * @return EncryptedField
     */
    public function getEncryptedField($engine = null)
    {
        if ($engine === null) {
            $engine = EncryptHelper::getCipherSweet();
        }
        $encryptedField = new EncryptedField($engine, $this->tableName, $this->name);
        return $encryptedField;
    }

    /**
     * Decrypt current value using underlying EncryptedField instance
     *
     * @return string
     */
    public function getDecryptedValue()
    {
        if (EncryptHelper::isEncrypted($this->value)) {
            return $this->decryptValue($this->value);
        }
        return $this->value;
    }

    /**
     * @param DataObject $record
     * @return void
     */
    protected function setEncryptionAad($record)
    {
        $field = EncryptHelper::getAadSource();
        if (!$field) {
            return;
        }
        if ($record && isset($record->$field)) {
            $this->encryptionAad = (string)$record->$field;
        }
    }

    /**
     * Decrypt a value using underlying EncryptedField instance
     *
     * @param string $value
     * @return string
     */
    protected function decryptValue($value)
    {
        if (!$value) {
            return $value;
        }
        if (!EncryptHelper::isEncrypted($value)) {
            return $value;
        }
        $decrypted = null;
        $aad = $this->encryptionAad;
        try {
            $decrypted = $this->getEncryptedField()->decryptValue($value, $aad);
        } catch (InvalidCiphertextException $ex) {
            $this->encryptionException = $ex;
            // rotate backend ?
            if (EncryptHelper::getAutomaticRotation()) {
                $encryption = EncryptHelper::getEncryption($value);
                $engine = EncryptHelper::getEngineForEncryption($encryption);
                $oldEncryptedField = $this->getEncryptedField($engine);
                $decrypted = $oldEncryptedField->decryptValue($value, $aad);
                // this could throw another error that won't be catched if the old configuration is invalid
            } else {
                $decrypted = $value;
            }
        } catch (Exception $ex) {
            // This is a temporary fix for records written with AAD enabled but saved improperly
            // This is not needed if resetFieldValues is used
            if ($ex->getMessage() == "Invalid ciphertext" && $aad) {
                try {
                    $decrypted = $this->getEncryptedField()->decryptValue($value, "0");
                } catch (Exception $ex) {
                    $this->encryptionException = $ex;
                }
            } else {
                $this->encryptionException = $ex;
            }
        }
        return $decrypted;
    }
}
