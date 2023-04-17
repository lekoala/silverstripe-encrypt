<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\ORM\DataObject;
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
            } else {
                $decrypted = $value;
            }
        } catch (Exception $ex) {
            $this->encryptionException = $ex;
        }
        return $decrypted;
    }
}
