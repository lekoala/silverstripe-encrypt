<?php

namespace LeKoala\Encrypt;

use Exception;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

/**
 * This trait allow encryption for fields that don't
 * require a blind index
 */
trait HasEncryption
{
    /**
     * @var Exception
     */
    protected $encryptionException;

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
     * @return Exception
     */
    public function getEncryptionException()
    {
        return $this->encryptionException;
    }

    /**
     * prepValueForDB gets passed $this->value
     *
     * @param string $value
     * @return string
     */
    public function prepValueForDB($value)
    {
        if (!$value) {
            if ($this->getNullifyEmpty() || $value === null) {
                return null;
            }
            return '';
        }
        // Don't encrypt twice
        if (EncryptHelper::isEncrypted($value)) {
            return $value;
        }
        $encryptedValue = $this->getEncryptedField()->encryptValue($value);
        return $encryptedValue;
    }

    public function setValue($value, $record = null, $markChanged = true)
    {
        // $markChanged is not used
        // The value might come encrypted from the database
        if ($value && EncryptHelper::isEncrypted($value)) {
            try {
                $this->value = $this->getEncryptedField()->decryptValue($value);
            } catch (InvalidCiphertextException $ex) {
                $this->encryptionException = $ex;
                // rotate backend ?
                if (EncryptHelper::getAutomaticRotation()) {
                    $encryption = EncryptHelper::getEncryption($value);
                    $engine = EncryptHelper::getEngineForEncryption($encryption);
                    $oldEncryptedField = $this->getEncryptedField($engine);
                    $this->value = $oldEncryptedField->decryptValue($value);
                } else {
                    $this->value = $value;
                }
            } catch (Exception $ex) {
                $this->encryptionException = $ex;
                // We cannot decrypt
                $this->value = $this->nullValue();
            }
        } else {
            $this->value = $value;
        }
        return $this;
    }
}
