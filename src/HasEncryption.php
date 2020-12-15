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

    public function prepValueForDB($value)
    {
        if (!$value) {
            if ($this->getNullifyEmpty() || $value === null) {
                return null;
            }
            return '';
        }

        $encryptedValue = $this->getEncryptedField()->encryptValue($value);
        return $encryptedValue;
    }

    public function setValue($value, $record = null, $markChanged = true)
    {
        if ($value && EncryptHelper::isEncrypted($value)) {
            try {
                $this->value = $this->getEncryptedField()->decryptValue($value);
            } catch (InvalidCiphertextException $ex) {
                // rotate backend ?
                // $this->value = $newEncryptedField->decryptValue($encryptedValue);
            } catch (Exception $ex) {
                // We cannot decrypt
                $this->value = $this->nullValue();
            }
        } else {
            $this->value = $value;
        }
        return $this;
    }
}
