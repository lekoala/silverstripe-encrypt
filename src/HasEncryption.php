<?php

namespace LeKoala\Encrypt;

/**
 * This trait allow encryption for fields that don't
 * require a blind index
 */
trait HasEncryption
{
    use HasBaseEncryption;

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
        $aad = $this->encryptionAad;
        $encryptedValue = $this->getEncryptedField()->encryptValue($value, $aad);
        return $encryptedValue;
    }

    public function setValue($value, $record = null, $markChanged = true)
    {
        $this->setEncryptionAad($record);

        // Return early if we keep encrypted value in memory
        if (!EncryptHelper::getAutomaticDecryption()) {
            $this->value = $value;
            return $this;
        }

        // $markChanged is not used
        // The value might come encrypted from the database
        if ($value && EncryptHelper::isEncrypted($value)) {
            $this->value = $this->decryptValue($value);
        } else {
            $this->value = $value;
        }
        return $this;
    }
}
