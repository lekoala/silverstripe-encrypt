<?php

namespace LeKoala\Encrypt;

use Exception;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

trait HasBaseEncryption
{
    /**
     * @var Exception
     */
    protected $encryptionException;

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
     * @param string $value
     * @return string
     */
    protected function decryptValue($value)
    {
        $decrypted = null;
        try {
            $decrypted = $this->getEncryptedField()->decryptValue($value);
        } catch (InvalidCiphertextException $ex) {
            $this->encryptionException = $ex;
            // rotate backend ?
            if (EncryptHelper::getAutomaticRotation()) {
                $encryption = EncryptHelper::getEncryption($value);
                $engine = EncryptHelper::getEngineForEncryption($encryption);
                $oldEncryptedField = $this->getEncryptedField($engine);
                $decrypted = $oldEncryptedField->decryptValue($value);
            } else {
                $decrypted = $value;
            }
        } catch (Exception $ex) {
            $this->encryptionException = $ex;
        }
        return $decrypted;
    }
}
