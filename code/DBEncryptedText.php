<?php
namespace LeKoala\SilverStripeEncrypt;

use SilverStripe\ORM\FieldType\DBText;

/**
 * Encrypted Text
 *
 * @link https://github.com/paragonie/sodium_compat
 */
class DBEncryptedText extends DBText
{
    public function prepValueForDB($value)
    {
        if ($this->nullifyEmpty && $value == '') {
            return '';
        }

        $encryptedValue = EncryptHelper::encryptValue($value);
        return $encryptedValue['binary_value'];
    }

    public function setValue($value, $record = null, $markChanged = true)
    {
        if ($value && EncryptHelper::isHexadecimal($value)) {
            $this->value = EncryptHelper::decryptBinaryValue($value);
        } else {
            $this->value = $value;
        }
    }
}
