<?php
namespace LeKoala\SilverStripeEncrypt;

use SilverStripe\ORM\FieldType\DBHTMLText;

/**
 * Encrypted HTMLText
 *
 * @link https://github.com/paragonie/sodium_compat
 */
class DBEncryptedHTMLText extends DBHTMLText
{
    public function prepValueForDB($value)
    {
        $value = $this->whitelistContent($value);

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
