<?php

/**
 * Encrypted Text
 *
 * @link https://github.com/paragonie/sodium_compat
 */
class DBEncryptedText extends Text
{
	public function prepValueForDB($value)
	{
		if ($this->nullifyEmpty && $value == '') {
			return '';
		}

		$encryptedValue = EncryptHelper::encryptValue($value);
		return $encryptedValue['binary_value'];
	}

	public function setValue($value, $record = null)
	{
		if ($value && EncryptHelper::isHexadecimal($value)) {
			$this->value = EncryptHelper::decryptBinaryValue($value);
		} else {
			$this->value = $value;
		}
	}
}
