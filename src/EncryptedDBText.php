<?php

namespace LeKoala\Encrypt;

use SilverStripe\ORM\FieldType\DBText;

/**
 * Fields using this class should use updated getField method
 */
class EncryptedDBText extends DBText
{
    use HasEncryption;
}
