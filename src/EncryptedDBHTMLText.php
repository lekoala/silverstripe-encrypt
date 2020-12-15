<?php

namespace LeKoala\Encrypt;

use SilverStripe\ORM\FieldType\DBHTMLText;

/**
 * Fields using this class should use updated getField method
 */
class EncryptedDBHTMLText extends DBHTMLText
{
    use HasEncryption;
}
