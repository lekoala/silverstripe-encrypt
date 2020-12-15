<?php

namespace LeKoala\Encrypt;

use SilverStripe\ORM\FieldType\DBVarchar;

/**
 * Fields using this class should use updated getField method
 */
class EncryptedDBVarchar extends DBVarchar
{
    use HasEncryption;
}
