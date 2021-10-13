<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;

class EncryptedFile extends File
{
    protected function onBeforeWrite()
    {
        parent::onBeforeWrite();
        try {
            $this->encryptFileIfNeeded();
        } catch (Exception $ex) {
            $this->Encrypted = false;
        }
    }
}
