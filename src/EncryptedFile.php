<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;

/**
 * @mixin \LeKoala\Encrypt\EncryptedDBFile
 * @property bool $Encrypted
 */
class EncryptedFile extends File
{
    protected function onBeforeWrite()
    {
        parent::onBeforeWrite();
        try {
            $this->encryptFileIfNeeded(false);
        } catch (Exception $ex) {
            $this->Encrypted = false;
        }
    }

    public function setFromLocalFile($path, $filename = null, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromLocalFile($path, $filename = null, $hash = null, $variant = null, $config = []);
    }

    public function setFromStream($stream, $filename, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromStream($stream, $filename, $hash = null, $variant = null, $config = []);
    }

    public function setFromString($data, $filename, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromString($data, $filename, $hash = null, $variant = null, $config = []);
    }
}
