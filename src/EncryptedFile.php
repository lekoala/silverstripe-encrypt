<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;

/**
 * @mixin \LeKoala\Encrypt\EncryptedDBFile
 * @property bool $Encrypted
 * @method bool encryptFileIfNeeded()
 */
class EncryptedFile extends File
{
    /**
     * @return void
     */
    protected function onBeforeWrite()
    {
        parent::onBeforeWrite();
        try {
            $this->encryptFileIfNeeded(false);
        } catch (Exception $ex) {
            $this->Encrypted = false;
        }
    }

    /**
     * @param string $path
     * @param ?string $filename
     * @param ?string $hash
     * @param ?string $variant
     * @param array<mixed> $config
     * @return array<mixed>
     */
    public function setFromLocalFile($path, $filename = null, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromLocalFile($path, $filename = null, $hash = null, $variant = null, $config = []);
    }

    /**
     * @param resource $stream
     * @param string $filename
     * @param ?string $hash
     * @param ?string $variant
     * @param array<mixed> $config
     * @return array<mixed>
     */
    public function setFromStream($stream, $filename, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromStream($stream, $filename, $hash = null, $variant = null, $config = []);
    }

    /**
     * @param string $data
     * @param string $filename
     * @param ?string $hash
     * @param ?string $variant
     * @param array<mixed> $config
     * @return array<mixed>
     */
    public function setFromString($data, $filename, $hash = null, $variant = null, $config = [])
    {
        $this->Encrypted = false;
        return parent::setFromString($data, $filename, $hash = null, $variant = null, $config = []);
    }
}
