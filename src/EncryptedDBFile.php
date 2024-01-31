<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;
use SilverStripe\Control\Director;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Versioned\Versioned;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;
use SilverStripe\Assets\Flysystem\FlysystemAssetStore;

/**
 * Safe and encrypted content file
 * Also make sure that files are not public assets! => use htaccess
 * @property bool $Encrypted
 * @property File&EncryptedDBFile $owner
 */
class EncryptedDBFile extends DataExtension
{
    /**
     * @var EncryptedFile
     */
    protected static $encryptionEngine;

    /**
     * @var array<string,string>
     */
    private static $db = [
        "Encrypted" => "Boolean",
    ];

    /**
     * @return string|bool
     */
    public function getDecryptionLink()
    {
        $data = [
            "ID" => $this->owner->ID,
            "Hash" => substr($this->owner->File->Hash, 0, 10),
        ];
        $url = "__decrypt/?" . http_build_query($data);
        return Director::absoluteURL($url);
    }

    /**
     * Check if the actual file on the filesystem is encrypted
     * You might also use the Encrypted field that should be accurate
     *
     * @return boolean
     */
    public function isEncrypted()
    {
        $stream = $this->owner->getStream();
        if (!$stream) {
            return false;
        }
        $encFile = EncryptHelper::getEncryptedFileInstance();
        return $encFile->isStreamEncrypted($stream);
    }

    /**
     * @param boolean $forceStatus
     * @param boolean $write
     * @return boolean
     */
    public function updateEncryptionStatus($forceStatus = null, $write = true)
    {
        if ($forceStatus !== null) {
            $this->owner->Encrypted = (bool)$forceStatus;
        } else {
            if ($this->isEncrypted()) {
                $this->owner->Encrypted = true;
            } else {
                $this->owner->Encrypted = false;
            }
        }
        if ($write) {
            if ($this->owner->hasExtension(Versioned::class)) {
                $this->owner->writeWithoutVersion();
            } else {
                $this->owner->write();
            }
        }
        return $this->owner->Encrypted;
    }

    /**
     * Output file using regular php
     * Does not send headers, see EncryptHelper::sendDecryptedFile
     *
     * @throws Exception
     * @return void
     */
    public function sendDecryptedFile()
    {
        if (ob_get_level()) {
            ob_end_clean();
        }
        $stream = $this->owner->getStream();
        if (!$stream) {
            throw new Exception("File not found");
        }
        if ($this->owner->Encrypted) {
            $encFile = EncryptHelper::getEncryptedFileInstance();
            $output = fopen('php://temp', 'w+b');
            if (!$output) {
                throw new Exception("Failed to open output stream");
            }

            // We need to decrypt stream
            if ($encFile->isStreamEncrypted($stream)) {
                $success = $encFile->decryptStream($stream, $output);
                if (!$success) {
                    throw new Exception("Failed to decrypt stream");
                }

                // Rewind first
                rewind($output);
                fpassthru($output);
            } else {
                fpassthru($stream);
            }
        } else {
            fpassthru($stream);
        }
    }

    /**
     * Files are not encrypted automatically
     * Call this method to encrypt them
     *
     * @throws Exception
     * @param bool $write
     * @return bool
     */
    public function encryptFileIfNeeded($write = true)
    {
        // Already mark as encrypted
        if ($this->owner->Encrypted) {
            return true;
        }
        if (!$this->owner->exists()) {
            throw new Exception("File does not exist");
        }
        $stream = $this->owner->getStream();
        if (!$stream) {
            throw new Exception("Failed to get stream");
        }

        $encFile = EncryptHelper::getEncryptedFileInstance();
        $isEncrypted = $encFile->isStreamEncrypted($stream);

        // It's not yet encrypted
        if (!$isEncrypted) {
            // php://temp is not a file path, it's a pseudo protocol that always creates a new random temp file when used.
            $output = fopen('php://temp', 'wb');
            if (!$output) {
                throw new Exception("Failed to decrypt stream");
            }
            $success =  $encFile->encryptStream($stream, $output);
            if (!$success) {
                throw new Exception("Failed to encrypt stream");
            }
            // dont forget to rewind the stream !
            rewind($output);

            // This is really ugly, see https://github.com/silverstripe/silverstripe-assets/issues/467
            $configFlag = FlysystemAssetStore::config()->keep_empty_dirs;
            Config::modify()->set(FlysystemAssetStore::class, 'keep_empty_dirs', true);
            $fileResult = $this->owner->setFromStream($output, $this->owner->getFilename());
            // Mark as encrypted in db
            $this->updateEncryptionStatus(true, $write);
            Config::modify()->set(FlysystemAssetStore::class, 'keep_empty_dirs', $configFlag);

            return true;
        }

        if ($this->owner->Encrypted != $isEncrypted) {
            $this->updateEncryptionStatus($isEncrypted, $write);
        }

        return $isEncrypted;
    }
}
