<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;
use SilverStripe\Control\Director;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Versioned\Versioned;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;
use SilverStripe\Assets\Flysystem\FlysystemAssetStore;
use SilverStripe\Assets\Storage\Sha1FileHashingService;
use SilverStripe\Core\Config\Config;

/**
 * Safe and encrypted content file
 * Also make sure that files are not public assets! => use htaccess
 * @property bool $Encrypted
 * @property File|EncryptedDBFile $owner
 */
class EncryptedDBFile extends DataExtension
{
    private static $db = [
        "Encrypted" => "Boolean",
    ];

    /**
     * @return EncryptedFile
     */
    protected function getEncryptedFileInstance()
    {
        $engine = EncryptHelper::getCipherSweet();
        $encFile = new EncryptedFile($engine);
        return $encFile;
    }

    /**
     * @return string
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
        $encFile = $this->getEncryptedFileInstance();
        $stream = $this->owner->getStream();
        return $encFile->isStreamEncrypted($stream);
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
        if ($this->owner->Encrypted) {
            $encFile = $this->getEncryptedFileInstance();
            $output = fopen('php://temp', 'w+b');

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
     * @return bool
     */
    public function encryptFileIfNeeded()
    {
        $encFile = $this->getEncryptedFileInstance();
        if (!$this->owner->exists()) {
            throw new Exception("File does not exist");
        }
        $stream = $this->owner->getStream();

        if (!$stream) {
            throw new Exception("Failed to get stream");
        }

        $result = false;

        // It's not yet encrypted
        if (!$encFile->isStreamEncrypted($stream)) {
            // php://temp is not a file path, it's a pseudo protocol that always creates a new random temp file when used.
            $output = fopen('php://temp', 'wb');
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
            $this->owner->Encrypted = true;
            if ($this->owner->hasExtension(Versioned::class)) {
                $result = $this->owner->writeWithoutVersion();
            } else {
                $result = $this->owner->write();
            }
            Config::modify()->set(FlysystemAssetStore::class, 'keep_empty_dirs', $configFlag);
        }

        // Make sure it's marked as encrypted
        if (!$this->owner->Encrypted) {
            $this->owner->Encrypted = true;
            if ($this->owner->hasExtension(Versioned::class)) {
                $result = $this->owner->writeWithoutVersion();
            } else {
                $result = $this->owner->write();
            }
        }

        return $result ? true : false;
    }
}
