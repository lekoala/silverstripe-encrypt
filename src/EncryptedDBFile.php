<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\Assets\File;
use SilverStripe\ORM\DataExtension;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedFile;

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
            }
        } else {
            fpassthru($stream);
        }
    }

    /**
     * Files are not encrypted automatically
     * Calls this method to encrypt them
     *
     * @throws Exception
     * @return void
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

        if (!$encFile->isStreamEncrypted($stream)) {
            // php://temp is not a file path, it's a pseudo protocol that always creates a new random temp file when used.
            $output = fopen('php://temp', 'wb');
            $success =  $encFile->encryptStream($stream, $output);
            if (!$success) {
                throw new Exception("Failed to encrypt stream");
            }
            // dont forget to rewind the stream !
            rewind($output);
            // Keep the hash ! encrypting file will change it's content and it would update the hash
            // This would move the file on the filesystem and mess up FileHash link
            $fileResult = $this->owner->setFromStream($output, $this->owner->getFilename(), $this->owner->FileHash);
            // Mark as encrypted in db
            $this->owner->Encrypted =  true;
            $this->owner->write();
        } elseif ($this->owner->Encrypted) {
            // Stream is not encrypted
            if ($this->owner->Encrypted) {
                $this->owner->Encrypted = false;
                $this->owner->write();
            }
        }
    }
}
