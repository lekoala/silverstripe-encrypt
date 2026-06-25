<?php

declare(strict_types=1);

namespace LeKoala\Encrypt\Test;

use SilverStripe\Assets\File;
use SilverStripe\Dev\TestOnly;

/**
 * Simulate a file whose encrypted write cannot be read back from storage.
 */
class Test_UnreadableAfterEncryptFile extends File implements TestOnly
{
    public bool $failSubsequentStreamReads = true;

    private int $streamReadCount = 0;

    /**
     * Return null after the source stream has been read once.
     *
     * @return resource|null
     */
    public function getStream()
    {
        $this->streamReadCount++;

        if ($this->failSubsequentStreamReads && $this->streamReadCount > 1) {
            return null;
        }

        return parent::getStream();
    }

    /**
     * Get how many times the file stream was requested.
     *
     * @return int
     */
    public function getStreamReadCount(): int
    {
        return $this->streamReadCount;
    }
}
