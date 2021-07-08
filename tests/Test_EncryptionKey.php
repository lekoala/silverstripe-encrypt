<?php

namespace LeKoala\Encrypt\Test;

use SilverStripe\Assets\File;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;

/**
 * @property string $EncryptionKey
 * @property int $MemberID
 */
class Test_EncryptionKey extends DataObject implements TestOnly
{
    private static $table_name = 'EncryptionKey';

    private static $db = [
        "EncryptionKey" => 'Varchar',
    ];

    private static $has_one = [
        "Member" => File::class,
    ];

    public static function getForMember($ID)
    {
        $rec = self::get()->filter('MemberID', $ID)->first();
        return $rec->EncryptionKey ?? null;
    }
}
