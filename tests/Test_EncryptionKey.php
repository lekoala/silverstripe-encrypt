<?php

namespace LeKoala\Encrypt\Test;

use SilverStripe\Assets\File;
use SilverStripe\Dev\TestOnly;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\ORM\DataObject;

/**
 * @property string $EncryptionKey
 * @property int $MemberID
 */
class Test_EncryptionKey extends DataObject implements TestOnly
{
    private static $table_name = 'EncryptionKey';

    private static $db = [
        // A 256 bit key (32 bytes = 32*8)
        // 32 bytes = 64 chars in hex (eg using bin2hex)
        "EncryptionKey" => 'Varchar',

        // X25519 Keypair (2x 32 bytes keys)
        "SecretKey" => 'Varchar',
        "PublicKey" => 'Varchar',
    ];

    private static $has_one = [
        "Member" => File::class,
    ];

    public static function getForMember($ID)
    {
        $rec = self::get()->filter('MemberID', $ID)->first();
        return $rec->EncryptionKey ?? null;
    }

    public static function getKeyPair($ID)
    {
        $rec = self::get()->filter('MemberID', $ID)->first();
        if ($rec) {
            return [
                'public' => Hex::decode($rec->PublicKey),
                'secret' => Hex::decode($rec->SecretKey),
            ];
        }
        return false;
    }
}
