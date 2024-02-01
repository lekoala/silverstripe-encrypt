<?php

namespace LeKoala\Encrypt\Test;

use SilverStripe\Dev\TestOnly;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * @property string $EncryptionKey
 * @property int $MemberID
 */
class Test_EncryptionKey extends DataObject implements TestOnly
{
    /**
     * @var string
     */
    private static $table_name = 'EncryptionKey';

    /**
     * @var array<string,string>
     */
    private static $db = [
        // A 256 bit key (32 bytes = 32*8)
        // 32 bytes = 64 chars in hex (eg using bin2hex)
        "EncryptionKey" => 'Varchar',

        // X25519 Keypair (2x 32 bytes keys)
        "SecretKey" => 'Varchar',
        "PublicKey" => 'Varchar',
    ];

    /**
     * @var array<string,string>
     */
    private static $has_one = [
        "Member" => Member::class,
    ];

    public static function getForMember(int $ID): ?string
    {
        $rec = self::get()->filter('MemberID', $ID)->first();
        return $rec->EncryptionKey ?? null;
    }

    /**
     * @param integer $ID
     * @return array<string,string>|null
     */
    public static function getKeyPair(int $ID): ?array
    {
        $rec = self::get()->filter('MemberID', $ID)->first();
        if ($rec) {
            return [
                'public' => Hex::decode($rec->PublicKey),
                'secret' => Hex::decode($rec->SecretKey),
            ];
        }
        return null;
    }
}
