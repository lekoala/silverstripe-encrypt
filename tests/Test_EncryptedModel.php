<?php

namespace LeKoala\Encrypt\Test;

use SilverStripe\Assets\File;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;
use LeKoala\Encrypt\EncryptedDBText;
use LeKoala\Encrypt\EncryptedDBField;
use LeKoala\Encrypt\EncryptedDBVarchar;
use LeKoala\Encrypt\HasEncryptedFields;
use LeKoala\Encrypt\EncryptedDBHTMLText;
use LeKoala\Encrypt\EncryptedDBJson;
use LeKoala\Encrypt\EncryptedFile;
use LeKoala\Encrypt\EncryptedNumberField;
use SilverStripe\Security\Member;

/**
 * A test model for our encryption
 *
 * @property string $Name
 * @property string $MyText
 * @property string $MyHTMLText
 * @property string $MyVarchar
 * @property string $MyNumber
 * @property string $MyVarcharWithIndex
 * @property string $MyJson
 * @property int $RegularFileID
 * @property int $EncryptedFileID
 */
class Test_EncryptedModel extends DataObject implements TestOnly
{
    use HasEncryptedFields;

    private static $table_name = 'EncryptedModel';

    private static $db = [
        "Name" => 'Varchar',
        "MyText" => EncryptedDBText::class,
        "MyHTMLText" => EncryptedDBHTMLText::class,
        "MyVarchar" => EncryptedDBVarchar::class,
        "MyNumber" => EncryptedNumberField::class . '(["output_size" => 4, "domain_size" => 10])',
        "MyIndexedVarchar" => EncryptedDBField::class,
        "MyJson" => EncryptedDBJson::class,
    ];

    private static $has_one = [
        "RegularFile" => File::class,
        // We use regular File class for encrypted files to keep only one table
        "EncryptedFile" => File::class,
        "EncryptedFileClass" => EncryptedFile::class,
        "Member" => Member::class,
    ];

    private static $indexes = [
        'MyIndexedVarcharBlindIndex' => true,
        'MyNumberBlindIndex' => true,
        'MyNumberLastFourBlindIndex' => true,
    ];

    public function getField($field)
    {
        return $this->getEncryptedField($field);
    }

    public function setField($fieldName, $val)
    {
        return $this->setEncryptedField($fieldName, $val);
    }
}
