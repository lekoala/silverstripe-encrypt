<?php

namespace LeKoala\Encrypt\Test;

use SilverStripe\Assets\File;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use LeKoala\Encrypt\EncryptedFile;
use LeKoala\Encrypt\EncryptedDBJson;
use LeKoala\Encrypt\EncryptedDBText;
use LeKoala\Encrypt\EncryptedDBField;
use LeKoala\Encrypt\EncryptedDBVarchar;
use LeKoala\Encrypt\HasEncryptedFields;
use ParagonIE\CipherSweet\JsonFieldMap;
use LeKoala\Encrypt\EncryptedDBHTMLText;
use LeKoala\Encrypt\EncryptedNumberField;
use LeKoala\Encrypt\EncryptHelper;

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
 * @property string $MyEncryptedJson
 * @property int $RegularFileID
 * @property int $EncryptedFileID
 */
class Test_EncryptedModel extends DataObject implements TestOnly
{
    use HasEncryptedFields;

    /**
     * @var string
     */
    private static $table_name = 'EncryptedModel';

    /**
     * @var array<string,string>
     */
    private static $db = [
        "Name" => 'Varchar',
        "MyText" => EncryptedDBText::class,
        "MyHTMLText" => EncryptedDBHTMLText::class,
        "MyVarchar" => EncryptedDBVarchar::class,
        "MyNumber" => EncryptedNumberField::class . '(["output_size" => 4, "domain_size" => 10])',
        "MyIndexedVarchar" => EncryptedDBField::class,
        "MyNullIndexedVarchar" => EncryptedDBField::class,
        "MyJson" => EncryptedDBJson::class,
        "MyEncryptedJson" => EncryptedDBJson::class . "(['map' => '7551830f{\"fields\":{\"$6e616d65\":\"string\",\"$616374697665\":\"bool\",\"$616765\":\"int\"}}'])",
    ];

    /**
     * @var array<string,string>
     */
    private static $has_one = [
        "RegularFile" => File::class,
        // We use regular File class for encrypted files to keep only one table
        "EncryptedFile" => File::class,
        "EncryptedFileClass" => EncryptedFile::class,
        "Member" => Member::class,
    ];

    /**
     * @var array<string,mixed>
     */
    private static $indexes = [
        'MyIndexedVarcharBlindIndex' => true,
        'MyNumberBlindIndex' => true,
        'MyNumberLastFourBlindIndex' => true,
    ];

    /**
     * @param string $baseTable
     * @param string $now
     * @return void
     */
    protected function writeBaseRecord($baseTable, $now)
    {
        parent::writeBaseRecord($baseTable, $now);
        // After base record is written, we have an ID and therefore AAD has changed
        $this->resetFieldValues();
    }

    public function getField($field)
    {
        return $this->getEncryptedField($field);
    }

    public function setField($fieldName, $val)
    {
        return $this->setEncryptedField($fieldName, $val);
    }
}
