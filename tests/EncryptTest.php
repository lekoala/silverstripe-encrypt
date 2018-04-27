<?php
namespace LeKoala\SilverStripeEncrypt\Tests;

use LeKoala\SilverStripeEncrypt\DBEncryptedHTMLText;
use LeKoala\SilverStripeEncrypt\DBEncryptedText;
use LeKoala\SilverStripeEncrypt\EncryptHelper;
use SilverStripe\ORM\DB;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\DataObject;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\Queries\SQLSelect;

/**
 * Test for Encrypt
 *
 * Run with the following command : ./vendor/bin/phpunit ./encrypt/tests/EncryptTest.php
 *
 * You may need to run:
 * php ./framework/cli-script.php dev/build ?flush=all
 * before (remember manifest for cli is not the same...)
 *
 * @group Encrypt
 */
class EncryptTest extends SapphireTest
{
    protected static $extra_dataobjects = [
        'LeKoala\SilverStripeEncrypt\Tests\EncryptedModel'
    ];



    public function testEncryptionWorks()
    {
        $someText = 'some text';

        $encrypt = EncryptHelper::encryptValue($someText);

        $decryptedValue = EncryptHelper::decryptBinaryValue($encrypt['binary_value']);

        $this->assertEquals($someText, $decryptedValue);
    }

    public function testRecordIsEncrypted()
    {
        $model = new EncryptedModel();

        $someText = 'some text';
        $model->EncryptedText = $someText .' text';
        $model->EncryptedHTMLText = $someText .' html';
        $id = $model->write();

        $this->assertNotEmpty($id);

        // For the model, its the same
        $this->assertEquals($model->EncryptedText, $someText .' text');
        $this->assertEquals($model->EncryptedHTMLText, $someText .' html');

        // In the db, it's not the same
        // TODO: this is not working because somehow the schema is not configured properly by SilverStripe

        $tableName = DataObject::getSchema()->tableName(EncryptedModel::class);
        $columnIdentifier = DataObject::getSchema()->sqlColumnForField(EncryptedModel::class, 'ID');
        $sql = new SQLSelect('*', [$tableName], [$columnIdentifier => $model->ID]);
        $dbRecord = $sql->firstRow();
        print_r($dbRecord);
        $text = isset($dbRecord['EncryptedText']) ? $dbRecord['EncryptedText'] : null;
        $this->assertNotEmpty($text);
        $this->assertNotEquals($text, $someText);
    }
}
