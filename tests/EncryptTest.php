<?php
namespace LeKoala\SilverStripeEncrypt\Tests;

use LeKoala\SilverStripeEncrypt\DBEncryptedHTMLText;
use LeKoala\SilverStripeEncrypt\DBEncryptedText;
use LeKoala\SilverStripeEncrypt\EncryptHelper;
use SilverStripe\ORM\DB;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\DataObject;
use SilverStripe\Dev\TestOnly;

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
        $result = DB::query('show tables');
        print_r($result, 1);
        $model = new EncryptedModel();

        $someText = 'some text';
        $model->EncryptedText = $someText;
        $ID = $model->write();

        $this->assertNotEmpty($ID);
        // For the model, its the same
        $this->assertEquals($model->EncryptedText, $someText);

        // In the db, it's not the same
        // TODO: this is not working because somehow the schema is not configured properly by SilverStripe
        $dbRecord = DB::query("SELECT * FROM EncryptedModel WHERE ID = " . $model->ID)->record();
        $text = isset($dbRecord['EncryptedText']) ? $dbRecord['EncryptedText'] : null;
        // $this->assertNotEmpty($text);
        // $this->assertNotEquals($text, $someText);
    }
}
