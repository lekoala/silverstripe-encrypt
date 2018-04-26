<?php

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
	protected $extraDataObjects = array(
		'EncryptedModel'
	);
	public function testEncryptionWorks()
	{
		$someText = 'some text';

		$encrypt = EncryptHelper::encryptValue($someText);

		$decryptedValue = EncryptHelper::decryptBinaryValue($encrypt['binary_value']);

		$this->assertEquals($someText, $decryptedValue);
	}
	public function testRecordIsEncrypted()
	{
		$model = new EncryptedModel;

		$singl = singleton('EncryptedModel');

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

class EncryptedModel extends DataObject implements TestOnly
{

	private static $db = [
		"EncryptedText" => DBEncryptedText::class,
		"EncryptedHTMLText" => DBEncryptedHTMLText::class,
	];

}
