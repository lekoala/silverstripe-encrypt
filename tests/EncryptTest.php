<?php

namespace LeKoala\Encrypt\Test;

use Exception;
use SilverStripe\Assets\File;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use LeKoala\Encrypt\EncryptHelper;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use LeKoala\Encrypt\EncryptedDBField;
use LeKoala\Encrypt\HasEncryptedFields;
use ParagonIE\CipherSweet\CipherSweet;
use SilverStripe\ORM\DB;
use SilverStripe\ORM\Queries\SQLSelect;
use SilverStripe\ORM\Queries\SQLUpdate;

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
    /**
     * Defines the fixture file to use for this test class
     * @var string
     */
    protected static $fixture_file = 'EncryptTest.yml';

    protected static $extra_dataobjects = [
        Test_EncryptedModel::class,
    ];

    public function setUp()
    {
        // EncryptHelper::setForcedEncryption("nacl");
        EncryptHelper::setAutomaticRotation(false);
        Environment::setEnv('ENCRYPTION_KEY', '502370dfc69fd6179e1911707e8a5fb798c915900655dea16370d64404be04e5');
        parent::setUp();
        EncryptHelper::setAutomaticRotation(true);

        // test extension is available
        if (!extension_loaded('sodium')) {
            throw new Exception("You must load sodium extension for this");
        }

        // The rows are already decrypted due to the fixtures going through the ORM layer
        $result = DB::query("SELECT * FROM EncryptedModel");
        // echo '<pre>';
        // print_r(iterator_to_array($result));
        // die();

        /*
        [0] => Array
        (
            [ID] => 1
            [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
            [LastEdited] => 2021-07-07 14:53:35
            [Created] => 2021-07-07 14:53:35
            [Name] => demo
            [MyText] => brng:MlkjE7xiock-ofeuROQCG7n1wOrbG8bj4gc0pTqZn2u3e2pNcQe-mCP6qgT1QkXPxZGjvojySyuWzA_aK8Y-fwrUMl2_8Q==
            [MyHTMLText] => brng:mSNIa6LmvexuEu2eoStA8ZxyCW22UOhrA9r_guJR8eDsvwxWQJNgdEzKaO5dct0HeiYdd7CYouPWm-ki-els-YV2DBOlv85TVgyckys=
            [MyVarchar] => brng:1fHGMjvptiCtmUQ5KNwAPqJsvrg38VUjUAsqvgW8taz-Ao791j0T8WBcCMvUcnZ087N1EifryBScrC0QhJzb5Jmt7Fp1dsbBB0EIr2glJg==
            [RegularFileID] => 2
            [EncryptedFileID] => 3
            [MyNumberValue] => nacl:tKXzRBnsEfdJVcCouNIvRYQlt5dPQrZk4_PvpdyEUkrN6gWdDzxJxwD6VDKgjQeKamo=
            [MyNumberBlindIndex] => a1de44f9
            [MyNumberLastFourBlindIndex] => addb
            [MyIndexedVarcharValue] => nacl:F-q5OUdxjK77sxrGM6Q8BzQ3lDbiDwM9VxOUchcrlDXmgzUwhb0ADQsrxRlbyZnCG4q3nRlJ2cVHRLskVA==
            [MyIndexedVarcharBlindIndex] => 216d113a
        )
        */

        // Replace with actual yml values
        $data = [
            'MyText' => 'nacl:_nKhFvZkFwWJssMLf2s6wsucM-6zMmT862XGiYG9KQaL5fgl3CSA_O0gcs3OGPPB4AJoNInC',
            'MyHTMLText' => 'nacl:jetKPUBgETbLtlfAx1VkZiWJFG65hCuWVSmrwVDX4TTysmJkj2vnhI329oa9eCTlX1kKSjCp7AyFXDKT7Q==',
            'MyVarchar' => 'nacl:_-5ZsG9txfqMNkHY7xl0JlmCLzrx9BemtC0CwGjYZOt9pCwle9PjHmIZcqJcoEdxpJXplLtKPF-xPGax_pIy',
            'MyIndexedVarcharValue' => 'nacl:V1G-EPYeHP5-OQu2XAcPp4ym0HuvLpseBqytg3VVddAWoyC3Lm5aAE3G9xx_2uW6QwO0dcnrLFBPNFZ6eQ==',
            'MyNumberValue' => 'nacl:u4-luf5o0pi-LuGOwLvKVGgD_tLlO8YJ7GbIx4VYYcUvoPNM-9pQfv05iwb0HQ6ugW4=',
        ];
        $update = new SQLUpdate("EncryptedModel", $data, "ID IN (1,3)");
        $update->execute();
        $data = [
            'MyText' => 'brng:DwBtLvR876mbL5qfX1IIUDZ7NbrDtyXAgXjB8dDKxfYAYKlajKr9J9NGMY47tkNcrLv4PBbHQ4bAOTZHGsTvmQuGT7he0w==',
            'MyHTMLText' => 'brng:Nf7VDpEPIQABaZvch8wDY3jCuctBcy0x6sIJO_BkWJL2H86b6O0WvXfDldFihhXxnhzJH3cy-Ygx6sMbgBttDPcT6j8SXFqxeG2pxHI=',
            'MyVarchar' => 'brng:hoE5xdUMwdJRjXi4jsGs8d_FzBzibUqmiRdoC-oo7_JsFPtz55FzAIb_Qcl-SreatW0uZViRGUvhLGbszKuIUejswmXIqYtSglkc9nHk5g==',
            'MyIndexedVarcharValue' => 'brng:_RZQDZXqeISYm3WtfTSAS2p0hZz-QDHAWmFSKvcaWLQ5ODRyUKKcPvsGOiIvfBPYmOJH35zh1Hrm2K2LY4ElLNVfAQN_QgcXpxWWNWI=',
            'MyNumberValue' => 'brng:4AB4YlC-AZHrb6d-t6aiDjZDVdg0BHRN2jAb5CoxiFN89XssvReGkbQMp9jGbXtstk1W94745WWJeiI4n05HsDPu',
        ];
        $update = new SQLUpdate("EncryptedModel", $data, "ID IN (2)");
        $update->execute();
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    /**
     * @return Test_EncryptedModel
     */
    public function getTestModel()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'demo');
    }

    /**
     * @return Test_EncryptedModel
     */
    public function getTestModel2()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'demo2');
    }

    /**
     * @return Test_EncryptedModel
     */
    public function getTestModel3()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'demo3');
    }

    /**
     * @return Member
     */
    public function getAdminMember()
    {
        return $this->objFromFixture(Member::class, 'admin');
    }

    /**
     * @return File
     */
    public function getRegularFile()
    {
        return $this->objFromFixture(File::class, 'regular');
    }

    /**
     * @return File
     */
    public function getEncryptedFile()
    {
        return $this->objFromFixture(File::class, 'encrypted');
    }

    /**
     * @param string $class
     * @param int $id
     * @return array
     */
    protected function fetchRawData($class, $id)
    {
        $tableName = DataObject::getSchema()->tableName($class);
        $columnIdentifier = DataObject::getSchema()->sqlColumnForField($class, 'ID');
        $sql = new SQLSelect('*', [$tableName], [$columnIdentifier => $id]);
        $dbRecord = $sql->firstRow()->execute()->first();
        return $dbRecord;
    }

    public function testEncryption()
    {
        $someText = 'some text';
        $encrypt = EncryptHelper::encrypt($someText);
        $decryptedValue = EncryptHelper::decrypt($encrypt);

        $this->assertEquals($someText, $decryptedValue);
    }

    public function testIndexes()
    {
        $indexes = DataObject::getSchema()->databaseIndexes(Test_EncryptedModel::class);
        $keys = array_keys($indexes);
        $this->assertContains('MyIndexedVarcharBlindIndex', $keys, "Index is not defined in : " . implode(", ", $keys));
        $this->assertContains('MyNumberLastFourBlindIndex', $keys, "Index is not defined in : " . implode(", ", $keys));
    }

    public function testSearch()
    {
        $singl = singleton(Test_EncryptedModel::class);
        $obj = $singl->dbObject('MyIndexedVarchar');
        $record = $obj->fetchRecord('some_searchable_value');

        $this->assertNotEmpty($record);
        $this->assertEquals(1, $record->ID);
        $this->assertNotEquals(2, $record->ID);

        $record = $obj->fetchRecord('some_unset_value');
        $this->assertEmpty($record);

        // Let's try our four digits index
        $obj = $singl->dbObject('MyNumber');
        $record = $obj->fetchRecord('6789', 'LastFourBlindIndex');
        $searchValue = $obj->getSearchValue('6789', 'LastFourBlindIndex');
        // $searchParams = $obj->getSearchParams('6789', 'LastFourBlindIndex');
        // print_r($searchParams);
        $this->assertNotEmpty($record, "Nothing found for $searchValue");
        $this->assertEquals(1, $record->ID);
    }

    public function testSearchFilter()
    {
        $record = Test_EncryptedModel::get()->filter('MyIndexedVarchar:Encrypted', 'some_searchable_value')->first();
        $this->assertNotEmpty($record);
        $this->assertEquals(1, $record->ID);
        $this->assertNotEquals(2, $record->ID);

        $record = Test_EncryptedModel::get()->filter('MyIndexedVarchar:Encrypted', 'some_unset_value')->first();
        $this->assertEmpty($record);
    }

    public function testRotation()
    {
        $model = $this->getTestModel3();
        $data = $this->fetchRawData(Test_EncryptedModel::class, $model->ID);

        $old = EncryptHelper::getEngineForEncryption("nacl");
        $result = $model->needsToRotateEncryption($old);
        $this->assertTrue($result);

        $result = $model->rotateEncryption($old);
        $this->assertTrue($result);
    }

    public function testFixture()
    {
        // this one use nacl encryption and will be rotated transparently
        $model = $this->getTestModel();

        $result = $model->needsToRotateEncryption(EncryptHelper::getEngineForEncryption("nacl"));
        $this->assertTrue($result);

        // Ensure we have our blind indexes
        $this->assertTrue($model->hasDatabaseField('MyIndexedVarcharValue'));
        $this->assertTrue($model->hasDatabaseField('MyIndexedVarcharBlindIndex'));
        $this->assertTrue($model->hasDatabaseField('MyNumberValue'));
        $this->assertTrue($model->hasDatabaseField('MyNumberBlindIndex'));
        $this->assertTrue($model->hasDatabaseField('MyNumberLastFourBlindIndex'));

        if (class_uses($model, HasEncryptedFields::class)) {
            $this->assertTrue($model->hasEncryptedField('MyVarchar'));
            $this->assertTrue($model->hasEncryptedField('MyIndexedVarchar'));
        }

        // print_r($model);
        /*
         [record:protected] => Array
        (
            [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
            [LastEdited] => 2020-12-15 10:09:47
            [Created] => 2020-12-15 10:09:47
            [Name] => demo
            [MyText] => nacl:mQ1g5ugjYSWjFd-erM6-xlB_EbWp1bOAUPbL4fa3Ce5SX6LP7sFCczkFx_lRABvZioWJXx-L
            [MyHTMLText] => nacl:836In6YCaEf3_mRJR7NOC_s0P8gIFESgmPnHCefTe6ycY_6CLKVmT0_9KWHgnin-WGXMJawkS1hS87xwQw==
            [MyVarchar] => nacl:ZeOw8-dcBdFemtGm-MRJ5pCSipOtAO5-zBRms8F5Elex08GuoL_JKbdN-CiOP-u009MJfvGZUkx9Ru5Zn0_y
            [RegularFileID] => 2
            [EncryptedFileID] => 3
            [MyIndexedVarcharBlindIndex] => 04bb6edd
            [ID] => 1
            [RecordClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
        )
        */

        $varcharValue = 'encrypted varchar value';
        $varcharWithIndexValue = 'some_searchable_value';
        // regular fields are not affected
        $this->assertEquals('demo', $model->Name);

        // get value
        $this->assertEquals($varcharValue, $model->dbObject('MyVarchar')->getValue());
        // encrypted fields work transparently when using trait
        $this->assertEquals($varcharValue, $model->MyVarchar);


        $this->assertTrue($model->dbObject('MyIndexedVarchar') instanceof EncryptedDBField);
        $this->assertTrue($model->dbObject('MyIndexedVarchar')->hasField('Value'));

        $model->MyIndexedVarchar = $varcharWithIndexValue;
        $model->write();
        $this->assertEquals($varcharWithIndexValue, $model->MyIndexedVarchar);

        $dbRecord = $this->fetchRawData(get_class($model), $model->ID);
        // print_r($dbRecord);
        /*
        Array
(
    [ID] => 1
    [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
    [LastEdited] => 2020-12-15 10:10:27
    [Created] => 2020-12-15 10:10:27
    [Name] => demo
    [MyText] => nacl:aDplmA9hs7naqiPwWdNRMcYNUltf4mOs8KslRQZ4vCdnJylnbjAJYChtVH7wiiygsAHWqbM6
    [MyHTMLText] => nacl:dMvk5Miux0bsSP1SjaXQRlbGogNTu7UD3p6AlNHFMAEGXOQz03hkBx43C-WelCS0KUdAN9ewuwuXZqMmRA==
    [MyVarchar] => nacl:sZRenCG6En7Sg_HmsUHkNy_1MXOstly7eHm0i2iq83kTFH40UsQj-HTqxxYfx0ghuWSKbcqHQ7_OAEy4pcPm
    [RegularFileID] => 2
    [EncryptedFileID] => 3
    [MyNumberValue] =>
    [MyNumberBlindIndex] =>
    [MyNumberLastFourBlindIndex] =>
    [MyIndexedVarcharValue] =>
    [MyIndexedVarcharBlindIndex] => 04bb6edd
)
*/
        $this->assertNotEquals($varcharValue, $dbRecord['MyVarchar']);
        $this->assertNotEmpty($dbRecord['MyVarchar']);
        $this->assertTrue(EncryptHelper::isEncrypted($dbRecord['MyVarchar']));
    }

    public function testFixture2()
    {
        // this one has only brng encryption
        $model = $this->getTestModel2();

        $result = $model->needsToRotateEncryption(EncryptHelper::getCipherSweet());
        $this->assertFalse($result);

        // Ensure we have our blind indexes
        $this->assertTrue($model->hasDatabaseField('MyIndexedVarcharValue'));
        $this->assertTrue($model->hasDatabaseField('MyIndexedVarcharBlindIndex'));
        $this->assertTrue($model->hasDatabaseField('MyNumberValue'));
        $this->assertTrue($model->hasDatabaseField('MyNumberBlindIndex'));
        $this->assertTrue($model->hasDatabaseField('MyNumberLastFourBlindIndex'));

        if (class_uses($model, HasEncryptedFields::class)) {
            $this->assertTrue($model->hasEncryptedField('MyVarchar'));
            $this->assertTrue($model->hasEncryptedField('MyIndexedVarchar'));
        }


        // print_r($model);
        /*
        [record:protected] => Array
        (
            [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
            [LastEdited] => 2021-07-07 13:38:48
            [Created] => 2021-07-07 13:38:48
            [Name] => demo2
            [MyText] => brng:XLzehy47IgENco4DcZj75u9D2p53UjDMCmTFGPNdmzYYxVVbDsaVWuZP1dTvIDaYagVggNAxT8S9fUTXw55VyIv6OxYJrQ==
            [MyHTMLText] => brng:bJ-6iGa-gjl9M6-UaNvtSrRuFLwDTLC6SIekrPHTcN_nmIUaK_VEFNAGVd3q__siNsvVXLreSlunpSyJ4JmF8eyI12ltz_s-eV6WVXw=
            [MyVarchar] => brng:qNEVUW3TS6eACSS4v1_NK0FOiG5JnbihmOHR1DU4L8Pt63OXQIJr_Kpd34J1IHaJXZWt4uuk2SZgskmvf8FrfApag_sRypca87MegXg_wQ==
            [RegularFileID] => 0
            [EncryptedFileID] => 0
            [MyNumberValue] => brng:pKYd8mXDduwhudwWeoE_ByO6IkvVlykVa6h09DTYFdHcb52yA1R5yhTEqQQjz1ndADFRa9WLLM3_e1U8PfPTiP4E
            [MyNumberBlindIndex] => a1de44f9
            [MyNumberLastFourBlindIndex] => addb
            [MyIndexedVarcharValue] => brng:TBD63tu-P9PluzI_zKTZ17P-4bhFvhbW7eOeSOOnDEf7n3Ytv2_52rlvGTVSJeWr5f6Z5eqrxi-RL5B6V0PrUmEqhfE2TGt-IdH5hfU=
            [MyIndexedVarcharBlindIndex] => 216d113a
            [ID] => 2
            [RecordClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
        )
        */

        $varcharValue = 'encrypted varchar value';
        $varcharWithIndexValue = 'some_searchable_value';
        // regular fields are not affected
        $this->assertEquals('demo2', $model->Name);

        // get value
        $this->assertEquals($varcharValue, $model->dbObject('MyVarchar')->getValue());
        // encrypted fields work transparently when using trait
        $this->assertEquals($varcharValue, $model->MyVarchar);


        $this->assertTrue($model->dbObject('MyIndexedVarchar') instanceof EncryptedDBField);
        $this->assertTrue($model->dbObject('MyIndexedVarchar')->hasField('Value'));

        $model->MyIndexedVarchar = $varcharWithIndexValue;
        $model->write();
        $this->assertEquals($varcharWithIndexValue, $model->MyIndexedVarchar);

        $dbRecord = $this->fetchRawData(get_class($model), $model->ID);
        // print_r($dbRecord);
        /*
        Array
(
    [ID] => 2
    [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
    [LastEdited] => 2021-07-07 13:52:10
    [Created] => 2021-07-07 13:52:08
    [Name] => demo2
    [MyText] => brng:IQ-6VoXJedlAGdoCPFUVTSnipUPR4k9YSi3Ik8_oPfUmMVDhA1kgTBFdG_6k08xLhD39G0ksVD_nMtUF4Opo6Zxgkc5Qww==
    [MyHTMLText] => brng:ATmS8Tooc0j2FN5zB8ojmhgNHD-vncvm1ljX8aF7rR6bbsD8pEwyX7BJ3mPg6WEzwyye4uriGskFy30GL9LEKsGs1hs40JJgs6rgwKA=
    [MyVarchar] => brng:zxu2RFNjqDGV0JmxF1WPMtxDKTyfOtvVztXfbnV3aYJAzro7RwHhSs8HhasHvdPOQ2Vxi_oDieRgcE8XeP3nyoF3tYJrJp3Mo9XdYXj2tw==
    [RegularFileID] => 0
    [EncryptedFileID] => 0
    [MyNumberValue] => brng:pKYd8mXDduwhudwWeoE_ByO6IkvVlykVa6h09DTYFdHcb52yA1R5yhTEqQQjz1ndADFRa9WLLM3_e1U8PfPTiP4E
    [MyNumberBlindIndex] => a1de44f9
    [MyNumberLastFourBlindIndex] => addb
    [MyIndexedVarcharValue] => brng:0ow_r7UD3FXYXxq7kjVzA3uY1ThFYfAWxZFAHA0aRoohLfQW_ZBa0Q8w5A3hyLJhT6djM6xR43O_jeEfP-w_fRaH3nXRI5RW7tO78JY=
    [MyIndexedVarcharBlindIndex] => 216d113a
)
*/
        $this->assertNotEquals($varcharValue, $dbRecord['MyVarchar']);
        $this->assertNotEmpty($dbRecord['MyVarchar']);
        $this->assertTrue(EncryptHelper::isEncrypted($dbRecord['MyVarchar']));
    }

    public function testRecordIsEncrypted()
    {
        $model = new Test_EncryptedModel();

        // Let's write some stuff
        $someText = 'some text';
        $model->MyText = $someText . ' text';
        $model->MyHTMLText = '<p>' . $someText . ' html</p>';
        $model->MyVarchar = 'encrypted varchar value';
        $model->MyIndexedVarchar = "some_searchable_value";
        $model->MyNumber = "0123456789";
        // echo '<pre>';
        // print_r(array_keys($model->getChangedFields()));
        // die();
        $id = $model->write();

        $this->assertNotEmpty($id);

        // For the model, its the same
        $this->assertEquals($someText . ' text', $model->MyText);
        $this->assertEquals($someText . ' text', $model->dbObject('MyText')->getValue());
        $this->assertEquals($someText . ' text', $model->getField('MyText'));
        $this->assertEquals('<p>' . $someText . ' html</p>', $model->MyHTMLText);

        // In the db, it's not the same
        $dbRecord = $this->fetchRawData(get_class($model), $model->ID);

        if (!EncryptHelper::isEncrypted($dbRecord['MyIndexedVarcharValue'])) {
            print_r($dbRecord);
        }

        /*
(
    [ID] => 2
    [ClassName] => LeKoala\Encrypt\Test\Test_EncryptedModel
    [LastEdited] => 2020-12-15 10:20:39
    [Created] => 2020-12-15 10:20:39
    [Name] =>
    [MyText] => nacl:yA3XhjUpxE6cS3VMOVI4eqpolP1vRZDYjFySULZiazi9V3HSugC3t8KgImnGV5jP1VzEytVX
    [MyHTMLText] => nacl:F3D33dZ2O7qtlmkX-fiaYwSjAo6RC03aiAWRTkfSJOZikcSfezjwmi9DPJ4EO0hYeVc9faRgA3RmTDajRA==
    [MyVarchar] => nacl:POmdt3mTUSgPJw3ttfi2G9HgHAE4FRX4FQ5CSBicj4JsEwyPwrP-JKYGcs5drFYLId3cMVf6m8daUY7Ao4Cz
    [RegularFileID] => 0
    [EncryptedFileID] => 0
    [MyNumberValue] => nacl:2wFOX_qahm-HmzQPXvcBFhWCG1TaGQgeM7vkebLxRXDfMpzAxhxkExVgBi8caPYrwvA=
    [MyNumberBlindIndex] => 5e0bd888
    [MyNumberLastFourBlindIndex] => 276b
    [MyIndexedVarcharValue] => nacl:BLi-zF02t0Zet-ADP3RT8v5RTsM11WKIyjlJ1EVHIai2HwjxCIq92gfsay5zqiLic14dXtwigb1kI179QQ==
    [MyIndexedVarcharBlindIndex] => 04bb6edd
)
        */
        $text = isset($dbRecord['MyText']) ? $dbRecord['MyText'] : null;
        $this->assertNotEmpty($text);
        $this->assertNotEquals($someText, $text, "Data is not encrypted in the database");
        // Composite fields should work as well
        $this->assertNotEmpty($dbRecord['MyIndexedVarcharValue']);
        $this->assertNotEmpty($dbRecord['MyIndexedVarcharBlindIndex']);

        // Test save into
        $modelFieldsBefore = $model->getQueriedDatabaseFields();
        $model->MyIndexedVarchar = 'new_value';
        $dbObj = $model->dbObject('MyIndexedVarchar');
        // $dbObj->setValue('new_value', $model);
        // $dbObj->saveInto($model);
        $modelFields = $model->getQueriedDatabaseFields();
        // print_r($modelFields);
        $this->assertTrue($dbObj->isChanged());
        $changed = implode(", ", array_keys($model->getChangedFields()));
        $this->assertNotEquals($modelFieldsBefore['MyIndexedVarchar'], $modelFields['MyIndexedVarchar'], "It should not have the same value internally anymore");
        $this->assertTrue($model->isChanged('MyIndexedVarchar'), "Field is not properly marked as changed, only have : " . $changed);
        $this->assertEquals('new_value', $dbObj->getValue());
        $this->assertNotEquals('new_value', $modelFields['MyIndexedVarcharValue'], "Unencrypted value is not set on value field");

        // Somehow this is not working on travis? composite fields don't save encrypted data although it works locally
        $this->assertNotEquals("some_searchable_value", $dbRecord['MyIndexedVarcharValue'], "Data is not encrypted in the database");

        // if we load again ?
        // it should work thanks to our trait
        // by default, data will be loaded encrypted if we don't use the trait and call getField directly
        $model2 = $model::get()->byID($model->ID);
        $this->assertEquals($someText . ' text', $model2->MyText, "Data does not load properly");
        $this->assertEquals('<p>' . $someText . ' html</p>', $model2->MyHTMLText, "Data does not load properly");
    }

    public function testFileEncryption()
    {
        $regularFile = $this->getRegularFile();
        $encryptedFile = $this->getEncryptedFile();

        $this->assertEquals(0, $regularFile->Encrypted);
        $this->assertEquals(1, $encryptedFile->Encrypted);

        // test encryption

        $string = 'Some content';

        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $string);
        rewind($stream);

        $encryptedFile->setFromStream($stream, 'secret.doc');
        $encryptedFile->write();

        $this->assertFalse($encryptedFile->isEncrypted());

        $encryptedFile->encryptFileIfNeeded();

        $this->assertTrue($encryptedFile->isEncrypted());
    }
}
