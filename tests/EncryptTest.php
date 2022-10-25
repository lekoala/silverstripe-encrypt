<?php

namespace LeKoala\Encrypt\Test;

use Exception;
use SilverStripe\ORM\DB;
use SilverStripe\Assets\File;
use SilverStripe\ORM\DataList;
use ParagonIE\ConstantTime\Hex;
use SilverStripe\ORM\ArrayList;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use LeKoala\Encrypt\EncryptedFile;
use LeKoala\Encrypt\EncryptHelper;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use Symfony\Component\Yaml\Parser;
use SilverStripe\Security\Security;
use LeKoala\Encrypt\EncryptedDBJson;
use LeKoala\Encrypt\EncryptedDBField;
use LeKoala\Encrypt\MemberKeyProvider;
use ParagonIE\CipherSweet\CipherSweet;
use LeKoala\Encrypt\HasEncryptedFields;
use ParagonIE\CipherSweet\JsonFieldMap;
use SilverStripe\ORM\Queries\SQLSelect;
use SilverStripe\ORM\Queries\SQLUpdate;
use ParagonIE\CipherSweet\KeyProvider\StringProvider;
use ParagonIE\CipherSweet\Contract\MultiTenantSafeBackendInterface;

/**
 * Test for Encrypt
 *;
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
        Test_EncryptionKey::class,
    ];

    public function setUp(): void
    {
        // We need to disable automatic decryption to avoid fixtures being re encrypted with the wrong keys
        EncryptHelper::setAutomaticDecryption(false);
        Environment::setEnv('ENCRYPTION_KEY', '502370dfc69fd6179e1911707e8a5fb798c915900655dea16370d64404be04e5');
        Environment::setEnv('OLD_ENCRYPTION_KEY', '502370dfc69fd6179e1911707e8a5fb798c915900655dea16370d64404be04e4');
        parent::setUp();
        EncryptHelper::setAutomaticDecryption(true);

        // test extension is available
        if (!extension_loaded('sodium')) {
            throw new Exception("You must load sodium extension for this");
        }

        // Generate our test data from scratch
        // Use some old engine first
        // $this->generateData();

        // $this->showRowsFromDb();
        // $this->writeDataFromYml();
    }

    public function tearDown(): void
    {
        parent::tearDown();
    }

    protected function generateData()
    {
        EncryptHelper::clearCipherSweet();
        EncryptHelper::setForcedEncryption("nacl");
        $someText = 'some text';
        $data = [
            'MyText' => $someText . ' text',
            'MyHTMLText' => '<p>' . $someText . ' html</p>',
            'MyVarchar' => 'encrypted varchar value',
            'MyIndexedVarchar' => "some_searchable_value",
            'MyNumber' => "0123456789",
        ];
        $record = Test_EncryptedModel::get()->filter('Name', 'demo')->first();
        foreach ($data as $k => $v) {
            $record->$k = $v;
        }
        $record->write();
        EncryptHelper::clearCipherSweet();
        $record = Test_EncryptedModel::get()->filter('Name', 'demo3')->first();
        foreach ($data as $k => $v) {
            $record->$k = $v;
        }
        $record->write();
        // use regular engine
        EncryptHelper::clearCipherSweet();
        EncryptHelper::setForcedEncryption(null);
        $record = Test_EncryptedModel::get()->filter('Name', 'demo2')->first();
        foreach ($data as $k => $v) {
            $record->$k = $v;
        }
        $record->write();
    }

    protected function showRowsFromDb()
    {
        $result = DB::query("SELECT * FROM EncryptedModel");
        echo '<pre>' . "\n";
        // print_r(iterator_to_array($result));
        foreach ($result as $row) {
            $this->showAsYml($row);
        }
        die();
    }

    protected function writeDataFromYml()
    {
        $ymlParser = new Parser;
        $ymlData = $ymlParser->parseFile(__DIR__ . '/EncryptTest.yml');

        foreach ($ymlData["LeKoala\\Encrypt\\Test\\Test_EncryptedModel"] as $name => $data) {
            unset($data['Member']);
            $update = new SQLUpdate("EncryptedModel", $data, ["Name" => $data['Name']]);
            $update->execute();
        }
    }

    protected function showAsYml($row)
    {
        $fields = [
            'Name', 'MyText', 'MyHTMLText', 'MyVarchar',
            'MyNumberValue', 'MyNumberBlindIndex', 'MyNumberLastFourBlindIndex',
            'MyIndexedVarcharValue', 'MyIndexedVarcharBlindIndex'
        ];
        echo "  " . $row['Name'] . ":\n";
        foreach ($row as $k => $v) {
            if (!in_array($k, $fields)) {
                continue;
            }
            echo "    $k: '$v'\n";
        }
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
     * @return Test_EncryptedModel
     */
    public function getAdminTestModel()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'admin_record');
    }

    /**
     * @return Test_EncryptedModel
     */
    public function getUser1TestModel()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'user1_record');
    }

    /**
     * @return Test_EncryptedModel
     */
    public function getUser2TestModel()
    {
        return $this->objFromFixture(Test_EncryptedModel::class, 'user2_record');
    }

    /**
     * @return Member
     */
    public function getAdminMember()
    {
        return $this->objFromFixture(Member::class, 'admin');
    }

    /**
     * @return Member
     */
    public function getUser1Member()
    {
        return $this->objFromFixture(Member::class, 'user1');
    }

    /**
     * @return Member
     */
    public function getUser2Member()
    {
        return $this->objFromFixture(Member::class, 'user2');
    }

    /**
     * @return DataList|Member[]
     */
    public function getAllMembers()
    {
        return new ArrayList([
            $this->getAdminMember(),
            $this->getUser1Member(),
            $this->getUser2Member(),
        ]);
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
     * @return EncryptedFile
     */
    public function getEncryptedFile2()
    {
        // Figure out how to do this properly in yml
        $record = $this->objFromFixture(File::class, 'encrypted2');
        $file = new EncryptedFile($record->toMap());
        return $file;
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

        /** @var EncryptedDBField $obj  */
        $obj = $singl->dbObject('MyIndexedVarchar');
        $record = $obj->fetchRecord('some_searchable_value');

        // echo '<pre>';print_r("From test: " . $record->MyIndexedVarchar);die();
        $this->assertNotEmpty($record);
        $this->assertEquals("some text text", $record->MyText);
        $this->assertEquals("some_searchable_value", $record->MyIndexedVarchar);
        $this->assertEquals("some_searchable_value", $record->dbObject('MyIndexedVarchar')->getValue());

        // Also search our super getter method
        $recordAlt = Test_EncryptedModel::getByBlindIndex('MyIndexedVarchar', 'some_searchable_value');
        $this->assertNotEmpty($record);
        $this->assertEquals($recordAlt->ID, $record->ID);

        // Can we get a list ?
        $list = Test_EncryptedModel::getAllByBlindIndex('MyIndexedVarchar', 'some_searchable_value');
        $this->assertInstanceOf(DataList::class, $list);

        $record = $obj->fetchRecord('some_unset_value');
        $this->assertEmpty($record);

        // Let's try our four digits index
        $obj = $singl->dbObject('MyNumber');
        $record = $obj->fetchRecord('6789', 'LastFourBlindIndex');
        $searchValue = $obj->getSearchValue('6789', 'LastFourBlindIndex');
        // $searchParams = $obj->getSearchParams('6789', 'LastFourBlindIndex');
        // print_r($searchParams);
        $this->assertNotEmpty($record, "Nothing found for $searchValue");
        $this->assertEquals("0123456789", $record->MyNumber);
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

    public function testCompositeOptions()
    {
        $model = $this->getTestModel();

        /** @var EncryptedDBField $myNumber */
        $myNumber = $model->dbObject('MyNumber');

        $this->assertEquals(10, $myNumber->getDomainSize());
        $this->assertEquals(4, $myNumber->getOutputSize());
        $this->assertEquals(EncryptedDBField::LARGE_INDEX_SIZE, $myNumber->getIndexSize());

        /** @var EncryptedDBField $MyIndexedVarchar */
        $MyIndexedVarchar = $model->dbObject('MyIndexedVarchar');

        // Default config values
        $this->assertEquals(EncryptHelper::DEFAULT_DOMAIN_SIZE, $MyIndexedVarchar->getDomainSize());
        $this->assertEquals(EncryptHelper::DEFAULT_OUTPUT_SIZE, $MyIndexedVarchar->getOutputSize());
        $this->assertEquals(EncryptedDBField::LARGE_INDEX_SIZE, $MyIndexedVarchar->getIndexSize());
    }

    public function testIndexPlanner()
    {
        $sizes = EncryptHelper::planIndexSizesForClass(Test_EncryptedModel::class);
        $this->assertNotEmpty($sizes);
        $this->assertArrayHasKey("min", $sizes);
        $this->assertArrayHasKey("max", $sizes);
        $this->assertArrayHasKey("indexes", $sizes);
        $this->assertArrayHasKey("estimated_population", $sizes);
        $this->assertArrayHasKey("coincidence_count", $sizes);
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

        // automatically rotated fields store an exception
        $this->assertNotEmpty($model->dbObject("MyVarchar")->getEncryptionException());

        // get value
        $this->assertEquals($varcharValue, $model->dbObject('MyVarchar')->getValue());
        // encrypted fields work transparently when using trait
        $this->assertEquals($varcharValue, $model->MyVarchar);

        // since dbobject cache can be cleared, exception is gone
        $this->assertEmpty($model->dbObject("MyVarchar")->getEncryptionException());


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

        // echo "*** start \n";
        // Let's write some stuff
        $someText = 'some text';
        $model->MyText = $someText . ' text';
        $model->MyHTMLText = '<p>' . $someText . ' html</p>';
        $model->MyVarchar = 'encrypted varchar value';
        $model->MyIndexedVarchar = "some_searchable_value";
        $model->MyNumber = "0123456789";
        // All fields are marked as changed, including "hidden" fields
        // MyNumber will mark as changed MyNumber, MyNumberValue, MuNumberBlindIndex, MyNumberLastFourBlindIndex
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
        $encryptedFile2 = $this->getEncryptedFile2();

        $this->assertEquals(0, $regularFile->Encrypted);

        // Even if we marked it as 1 in the yml, reflect actual value
        $encryptedFile->updateEncryptionStatus();

        $this->assertEquals(0, $encryptedFile->Encrypted, "The encrypted flag was not reset");
        $this->assertEquals(0, $encryptedFile2->Encrypted);

        // test encryption
        $string = 'Some content';
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $string);
        rewind($stream);
        $encryptedFile->setFromStream($stream, 'secret.doc');
        $encryptedFile->write();
        $encryptedFile2->setFromStream($stream, 'secret.doc');
        $encryptedFile2->write();

        $this->assertFalse($encryptedFile->isEncrypted());
        // It is automatically encrypted
        $this->assertTrue($encryptedFile2->isEncrypted());

        $encryptedFile->encryptFileIfNeeded();

        $this->assertTrue($encryptedFile->isEncrypted());
        $this->assertTrue($encryptedFile->Encrypted);

        // still encrypted?
        $encryptedFile->encryptFileIfNeeded();
        $this->assertTrue($encryptedFile->isEncrypted());
        $this->assertTrue($encryptedFile->Encrypted);

        // set something new
        $string = 'Some content';
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $string);
        rewind($stream);
        $encryptedFile->setFromStream($stream, 'secret.doc');
        $encryptedFile->write();
        $encryptedFile2->setFromStream($stream, 'secret.doc');
        $encryptedFile2->write();

        // we need to update manually
        $encryptedFile->updateEncryptionStatus();

        // It is not encrypted nor marked as such
        $this->assertFalse($encryptedFile->isEncrypted());
        $this->assertFalse($encryptedFile->Encrypted);
        // Ir was automatically encrypted again
        $this->assertTrue($encryptedFile2->isEncrypted());
        $this->assertTrue($encryptedFile2->Encrypted);

        // No file => no encryption
        $encryptedFile2->deleteFile();
        $this->assertFalse($encryptedFile->isEncrypted());
    }

    /**
     * @group only
     */
    public function testMessageEncryption()
    {
        $admin = $this->getAdminMember();
        $user1 = $this->getUser1Member();

        $adminKeys = Test_EncryptionKey::getKeyPair($admin->ID);
        $user1Keys = Test_EncryptionKey::getKeyPair($user1->ID);

        $this->assertArrayHasKey("public", $adminKeys);
        $this->assertArrayHasKey("secret", $adminKeys);
        $this->assertArrayHasKey("public", $user1Keys);
        $this->assertArrayHasKey("secret", $user1Keys);

        // $pairs = sodium_crypto_box_keypair();
        // $adminKeys['secret'] = sodium_crypto_box_secretkey($pairs);
        // $adminKeys['public'] = sodium_crypto_box_publickey($pairs);

        // $pairs = sodium_crypto_box_keypair();
        // $user1Keys['secret'] = sodium_crypto_box_secretkey($pairs);
        // $user1Keys['public'] = sodium_crypto_box_publickey($pairs);

        // $adminKeys['secret'] = Hex::encode($adminKeys['secret']);
        // $adminKeys['public'] = Hex::encode($adminKeys['public']);
        // $user1Keys['secret'] = Hex::encode($user1Keys['secret']);
        // $user1Keys['public'] = Hex::encode($user1Keys['public']);

        // $adminKeys['secret'] = Hex::decode($adminKeys['secret']);
        // $adminKeys['public'] = Hex::decode($adminKeys['public']);
        // $user1Keys['secret'] = Hex::decode($user1Keys['secret']);
        // $user1Keys['public'] = Hex::decode($user1Keys['public']);

        $message = 'hello';
        // 24
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $encryption_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($adminKeys['secret'], $user1Keys['public']);
        $encrypted = sodium_crypto_box($message, $nonce, $encryption_key);
        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($message, $encrypted);

        // Revert keys to decrypt
        $decryption_key = sodium_crypto_box_keypair_from_secretkey_and_publickey($user1Keys['secret'], $adminKeys['public']);
        $decrypted = sodium_crypto_box_open($encrypted, $nonce, $decryption_key);
        $this->assertNotEmpty($decrypted);
        $this->assertEquals($message, $decrypted);
    }

    protected function getMultiTenantProvider()
    {
        $members = $this->getAllMembers();
        $tenants = [];
        foreach ($members as $member) {
            // You can also use the secret key from a keypair
            // $key = Test_EncryptionKey::getForMember($member->ID);
            $keyPair = Test_EncryptionKey::getKeyPair($member->ID);
            if ($keyPair) {
                $tenants[$member->ID] = new StringProvider($keyPair['secret']);
                // $tenants[$member->ID] = new StringProvider($key);
            }
        }
        $provider = new MemberKeyProvider($tenants);
        return $provider;
    }

    /**
     * @group multi-tenant
     * @group only
     */
    public function testMultiTenantProvider()
    {
        // echo '<pre>';
        // print_r(EncryptHelper::generateKeyPair());
        // die();
        $admin = $this->getAdminMember();
        $user1 = $this->getUser1Member();
        $user2 = $this->getUser2Member();

        $adminModel = $this->getAdminTestModel();
        $user1Model = $this->getUser1TestModel();
        $user2Model = $this->getUser2TestModel();

        $provider = $this->getMultiTenantProvider();

        Security::setCurrentUser($admin);
        EncryptHelper::clearCipherSweet();
        $cs = EncryptHelper::getCipherSweet($provider);

        $this->assertInstanceOf(MultiTenantSafeBackendInterface::class, $cs->getBackend());

        $string = "my content";
        $record = new Test_EncryptedModel();
        // $record = Test_EncryptedModel::get()->filter('ID', $user2Model->ID)->first();
        $record->MyText = $string;
        // We need to set active tenant ourselves because orm records fields one by one
        // it doesn't go through injectMetadata
        $record->MemberID = Security::getCurrentUser()->ID ?? 0;
        $record->write();

        // echo '<pre>';
        // print_r($this->fetchRawData(Test_EncryptedModel::class, $record->ID));
        // die();

        $freshRecord = Test_EncryptedModel::get()->filter('ID', $record->ID)->first();

        $this->assertEquals($admin->ID, Security::getCurrentUser()->ID, "Make sure the right member is logged in");
        // He can decode
        $this->assertEquals($string, $freshRecord->MyText);

        // He can also decode his content from the db
        $adminRecord = Test_EncryptedModel::get()->filter('ID', $adminModel->ID)->first();
        // echo '<pre>';print_r($adminRecord);die();
        $this->assertEquals($string, $adminRecord->MyText);

        // He cannot decode
        Security::setCurrentUser($user1);
        // We don't need to set active tenant because our MemberKeyProvider reads currentUser automatically
        // $provider->setActiveTenant($user1->ID);
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $record->ID)->first();
        $this->assertNotEquals($string, $freshRecord->MyText);

        // Test tenant from row
        $this->assertEquals($admin->ID, $cs->getTenantFromRow($adminModel->toMap()));
        $this->assertEquals($user1->ID, $cs->getTenantFromRow($user1Model->toMap()));
        $this->assertEquals($user2->ID, $cs->getTenantFromRow($user2Model->toMap()));

        // Current user can decode what he can
        Security::setCurrentUser($admin);
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $adminModel->ID)->first();
        $this->assertEquals($string, $freshRecord->MyText, "Invalid content for admin model #{$adminModel->ID}");
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $user2Model->ID)->first();
        $this->assertNotEquals($string, $freshRecord->MyText, "Invalid content for user2 model #{$user2Model->ID}");

        // Thanks to getTenantFromRow we should be able to rotate encryption
        // rotate from admin to user2
        Security::setCurrentUser($user2);
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $adminModel->ID)->first();
        $freshRecord->MemberID = $user2->ID;
        $freshRecord->write();
        $this->assertNotEquals($string, $freshRecord->MyText);
        // We can keep the same provider but we need to clone it and change the active tenant
        $cs->setActiveTenant($user2->ID);

        // clone will not deep clone the key provider with the active tenant
        // $old = clone $cs;
        $clonedProvider = clone $provider;
        $clonedProvider->setForcedTenant($admin->ID);
        $old = EncryptHelper::getEngineWithProvider(EncryptHelper::getBackendForEncryption("brng"), $clonedProvider);

        $freshRecord->rotateEncryption($old);
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $adminModel->ID)->first();
        $this->assertEquals($string, $freshRecord->MyText);

        // Admin can't read anymore, don't forget to refresh record from db
        Security::setCurrentUser($admin);
        $freshRecord = Test_EncryptedModel::get()->filter('ID', $adminModel->ID)->first();
        $this->assertNotEquals($string, $freshRecord->MyText);

        // Cleanup
        EncryptHelper::clearCipherSweet();
    }

    public function testJsonField()
    {
        $model = $this->getTestModel();

        $longstring = str_repeat("lorem ipsum loquor", 100);
        $array = [];
        foreach (range(1, 100) as $i) {
            $array["key_$i"] = $longstring . $i;
        }

        $model->MyJson = $array;
        $model->write();

        $freshRecord = Test_EncryptedModel::get()->filter('ID', $model->ID)->first();

        $this->assertEquals(json_encode($array), $freshRecord->MyJson);
        $this->assertEquals(json_decode(json_encode($array)), $freshRecord->dbObject('MyJson')->decode());
        $this->assertEquals($array, $freshRecord->dbObject('MyJson')->toArray());
        $this->assertEquals($array, $freshRecord->dbObject('MyJson')->decodeArray());
        $this->assertEquals($model->dbObject('MyJson')->toArray(), $freshRecord->dbObject('MyJson')->toArray());
    }

    public function testEncryptedJsonField()
    {
        $model = $this->getTestModel();

        /** @var EncryptedDBJson $field */
        $field = $model->dbObject('MyEncryptedJson');

        $map = (new JsonFieldMap())
            ->addTextField('name')
            ->addBooleanField('active')
            ->addIntegerField('age');

        $definition = EncryptHelper::convertJsonMapToDefinition($map);
        $this->assertIsString($definition);

        $encryptedJsonField = $field->getEncryptedJsonField();

        $data = [
            'name' => 'test name',
            'active' => true,
            'age' => 42,
            'not_encrypted' => "this is not encrypted"
        ];

        $aad = (string)$model->ID;
        $encryptedJsonData = $encryptedJsonField->encryptJson($data, $aad);

        $this->assertFalse(EncryptHelper::isJsonEncrypted($data));
        $this->assertTrue(EncryptHelper::isJsonEncrypted($encryptedJsonData));

        $decoded = json_decode($encryptedJsonData, JSON_OBJECT_AS_ARRAY);

        // it is properly encrypted if required
        $this->assertEquals($data['not_encrypted'], $decoded['not_encrypted']);
        $this->assertNotEquals($data['name'], $decoded['name']);

        // we can write
        $model->MyEncryptedJson = $data;
        $model->write();

        $dbData = DB::query("SELECT MyEncryptedJson FROM EncryptedModel WHERE ID = " . $model->ID)->value();
        $decodedDbData = json_decode($dbData, JSON_OBJECT_AS_ARRAY);

        // data is properly stored with partially encrypted json
        $this->assertNotNull($decodedDbData, "got $dbData");
        $this->assertEquals($data['not_encrypted'], $decodedDbData['not_encrypted']);
        $this->assertNotEquals($data['name'], $decodedDbData['name']);

        $freshRecord = Test_EncryptedModel::get()->filter('ID', $model->ID)->first();
        $freshValue = $freshRecord->dbObject('MyEncryptedJson')->toArray();

        // It is decoded transparently
        $this->assertEquals($data, $freshValue);
    }

    public function testFashHash()
    {
        $model = $this->getTestModel();

        /** @var EncryptedDBField $encrField */
        $encrField = $model->dbObject('MyIndexedVarchar');

        $value = (string)$model->MyIndexedVarchar;
        $bi = $model->MyIndexedVarcharBlindIndex;

        $aad = '';

        $t = microtime(true);
        $slowBi = $encrField->getEncryptedField(null, false)->prepareForStorage($value, $aad);
        $slowBi2 = $encrField->getEncryptedField(null, false)->prepareForStorage($value, $aad);
        $et = microtime(true) - $t;

        $t2 = microtime(true);
        $fastBi = $encrField->getEncryptedField(null, true)->prepareForStorage($value, $aad);
        $fastBi2 = $encrField->getEncryptedField(null, true)->prepareForStorage($value, $aad);
        $et2 = microtime(true) - $t2;

        // Values are not equals, but blind indexes are
        $this->assertNotEquals($slowBi2[0], $slowBi[0]);
        $this->assertEquals($slowBi2[1]['MyIndexedVarcharBlindIndex'], $slowBi[1]['MyIndexedVarcharBlindIndex']);
        $this->assertEquals($bi, $slowBi[1]['MyIndexedVarcharBlindIndex']);
        $this->assertNotEquals($fastBi2[0], $fastBi[0]);
        $this->assertEquals($fastBi2[1]['MyIndexedVarcharBlindIndex'], $fastBi[1]['MyIndexedVarcharBlindIndex']);

        // Slow indexes are not the same as fast indexes
        $this->assertNotEquals($fastBi[1]['MyIndexedVarcharBlindIndex'], $slowBi[1]['MyIndexedVarcharBlindIndex']);
        $this->assertNotEquals($fastBi2[1]['MyIndexedVarcharBlindIndex'], $slowBi2[1]['MyIndexedVarcharBlindIndex']);

        // It is faster to generate fast indexes
        // $et2 = 0.0004119873046875
        // $et = 0.0683131217956543

        $this->assertTrue($et2 <= $et);

        // We can convert and keep stored values readable

        $result = EncryptHelper::convertHashType($model, 'MyIndexedVarchar');
        $this->assertTrue($result);

        $freshRecord = Test_EncryptedModel::get()->filter('ID', $model->ID)->first();
        $freshValue = (string)$freshRecord->MyIndexedVarchar;
        $this->assertEquals($value, $freshValue);

        // We can find it using new hash
        /** @var EncryptedDBField $freshEncrField */
        $freshEncrField = $freshRecord->dbObject('MyIndexedVarchar');

        $blindIndex = $freshEncrField->getEncryptedField(null, true)->getBlindIndex($freshValue, 'MyIndexedVarcharBlindIndex');
        $freshRecord2 = Test_EncryptedModel::get()->filter('MyIndexedVarcharBlindIndex', $blindIndex)->first();
        $this->assertEquals($freshRecord2->ID, $freshRecord->ID);
    }
}
