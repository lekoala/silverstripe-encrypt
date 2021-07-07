SilverStripe Encrypt module
==================
[![Build Status](https://travis-ci.com/lekoala/silverstripe-encrypt.svg?branch=master)](https://travis-ci.com/lekoala/silverstripe-encrypt/)
[![scrutinizer](https://scrutinizer-ci.com/g/lekoala/silverstripe-encrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/lekoala/silverstripe-encrypt/)
[![Code coverage](https://codecov.io/gh/lekoala/silverstripe-encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/lekoala/silverstripe-encrypt)

Easily add encryption to your DataObjects. In a time of GDPR and data leaks, this module helps you to keep your data secure.

This module use [ciphersweet](https://github.com/paragonie/ciphersweet) under the hood to encrypt field data

Thanks to CipherSweet, your encrypted data is searchable!

NOTE: Current version of this module has incompatibilities for composite fields with branch 2. Plan to rotate your values or keep using previous version.
NOTE: Branch 2 of this module is not compatible with previous versions. Please use branch 1 if you need the previous encryption system.

How to use
==================

First of all, you need to define an encryption key as part of your environment. This can be done like so in your `.env` file:

    ENCRYPTION_KEY='here_is_my_key'

You can generate a key with `EncryptHelper::generateKey()`.

*Make sure your key stays safe and that nobody gets access to it*

How this module works
==================

You define encrypted field types. By default, everything is stored as text (varchars or texts). This is easier since our encrypted
data is in text format.

    class MySecureObject extends DataObject
    {
        use HasEncryptedFields;

        private static $db = [
            "Name" => 'Varchar',
            "MyText" => EncryptedDBText::class,
            "MyHTMLText" => EncryptedDBHTMLText::class,
            "MyVarchar" => EncryptedDBVarchar::class,
            "MyNumber" => EncryptedNumberField::class,
            "MyIndexedVarchar" => EncryptedDBField::class,
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

There are two types of fields : simple and indexes (based on Composite field).

The value is encoded before `write` and is decoded when `getField` (or any __get) is called.
This is why we have to use the HasEncryptedFields trait, in order to transparently encode and decode data.
Otherwise, we end up loading encrypted data from the database that is never decoded if you don't
use dbObject calls.

You can of course not use the trait, just keep in mind that your calls to $myObject->myEncryptedField = 'my value'
won't be encoded automatically. But you can most certainly do $myObject->dbObject('myEncryptedField')->setValue('my value') ...
but that's really not convenient in my opinion.
Maybe I'll find some way to avoid overriding the get/set field methods, but I haven't been succesful so far.

Simple field types
==================

This module provides three fields without blind indexes (if you need a blind index, see next point):
- EncryptedDBText
- EncryptedDBVarchar
- EncryptedDBHTMLText

These fields work exactly like their regular counterpart, except the data is encrypted.

Searching for data
==================

Thanks to CipherSweet, data is encrypted with a blind index. This blind index can be used to search data if you know the value
or a partial value based on what kind of index you created.

To search using an index, use the EncryptedDBField instance

    $singl = singleton(MyModel::class);
    $obj = $singl->dbObject('MyEncryptedField');
    $searchValue = $obj->getSearchValue($value);
    $query = MyModel::get()->where(array('MyEncryptedFieldBlindIndex = ?' => $searchValue));

Or use shortcut

    $singl = singleton(MyModel::class);
    $obj = $singl->dbObject('MyEncryptedField');
    $record = $obj->fetchRecord($value);

Or use search filter

     $record = MyModel::get()->filter('MyEncryptedField:Encrypted', $searchValue)->first();

It is highly recommended to set indexes on your fields that use blind indexes. The convention is as follows:
{Name}BlindIndex and {Name}LastFourBlindIndex

This module provides two fields with blind indexes:
- EncryptedDBField that holds a single value with a full blind index
- EncryptedNumberField that holds a single value with a full blind index and a blind index for the last 4 digits

You can extend `EncryptedDBField` to add more fields types to suit your use case.

Encrypt and decrypt other kind of data
==================

You can also encrypt and decrypt data using a symmetrical key with the helper

    $someText = 'some text';
    $encrypt = EncryptHelper::encrypt($someText);
    $decryptedValue = EncryptHelper::decrypt($encrypt);

Handling encrypted files
==================

This module automatically adds `EncryptedDBFile` extension to your files.

This will add an `Encrypted` field in your table that tracks encryption status

Please note that files are not encrypted by default, you need to call

    $myFile->encryptFileIfNeeded();

After your uploads, for example.

Even if your files are encrypted, they should not be available in your public folder.

Make sure to review [SilverStripe file security](https://docs.silverstripe.org/en/4/developer_guides/files/file_security/) documentation.
Keeping files .protected and served by a dedicated controller (using `sendDecryptedFile`) is necessary.

Todo
==================

- Figure out a way to encrypt the Email field for members
- Do not hardcode index sizes
- Fetch key from external service + cache
- Key rotation

Compatibility
==================

Tested with 4.6 but should work with 4.4+

Maintainer
==================
LeKoala - thomas@lekoala.be
