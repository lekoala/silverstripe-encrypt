# SilverStripe Encrypt module

[![Build Status](https://travis-ci.com/lekoala/silverstripe-encrypt.svg?branch=master)](https://travis-ci.com/lekoala/silverstripe-encrypt/)
[![scrutinizer](https://scrutinizer-ci.com/g/lekoala/silverstripe-encrypt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/lekoala/silverstripe-encrypt/)
[![Code coverage](https://codecov.io/gh/lekoala/silverstripe-encrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/lekoala/silverstripe-encrypt)

Easily add encryption to your DataObjects. In a time of GDPR and data leaks, this module helps you to keep your data secure.

This module use [ciphersweet](https://github.com/paragonie/ciphersweet) under the hood to encrypt field data

Thanks to CipherSweet, your encrypted data is searchable!

NOTE: Current version of this module has incompatibilities for composite fields with branch 2. Plan to rotate your values or keep using previous version.

NOTE: Branch 2 of this module is not compatible with previous versions. Please use branch 1 if you need the previous encryption system.

# How to use

First of all, you need to define an encryption key as part of your environment. This can be done like so in your `.env` file:

```
ENCRYPTION_KEY='here_is_my_key'
```

You can generate a key with `EncryptHelper::generateKey()`.

_Make sure your key stays safe and that nobody gets access to it_

# How this module works

You define encrypted field types. By default, everything is stored as text (varchars or texts). This is easier since our encrypted
data is in text format.

```php
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
```

There are two types of fields : simple and indexes (based on Composite field).

The value is encoded before `write` and is decoded when `getField` (or any \_\_get) is called.
This is why we have to use the HasEncryptedFields trait, in order to transparently encode and decode data.
Otherwise, we end up loading encrypted data from the database that is never decoded if you don't
use dbObject calls.

You can of course not use the trait, just keep in mind that your calls to $myObject->myEncryptedField = 'my value'
won't be encoded automatically. But you can most certainly do $myObject->dbObject('myEncryptedField')->setValue('my value') ...
but that's really not convenient in my opinion.
Maybe I'll find some way to avoid overriding the get/set field methods, but I haven't been succesful so far.

# A quick note about indexes

Please note that this module doesn't create indexes automatically for your blind indexes. Since you
are probably going to use them to search your records, it's a good idea to add a database index to avoid
full table scan.

NOTE: blind indexes can have false positives (two records get the same index) and therefore, you cannot
be sure that a given blind index will only return one record.

The function `EncryptHelper::planIndexSizeForClass` will help you to set the right values. It returns
an array that is similar to this:

```php
Array
(
    [min] => 2
    [max] => 32
    [indexes] => 2
    [coincidence_count] => 8589934592
    [coincidence_ratio] => 9.3132257461548E-8
    [estimated_population] => 9223372036854775807
)
```

For each encrypted class, you can set the following config values:

- estimated_population: the number of expected records. 
The higher the population, the higher is the coincidence count (which makes your blind index safe to use)
- output_size and domain_size: these settings are configured at field level.

```php
private static $db = [
    "MyNumber" => EncryptedNumberField::class . '(["output_size" => 4, "domain_size" => 10, "index_size" => 32])',
];
```

# Simple field types

This module provides three fields without blind indexes (if you need a blind index, see next point):

- EncryptedDBText
- EncryptedDBVarchar
- EncryptedDBHTMLText

These fields work exactly like their regular counterpart, except the data is encrypted.

# Searching for data

Thanks to CipherSweet, data is encrypted with a blind index. This blind index can be used to search data if you know the value
or a partial value based on what kind of index you created.

To search using an index, use the EncryptedDBField instance

```php
$singl = singleton(MyModel::class);
$obj = $singl->dbObject('MyEncryptedField');
$searchValue = $obj->getSearchValue($value);
$query = MyModel::get()->where(array('MyEncryptedFieldBlindIndex = ?' => $searchValue));
```

Or use shortcut

```php
$singl = singleton(MyModel::class);
$obj = $singl->dbObject('MyEncryptedField');
$record = $obj->fetchRecord($value);
```

Or even better

```php
$record = MyModel::getByBlindIndex("MyEncryptedField", $value);
$list = MyModel::getAllByBlindIndex("MyEncryptedField", $value);
```

Or use search filter

```php
$record = MyModel::get()->filter('MyEncryptedField:Encrypted', $searchValue)->first();
```

NOTE: the search filter can return false positives, the `getByBlindIndex` method is preferred if you want one record.

It is highly recommended to set indexes on your fields that use blind indexes. The convention is as follows:
{Name}BlindIndex and {Name}LastFourBlindIndex

This module provides two fields with blind indexes:

- EncryptedDBField that holds a single value with a full blind index
- EncryptedNumberField that holds a single value with a full blind index and a blind index for the last 4 digits

You can extend `EncryptedDBField` to add more fields types to suit your use case. Make sure their name starts with "Encrypted".

# Encrypt and decrypt other kind of data

You can also encrypt and decrypt data using a symmetrical key with the helper

```php
$someText = 'some text';
$encrypt = EncryptHelper::encrypt($someText);
$decryptedValue = EncryptHelper::decrypt($encrypt);
```

# Handling encrypted files

This module automatically adds `EncryptedDBFile` extension to your files.

This will add an `Encrypted` field in your table that tracks encryption status

Please note that files are not encrypted by default, you need to call

```php
$myFile->encryptFileIfNeeded();
```

After your uploads, for example.

Even if your files are encrypted, they should not be available in your public folder.

Make sure to review [SilverStripe file security](https://docs.silverstripe.org/en/4/developer_guides/files/file_security/) documentation.
Keeping files .protected and served by a dedicated controller (using `sendDecryptedFile`) is necessary.

# Key rotation

If you need to change algo or key, you will need to rotate encryption.

Rotating algorithm with the same key is easy and built into this module. It happens automatically by default and you
can use the `needsToRotateEncryption` and `rotateEncryption` methods.

If you need to change key, you need to refer it first in the env:

```
OLD_ENCRYPTION_KEY='here_is_my_old_key'
```

Then call `rotateEncryption` like this

```php
$oldKey = EncryptHelper::getOldKey();
$old = EncryptHelper::getEngineForEncryption("nacl", $oldKey);
$result = $model->needsToRotateEncryption($old);
if($result) {
    $result = $model->rotateEncryption($old);
}
```

# Planning index sizes

If you are using blind indexes, you might need to plan their sizes.

It is highly recommended to read the following guide about blind index planning.
https://ciphersweet.paragonie.com/php/blind-index-planning

This modules gives you some tools and defaults that helps you to have
your indexes properly configured.

By default, blind indexes will have a size of 32 chars which allow a large numbers
of records in your table with a really low 

# Using aad

By default, this module will use AAD.

This binds the ciphertext to a specific row, thereby preventing an attacker capable of replacing ciphertexts 
and using legitimate app access to decrypt ciphertexts they wouldn't otherwise have access to.

This setting is controlled by `aad_source` parameter that takes by default the "ID" value.
You can disable aad by setting this to an empty string.

# Todo

- Figure out a way to encrypt the Email field for members
- Fetch key from external service + cache

# Compatibility

Tested with 4.6 to 4.8 but should work with 4.4+

# Maintainer

LeKoala - thomas@lekoala.be
