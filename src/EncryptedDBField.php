<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\TextField;
use ParagonIE\CipherSweet\BlindIndex;
use SilverStripe\ORM\Queries\SQLSelect;
use ParagonIE\CipherSweet\EncryptedField;
use SilverStripe\ORM\FieldType\DBComposite;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

/**
 * Value will be set on parent record through built in getField
 * mechanisms for composite fields
 */
class EncryptedDBField extends DBComposite
{
    const LARGE_INDEX_SIZE = 32;
    const SMALL_INDEX_SIZE = 16;

    /**
     * @config
     * @var int
     */
    private static $output_size = 15;

    /**
     * @config
     * @var int
     */
    private static $domain_size = 127;

    /**
     * @param array
     */
    private static $composite_db = array(
        "Value" => "Varchar(191)",
        "BlindIndex" => 'Varchar(32)',
    );

    /**
     * @var Exception
     */
    protected $encryptionException;

    /**
     * @return Exception
     */
    public function getEncryptionException()
    {
        return $this->encryptionException;
    }

    /**
     * Output size is the number of bits (not bytes) of a blind index.
     * Eg: 4 for a 4 digits year
     * Note: the larger the output size, the smaller the index should be
     * @return int
     */
    public function getOutputSize()
    {
        if (array_key_exists('output_size', $this->options)) {
            $outputSize = $this->options['output_size'];
        } else {
            $outputSize = static::config()->get('output_size');
        }
        return $outputSize;
    }

    /**
     * Input domain is the set of all possible distinct inputs.
     * Eg : 4 digits have 10,000 possible values (10^4). The log (base 2) of 10,000 is 13.2877; you would want to always round up (so 14).
     * @return int
     */
    public function getDomainSize()
    {
        if (array_key_exists('domain_size', $this->options)) {
            $domainSize = $this->options['domain_size'];
        } else {
            $domainSize = static::config()->get('domain_size');
        }
        return $domainSize;
    }

    /**
     * @param int $default
     * @return int
     */
    public function getIndexSize($default = null)
    {
        if (array_key_exists('index_size', $this->options)) {
            return $this->options['index_size'];
        }
        if ($default) {
            return $default;
        }
        return self::LARGE_INDEX_SIZE;
    }

    /**
     * @return string
     */
    public function getValueField()
    {
        return $this->getField('Value');
    }

    /**
     * @return $this
     */
    public function setValueField($value, $markChanged = true)
    {
        return $this->setField('Value', $value, $markChanged);
    }

    /**
     * @return string
     */
    public function getBlindIndexField()
    {
        return $this->getField('BlindIndex');
    }

    /**
     * @return $this
     */
    public function setBlindIndexField($value, $markChanged = true)
    {
        return $this->setField('BlindIndex', $value, $markChanged);
    }

    /**
     * @param CipherSweet $engine
     * @return EncryptedField
     */
    public function getEncryptedField($engine = null)
    {
        if ($engine === null) {
            $engine = EncryptHelper::getCipherSweet();
        }
        $indexSize = $this->getIndexSize(self::LARGE_INDEX_SIZE);
        // fieldName needs to match exact db name for row rotator to work properly
        $encryptedField = (new EncryptedField($engine, $this->tableName, $this->name . "Value"))
            ->addBlindIndex(new BlindIndex($this->name . "BlindIndex", [], $indexSize));
        return $encryptedField;
    }

    /**
     * This is not called anymore, we rely on saveInto for now
     * @link https://github.com/silverstripe/silverstripe-framework/issues/8800
     * @param array $manipulation
     * @return void
     */
    public function writeToManipulation(&$manipulation)
    {
        $encryptedField = $this->getEncryptedField();

        if ($this->value) {
            $dataForStorage = $encryptedField->prepareForStorage($this->value);
            $encryptedValue = $this->prepValueForDB($dataForStorage[0]);
            $blindIndexes = $dataForStorage[1];
        } else {
            $encryptedValue = null;
            $blindIndexes = [];
        }

        $manipulation['fields'][$this->name . 'Value'] = $encryptedValue;
        $manipulation['fields'][$this->name . 'BlindIndex'] = $blindIndexes[$this->name . "BlindIndex"] ?? null;
    }

    /**
     * @param SQLSelect $query
     */
    public function addToQuery(&$query)
    {
        parent::addToQuery($query);
        $query->selectField(sprintf('"%sValue"', $this->name));
        $query->selectField(sprintf('"%sBlindIndex"', $this->name));
    }

    /**
     * Return the blind index value to search in the database
     *
     * @param string $val The unencrypted value
     * @param string $indexSuffix The blind index. Defaults to full index
     * @return string
     */
    public function getSearchValue($val, $indexSuffix = 'BlindIndex')
    {
        if (!$this->tableName && $this->record) {
            $this->tableName = DataObject::getSchema()->tableName(get_class($this->record));
        }
        if (!$this->tableName) {
            throw new Exception("Table name not set for search value. Please set a dataobject.");
        }
        if (!$this->name) {
            throw new Exception("Name not set for search value");
        }
        $field = $this->getEncryptedField();
        $index = $field->getBlindIndex($val, $this->name . $indexSuffix);
        return $index;
    }

    /**
     * Return a ready to use array params for a where clause
     *
     * @param string $val The unencrypted value
     * @param string $indexSuffix The blind index. Defaults to full index
     * @return array
     */
    public function getSearchParams($val, $indexSuffix = null)
    {
        if (!$indexSuffix) {
            $indexSuffix = 'BlindIndex';
        }
        $searchValue = $this->getSearchValue($val, $indexSuffix);
        $blindIndexField = $this->name . $indexSuffix;
        return array($blindIndexField . ' = ?' => $searchValue);
    }

    /**
     * @param string $val The unencrypted value
     * @param string $indexSuffix The blind index. Defaults to full index
     * @return DataObject
     */
    public function fetchRecord($val, $indexSuffix = null)
    {
        if (!$this->record) {
            throw new Exception("No record set for this field");
        }
        $class = get_class($this->record);

        // A blind index can return false positives
        $list = $class::get()->where($this->getSearchParams($val, $indexSuffix));
        return $list->first();
        $name = $this->name;
        foreach ($list as $record) {
            if ($record->dbObject($name)->getValue() == $val) {
                return $record;
            }
        }
        // throw exception if there where matches but none with the right value
        if ($list->count()) {
            throw new Exception($list->count() . " records were found but none matched the right value");
        }
        return false;
    }

    public function setValue($value, $record = null, $markChanged = true)
    {
        if ($markChanged) {
            $this->isChanged = true;
        }

        // When given a dataobject, bind this field to that
        if ($record instanceof DataObject) {
            $this->bindTo($record);
            $record = null;
        }

        // Convert an object to an array
        if ($record && $record instanceof DataObject) {
            $record = $record->getQueriedDatabaseFields();
        }

        // Set the table name if it was not set earlier
        if (!$this->tableName && $record) {
            $this->tableName = DataObject::getSchema()->tableName(get_class($record));
            if (!$this->tableName) {
                throw new Exception("Could not get table name from record from " . gettype($record));
            }
        }

        // Value will store the decrypted value
        if ($value instanceof EncryptedDBField) {
            $this->value = $value->getValue();
        } elseif ($record && isset($record[$this->name . 'Value'])) {
            // In that case, the value come from the database and might be encrypted
            if ($record[$this->name . 'Value']) {
                $encryptedValue = $record[$this->name . 'Value'];
                try {
                    $this->value = $this->getEncryptedField()->decryptValue($encryptedValue);
                } catch (InvalidCiphertextException $ex) {
                    $this->encryptionException = $ex;
                    // rotate backend ?
                    if (EncryptHelper::getAutomaticRotation()) {
                        $encryption = EncryptHelper::getEncryption($encryptedValue);
                        $engine = EncryptHelper::getEngineForEncryption($encryption);
                        $oldEncryptedField = $this->getEncryptedField($engine);
                        $this->value = $oldEncryptedField->decryptValue($encryptedValue);
                    } else {
                        $this->value = $encryptedValue;
                    }
                } catch (Exception $ex) {
                    $this->encryptionException = $ex;
                    // We cannot decrypt
                    $this->value = $this->nullValue();
                }
            } else {
                $this->value = $this->nullValue();
            }
        } elseif (is_array($value)) {
            if (array_key_exists('Value', $value)) {
                $this->value = $value;
            }
        } elseif (is_string($value) || !$value) {
            $this->value = $value;
        } else {
            throw new Exception("Unexcepted value of type " . gettype($value));
        }

        // Forward changes since writeToManipulation are not called
        // $this->setValueField($value, $markChanged);

        return $this;
    }

    /**
     * @return string
     */
    public function Nice($options = array())
    {
        return $this->getValue();
    }

    /**
     * @return boolean
     */
    public function exists()
    {
        return strlen($this->value) > 0;
    }

    /**
     * This is called by getChangedFields() to check if a field is changed
     *
     * @return boolean
     */
    public function isChanged()
    {
        return $this->isChanged;
    }

    /**
     * If we pass a DBField to the setField method, it will
     * trigger this method
     *
     * We save encrypted value on sub fields. They will be collected
     * by write() operation by prepareManipulationTable
     *
     * Currently prepareManipulationTable ignores composite fields
     * so we rely on the sub field mechanisms
     *
     * @param DataObject $dataObject
     * @return void
     */
    public function saveInto($dataObject)
    {
        $encryptedField = $this->getEncryptedField();

        if ($this->value) {
            $dataForStorage = $encryptedField->prepareForStorage($this->value);
            $encryptedValue = $this->prepValueForDB($dataForStorage[0]);
            $blindIndexes = $dataForStorage[1];
        } else {
            $encryptedValue = null;
            $blindIndexes = [];
        }

        // This cause infinite loops
        // $dataObject->setField($this->getName(), $this->value);

        // Encrypt value
        $key = $this->getName() . 'Value';
        $dataObject->setField($key, $encryptedValue);

        // Build blind index
        $key = $this->getName() . 'BlindIndex';
        if (isset($blindIndexes[$key])) {
            $dataObject->setField($key, $blindIndexes[$key]);
        }
    }

    /**
     * @param string $title Optional. Localized title of the generated instance
     * @return FormField
     */
    public function scaffoldFormField($title = null, $params = null)
    {
        $field = TextField::create($this->name);
        return $field;
    }

    /**
     * Returns the string value
     */
    public function __toString()
    {
        return (string) $this->getValue();
    }

    public function scalarValueOnly()
    {
        return false;
    }
}
