<?php

namespace LeKoala\Encrypt;

use Exception;
use SodiumException;
use SilverStripe\ORM\DataObject;
use ParagonIE\CipherSweet\CipherSweet;
use SilverStripe\ORM\DataObjectSchema;
use ParagonIE\CipherSweet\EncryptedRow;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\ORM\Queries\SQLSelect;
use SilverStripe\ORM\Queries\SQLUpdate;
use ParagonIE\CipherSweet\KeyRotation\RowRotator;
use ParagonIE\CipherSweet\Exception\InvalidCiphertextException;

/**
 * This trait helps to override the default getField method in order to return
 * the value of a field directly instead of the db object instance
 *
 * Simply define this in your code
 *
 * public function getField($field)
 * {
 *    return $this->getEncryptedField($field);
 * }
 *
 * public function setField($fieldName, $val)
 * {
 *     return $this->setEncryptedField($fieldName, $val);
 * }
 *
 * @property array $record
 * @method DBField dbObject()
 */
trait HasEncryptedFields
{
    /**
     * This value will return exactly one record, taking care of false positives
     *
     * @param string $field
     * @param string $value
     * @return $this
     */
    public static function getByBlindIndex($field, $value)
    {
        /** @var DataObject $singl  */
        $singl = singleton(get_called_class());
        /** @var EncryptedDBField $obj  */
        $obj = $singl->dbObject($field);
        return $obj->fetchRecord($value);
    }

    /**
     * Check if the record needs to be reencrypted with a new key or algo
     * @param CipherSweet $old
     * @return bool
     */
    public function needsToRotateEncryption(CipherSweet $old)
    {
        $class = get_class($this);
        $tableName = DataObject::getSchema()->tableName($class);
        $columnIdentifier = DataObject::getSchema()->sqlColumnForField($class, 'ID');

        $new = EncryptHelper::getCipherSweet();

        $oldRow = $this->getEncryptedRow($old);
        $newRow = $this->getEncryptedRow($new);

        $rotator = new RowRotator($oldRow, $newRow);
        $query = new SQLSelect("*", $tableName, [$columnIdentifier => $this->ID]);
        $ciphertext = $query->execute()->first();
        $ciphertext = EncryptHelper::removeNulls($ciphertext);
        if ($rotator->needsReEncrypt($ciphertext)) {
            return true;
        }
        return false;
    }

    /**
     * Rotate encryption with current engine without using orm
     * @param CipherSweet $old
     * @return bool
     * @throws SodiumException
     * @throws InvalidCiphertextException
     */
    public function rotateEncryption(CipherSweet $old)
    {
        $class = get_class($this);
        $tableName = DataObject::getSchema()->tableName($class);
        $columnIdentifier = DataObject::getSchema()->sqlColumnForField($class, 'ID');

        $new = EncryptHelper::getCipherSweet();

        $oldRow = $this->getEncryptedRow($old);
        $newRow = $this->getEncryptedRow($new);

        $rotator = new RowRotator($oldRow, $newRow);
        $encryptedFields = array_keys(EncryptHelper::getEncryptedFields($class, true));
        $query = new SQLSelect($encryptedFields, $tableName, [$columnIdentifier => $this->ID]);
        $ciphertext = $query->execute()->first();
        $ciphertext = EncryptHelper::removeNulls($ciphertext);
        $indices = null;
        if ($rotator->needsReEncrypt($ciphertext)) {
            list($ciphertext, $indices) = $rotator->prepareForUpdate($ciphertext);
            $assignment = $ciphertext;
            foreach ($indices as $name => $arr) {
                $assignment[$name] = $arr["value"];
            }
            $update = new SQLUpdate($tableName, $assignment, ["ID" => $this->ID]);
            $update->execute();
            return true;
        }
        return false;
    }

    /**
     * @param CipherSweet $engine
     * @return EncryptedRow
     */
    public function getEncryptedRow(CipherSweet $engine = null)
    {
        if ($engine === null) {
            $engine = EncryptHelper::getCipherSweet();
        }
        $class = get_class($this);
        $tableName = DataObject::getSchema()->tableName($class);
        $encryptedRow = new EncryptedRow($engine, $tableName);
        $encryptedFields = array_keys(EncryptHelper::getEncryptedFields($class));
        foreach ($encryptedFields as $field) {
            /** @var EncryptedField $encryptedField */
            $encryptedField = $this->dbObject($field)->getEncryptedField($engine);
            $blindIndexes = $encryptedField->getBlindIndexObjects();
            if (count($blindIndexes)) {
                $encryptedRow->addField($field . "Value");
                foreach ($encryptedField->getBlindIndexObjects() as $blindIndex) {
                    $encryptedRow->addBlindIndex($field . "Value", $blindIndex);
                }
            } else {
                $encryptedRow->addField($field);
            }
        }
        return $encryptedRow;
    }

    /**
     * Extend getField to support retrieving encrypted value transparently
     * @param string $field The name of the field
     * @return mixed The field value
     */
    public function getEncryptedField($field)
    {
        // We cannot check directly $this->record[$field] because it may
        // contain encrypted value that needs to be decoded first

        // If it's an encrypted field
        if ($this->hasEncryptedField($field)) {
            $fieldObj = $this->dbObject($field);
            // Set decrypted value directly on the record for later use
            $this->record[$field] = $fieldObj->getValue();
            return $this->record[$field];
        }
        return parent::getField($field);
    }

    /**
     * Extend setField to support setting encrypted value transparently
     * @param string $field
     * @param mixed $val
     * @return $this
     */
    public function setEncryptedField($field, $val)
    {
        // If it's an encrypted field
        if ($this->hasEncryptedField($field) && $val && is_scalar($val)) {
            /** @var DataObjectSchema $schema  */
            $schema = static::getSchema();

            // In case of composite fields, return the DBField object
            // Eg: if we call MyIndexedVarchar instead of MyIndexedVarcharValue
            $compositeClass = $schema->compositeField(static::class, $field);
            if ($compositeClass) {
                $fieldObj = $this->dbObject($field);
                $fieldObj->setValue($val);
                // Keep a reference for isChange checks
                $this->record[$field] = $fieldObj;
                // Proceed with DBField instance, that will call saveInto
                // and call this method again for distinct fields
                $val = $fieldObj;
            }
        }
        parent::setField($field, $val);
        return $this;
    }

    /**
     * @param string $field
     * @return boolean
     */
    public function hasEncryptedField($field)
    {
        return EncryptHelper::isEncryptedField(get_class($this), $field);
    }
}
