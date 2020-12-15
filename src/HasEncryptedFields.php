<?php

namespace LeKoala\Encrypt;

use SilverStripe\Core\Injector\Injector;

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
 */
trait HasEncryptedFields
{
    /**
     * Extend getField to support retrieving encrypted value transparently
     * @param string $field The name of the field
     * @return mixed The field value
     */
    public function getEncryptedField($field)
    {
        // If it's an encrypted field
        if ($this->hasEncryptedField($field)) {
            $fieldObj = $this->dbObject($field);
            // Set decrypted value directly on the record for later use
            $this->record[$field] = $fieldObj->getValue();
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
            $schema = static::getSchema();

            // In case of composite fields, return the DBField object
            if ($schema->compositeField(static::class, $field)) {
                $fieldObj = $this->dbObject($field);
                $fieldObj->setValue($val);
                // Keep a reference for isChange checks
                // TODO: check if useful?
                $this->record[$field] = $fieldObj;
                // Proceed with DBField instance, that will call saveInto
                // and call this method again for distinct fields
                $val = $fieldObj;
            }
        }
        return parent::setField($field, $val);
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
