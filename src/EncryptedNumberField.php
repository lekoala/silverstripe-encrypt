<?php

namespace LeKoala\Encrypt;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\EncryptedField;
use ParagonIE\CipherSweet\Transformation\LastFourDigits;

/**
 * Value will be set on parent record through built in getField
 * mechanisms for composite fields
 *
 * This can be useful to store phone numbers, national numbers...
 * We keep two indexes:
 * - One with the full record
 * - One with the last 4 numbers (so if your phone number is +00 471 123 456, it will be searchable with 3456)
 */
class EncryptedNumberField extends EncryptedDBField
{
    /**
     * @param array
     */
    private static $composite_db = array(
        "Value" => "Varchar(191)",
        "BlindIndex" => 'Varchar(32)',
        "LastFourBlindIndex" => 'Varchar(16)',
    );

    /**
     * @return string
     */
    public function getLastFourBlindIndexField()
    {
        return $this->getField('LastFourBlindIndex');
    }

    /**
     * @return $this
     */
    public function setLastFourBlindIndexField($value, $markChanged = true)
    {
        return $this->setField('LastFourBlindIndex', $value, $markChanged);
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
        // fieldName needs to match exact db name for row rotator to work properly
        $encryptedField = (new EncryptedField($engine, $this->tableName, $this->name . "Value"))
            // Add a blind index for the "last 4 of SSN":
            ->addBlindIndex(new BlindIndex($this->name . "LastFourBlindIndex", [new LastFourDigits()], 16))
            ->addBlindIndex(new BlindIndex($this->name . "BlindIndex", [], 32));
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
        $manipulation['fields'][$this->name . 'BlindIndex'] = $blindIndexes[$this->name . 'BlindIndex'] ?? null;
        $manipulation['fields'][$this->name . 'LastFourBlindIndex'] = $blindIndexes[$this->name . 'LastFourBlindIndex'] ?? null;
    }

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

        // Encrypt value
        $key = $this->getName() . 'Value';
        $dataObject->setField($key, $encryptedValue);

        // Build blind index
        $key = $this->getName() . 'BlindIndex';
        if (isset($blindIndexes[$key])) {
            $dataObject->setField($key, $blindIndexes[$key]);
        }

        // Build last four blind index
        $key = $this->getName() . 'LastFourBlindIndex';
        if (isset($blindIndexes[$key])) {
            $dataObject->setField($key, $blindIndexes[$key]);
        }
    }

    public function addToQuery(&$query)
    {
        parent::addToQuery($query);
        $query->selectField(sprintf('"%sValue"', $this->name));
        $query->selectField(sprintf('"%sBlindIndex"', $this->name));
        $query->selectField(sprintf('"%sLastFourBlindIndex"', $this->name));
    }
}
