<?php

namespace LeKoala\Encrypt;

use SilverStripe\ORM\DataObject;
use SilverStripe\Forms\HiddenField;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\JsonFieldMap;
use ParagonIE\CipherSweet\EncryptedJsonField;
use SilverStripe\Forms\FormField;
use SilverStripe\Model\ModelData;

/**
 * A simple extension over EncryptedDBText that supports json
 * as a datastructure
 * The data is stored in a text field
 *
 * If you want to access array stuff, you need to use
 * $model->dbObject('myField')->toArray() or any other method
 *
 * This field is a great way to store serialized encrypted data
 */
class EncryptedDBJson extends EncryptedDBText
{
    /**
     * @return ?string
     */
    public function getJsonMap()
    {
        if (array_key_exists('map', $this->options)) {
            return $this->options['map'];
        }
        return null;
    }

    /**
     * We cannot search on json fields
     *
     * @param string $title
     * @return HiddenField
     */
    public function scaffoldSearchField(?string $title = null): ?FormField
    {
        return HiddenField::create($this->getName());
    }

    /**
     * Json data is not easily displayed
     *
     * @param string $title
     * @param array<mixed> $params
     * @return HiddenField
     */
    public function scaffoldFormField(?string $title = null, array $params = []): ?FormField
    {
        return HiddenField::create($this->getName());
    }

    /**
     * @return mixed
     */
    public function decode()
    {
        if (!$this->value) {
            return false;
        }
        return json_decode($this->value);
    }

    /**
     * @return array<string,mixed>
     */
    public function decodeArray()
    {
        if (!$this->value) {
            return [];
        }
        return json_decode($this->value, true);
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray()
    {
        return $this->decodeArray();
    }

    /**
     * @return string
     */
    public function pretty()
    {
        if (!$this->value) {
            return '';
        }
        $decoded = json_decode($this->value);
        if (!$decoded) {
            return json_last_error_msg();
        }
        $result = json_encode($decoded, JSON_PRETTY_PRINT);
        if (!$result) {
            return json_last_error_msg();
        }
        return $result;
    }

    public function saveInto(ModelData $model): void
    {
        if ($this->value && is_array($this->value)) {
            $this->value = json_encode($this->value);
        }
        parent::saveInto($model);
    }

    /**
     * Add a value
     *
     * @link https://stackoverflow.com/questions/7851590/array-set-value-using-dot-notation
     * @param string|array<string> $key
     * @param string $value
     * @return $this
     */
    public function addValue($key, $value)
    {
        $currentValue = $this->decodeArray();

        if (!is_array($key)) {
            $key = [$key];
        }
        $arr = &$currentValue;
        foreach ($key as $idx) {
            if (!isset($arr[$idx])) {
                $arr[$idx] = [];
            }
            $arr = &$arr[$idx];
        }
        $arr = $value;
        return $this->setValue($currentValue);
    }

    /**
     * Internally, the value is always a json string
     *
     * @param mixed $value
     * @param DataObject $record
     * @param boolean $markChanged
     * @return $this
     */
    public function setValue(mixed $value, null|array|ModelData $record = null, bool $markChanged = true): static
    {
        $this->setEncryptionAad($record);

        // Not supported, we need decrypted values for methods to work properly
        // Return early if we keep encrypted value in memory
        // if (!EncryptHelper::getAutomaticDecryption()) {
        //     $this->value = $value;
        //     return $this;
        // }

        // Decrypt first if needed
        if ($this->getJsonMap() && $value && is_string($value)) {
            if (EncryptHelper::isJsonEncrypted($value)) {
                $aad = $this->encryptionAad;
                $value = json_encode($this->getEncryptedJsonField()->decryptJson($value, $aad));
            }
        }
        // Internally, we use a string
        if (is_array($value)) {
            $value = json_encode($value);
        }

        return parent::setValue($value, $record, $markChanged);
    }

    public function prepValueForDB(mixed $value): array|string|null
    {
        // We need an array to encrypt
        if ($this->getJsonMap() && $value && is_string($value)) {
            $value = $this->toArray();
        }
        if (is_array($value)) {
            if ($this->getJsonMap()) {
                $aad = $this->encryptionAad;
                $value = $this->getEncryptedJsonField()->encryptJson($value, $aad);
                return $value; // return early
            } else {
                $value = json_encode($value);
                if ($value === false) {
                    $value = '';
                }
            }
        }
        return parent::prepValueForDB($value);
    }

    /**
     * We return false because we can accept array and convert it to string
     */
    public function scalarValueOnly(): bool
    {
        return false;
    }

    /**
     * @param CipherSweet $engine
     * @param JsonFieldMap $map
     * @return EncryptedJsonField
     */
    public function getEncryptedJsonField($engine = null, $map = null)
    {
        if ($engine === null) {
            $engine = EncryptHelper::getCipherSweet();
        }
        if ($map === null) {
            $mapString = $this->getJsonMap();
            $map = JsonFieldMap::fromString($mapString);
        }
        $encryptedField = EncryptedJsonField::create($engine, $map, $this->tableName, $this->name);
        $encryptedField->setStrictMode(false);
        return $encryptedField;
    }
}
