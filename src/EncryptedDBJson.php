<?php

namespace LeKoala\Encrypt;

use SilverStripe\Forms\HiddenField;

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
     * We cannot search on json fields
     *
     * @param string $title
     * @return HiddenField
     */
    public function scaffoldSearchField($title = null)
    {
        return HiddenField::create($this->getName());
    }

    /**
     * Json data is not easily displayed
     *
     * @param string $title
     * @param string $params
     * @return HiddenField
     */
    public function scaffoldFormField($title = null, $params = null)
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
     * @return array
     */
    public function decodeArray()
    {
        if (!$this->value) {
            return [];
        }
        return json_decode($this->value, JSON_OBJECT_AS_ARRAY);
    }

    /**
     * @return array
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
        return json_encode(json_decode($this->value), JSON_PRETTY_PRINT);
    }

    /**
     * @inheritDoc
     */
    public function saveInto($dataObject)
    {
        if ($this->value && is_array($this->value)) {
            $this->value = json_encode($this->value);
        }
        parent::saveInto($dataObject);
    }

    /**
     * Add a value
     *
     * @link https://stackoverflow.com/questions/7851590/array-set-value-using-dot-notation
     * @param string|array $key
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
    public function setValue($value, $record = null, $markChanged = true)
    {
        if (is_array($value)) {
            $value = json_encode($value);
        }
        return parent::setValue($value, $record, $markChanged);
    }

    /**
     * @inheritDoc
     */
    public function prepValueForDB($value)
    {
        if (is_array($value)) {
            $value = json_encode($value);
        }
        return parent::prepValueForDB($value);
    }

    /**
     * We return false because we can accept array and convert it to string
     * @return boolean
     */
    public function scalarValueOnly()
    {
        return false;
    }
}
