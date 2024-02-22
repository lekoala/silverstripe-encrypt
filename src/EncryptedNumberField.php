<?php

namespace LeKoala\Encrypt;

use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\CipherSweet;
use SilverStripe\ORM\Queries\SQLSelect;
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
    const SHORT_INDEX_SUFFIX = "LastFourBlindIndex";

    /**
     * @var array<string,string>
     */
    private static $composite_db = array(
        "Value" => "Varchar(191)",
        "BlindIndex" => 'Varchar(32)',
        "LastFourBlindIndex" => 'Varchar(16)',
    );

    /**
     * @param int $default
     * @return int
     */
    public function getLastFourIndexSize($default = null)
    {
        if (array_key_exists('last_four_index_size', $this->options)) {
            return $this->options['last_four_index_size'];
        }
        return $default;
    }

    /**
     * @return string
     */
    public function getLastFourBlindIndexField()
    {
        return $this->getField('LastFourBlindIndex');
    }

    /**
     * @param mixed $value
     * @param bool $markChanged
     * @return $this
     */
    public function setLastFourBlindIndexField($value, $markChanged = true)
    {
        return $this->setField('LastFourBlindIndex', $value, $markChanged);
    }

    /**
     * @param CipherSweet $engine
     * @param bool $fashHash
     * @return EncryptedField
     */
    public function getEncryptedField($engine = null, $fashHash = null)
    {
        if ($engine === null) {
            $engine = EncryptHelper::getCipherSweet();
        }
        if ($fashHash === null) {
            $fashHash = EncryptHelper::getFashHash();
        }
        $lastFourIndexSize = $this->getLastFourIndexSize(self::SMALL_INDEX_SIZE);
        $indexSize = $this->getIndexSize(self::LARGE_INDEX_SIZE);

        //TODO: review how naming is done (see: getEncryptedRow)
        // fieldName needs to match exact db name for row rotator to work properly
        $fieldName = $this->name . self::VALUE_SUFFIX;
        $indexName = $this->name . self::INDEX_SUFFIX;
        $shortIndexName = $this->name . self::SHORT_INDEX_SUFFIX;

        $encryptedField = (new EncryptedField($engine, $this->tableName, $fieldName))
            ->addBlindIndex(new BlindIndex($shortIndexName, [new LastFourDigits()], $lastFourIndexSize, $fashHash))
            ->addBlindIndex(new BlindIndex($indexName, [], $indexSize, $fashHash));
        return $encryptedField;
    }

    /**
     * @param SQLSelect $query
     * @return void
     */
    // public function addToQuery(&$query)
    // {
    //     parent::addToQuery($query);
    //     $query->selectField(sprintf('"%s' . self::VALUE_SUFFIX . '"', $this->name));
    //     $query->selectField(sprintf('"%s' . self::INDEX_SUFFIX . '"', $this->name));
    //     $query->selectField(sprintf('"%s' . self::SHORT_INDEX_SUFFIX . '"', $this->name));
    // }
}
