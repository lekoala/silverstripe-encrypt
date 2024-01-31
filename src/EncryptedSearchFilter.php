<?php

namespace LeKoala\Encrypt;

use Exception;
use SilverStripe\ORM\DB;
use InvalidArgumentException;
use SilverStripe\ORM\DataQuery;
use ParagonIE\CipherSweet\CipherSweet;
use ParagonIE\CipherSweet\EncryptedField;
use SilverStripe\ORM\Filters\SearchFilter;

/**
 * A filter that helps searching against a full blind index
 * This can return false positive and is NOT recommended
 * @deprecated
 */
class EncryptedSearchFilter extends SearchFilter
{
    /**
     * @param array<string> $modifiers
     * @return void
     */
    public function setModifiers(array $modifiers)
    {
        if (!empty($modifiers)) {
            throw new InvalidArgumentException(
                get_class($this) . ' does not accept ' . implode(', ', $modifiers) . ' as modifiers'
            );
        }
        parent::setModifiers($modifiers);
    }

    protected function getCaseSensitive()
    {
        return null;
    }

    public function getDbName()
    {
        $column = parent::getDbName();
        $column = str_replace('"', '', $column);
        return '"' . $column . 'BlindIndex"';
    }

    /**
     * @param CipherSweet $engine
     * @param bool $fashHash
     * @return EncryptedField
     */
    public function getEncryptedField($engine = null, $fashHash = null)
    {
        $singleton = singleton($this->model);
        return $singleton->dbObject($this->name)->getEncryptedField($engine, $fashHash);
    }

    /**
     * Accessor for the current value to be filtered on.
     *
     * @return string
     */
    public function getEncryptedValue()
    {
        $plaintext = $this->getValue();
        if (is_array($plaintext)) {
            throw new Exception("Array value are not supported");
        }
        $value = $this->getEncryptedField()->getBlindIndex($plaintext, $this->name . EncryptedDBField::INDEX_SUFFIX);
        if (is_array($value)) {
            return $value['value'];
        }
        return $value;
    }

    /**
     * Applies an exact match (equals) on a field value.
     *
     * @return DataQuery
     */
    protected function applyOne(DataQuery $query)
    {
        $this->model = $query->applyRelation($this->relation);
        $where = DB::get_conn()->comparisonClause(
            $this->getDbName(),
            '',
            true, // exact?
            false, // negate?
            $this->getCaseSensitive(),
            true
        );
        $array = array($where => $this->getEncryptedValue());
        return $query->where($array);
    }

    /**
     * Applies an exact match (equals) on a field value against multiple
     * possible values.
     *
     * @return DataQuery
     */
    protected function applyMany(DataQuery $query)
    {
        $this->model = $query->applyRelation($this->relation);
        $caseSensitive = $this->getCaseSensitive();
        $values = [$this->getEncryptedValue()];
        $column = $this->getDbName();
        $placeholders = DB::placeholders($values);
        return $query->where(array(
            "$column IN ($placeholders)" => $values
        ));
    }

    /**
     * Excludes an exact match (equals) on a field value.
     *
     * @return DataQuery
     */
    protected function excludeOne(DataQuery $query)
    {
        $this->model = $query->applyRelation($this->relation);
        $column = $this->getDbName();
        $where = DB::get_conn()->comparisonClause(
            $column,
            '',
            true, // exact?
            true, // negate?
            $this->getCaseSensitive(),
            true
        );
        $array = array($where => $this->getEncryptedValue());
        return $query->where($array);
    }

    /**
     * Excludes an exact match (equals) on a field value against multiple
     * possible values.
     *
     * @return DataQuery
     */
    protected function excludeMany(DataQuery $query)
    {
        $this->model = $query->applyRelation($this->relation);
        $caseSensitive = $this->getCaseSensitive();
        $values = [$this->getEncryptedValue()];
        $column = $this->getDbName();
        if ($caseSensitive === null) {
            $placeholders = DB::placeholders($values);
            return $query->where(array(
                "$column NOT IN ($placeholders)" => $values
            ));
        } else {
            // Generate reusable comparison clause
            $comparisonClause = DB::get_conn()->comparisonClause(
                $column,
                '',
                true, // exact?
                true, // negate?
                $this->getCaseSensitive(),
                true
            );
            // Since query connective is ambiguous, use AND explicitly here
            $count = count($values);
            $predicate = implode(' AND ', array_fill(0, $count, $comparisonClause));
            return $query->where(array($predicate => $values));
        }
    }

    public function isEmpty()
    {
        /** @var array<mixed>|string|null $v */
        $v = $this->getValue();
        return $v === array() || $v === null || $v === '';
    }
}
