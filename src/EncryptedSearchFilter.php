<?php

namespace LeKoala\Encrypt;

use SilverStripe\ORM\DB;
use InvalidArgumentException;
use SilverStripe\ORM\DataQuery;
use ParagonIE\CipherSweet\BlindIndex;
use ParagonIE\CipherSweet\EncryptedField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\Filters\SearchFilter;

/**
 * A filter that helps searching against a full blind index
 */
class EncryptedSearchFilter extends SearchFilter
{
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
     * @return EncryptedField
     */
    public function getEncryptedField()
    {
        $engine = EncryptHelper::getCipherSweet();
        $table = DataObject::getSchema()->tableName($this->model);
        $encryptedField = (new EncryptedField($engine, $table, $this->name))
            ->addBlindIndex(new BlindIndex($this->name . "BlindIndex", [], 32));
        return $encryptedField;
    }

    /**
     * Accessor for the current value to be filtered on.
     *
     * @return string|array
     */
    public function getEncryptedValue()
    {
        return $this->getEncryptedField()->getBlindIndex($this->getValue(), $this->name . 'BlindIndex');
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
            null,
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
        $values = $this->getEncryptedValue();
        $column = $this->getDbName();
        // For queries using the default collation (no explicit case) we can use the WHERE .. IN .. syntax,
        // providing simpler SQL than many WHERE .. OR .. fragments.
        // If values is an empty array, fall back to 3.1 behaviour and use empty string comparison
        if (empty($values)) {
            $values = array('');
        }
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
            null,
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
        $values = $this->getEncryptedValue();
        $column = $this->getDbName();
        if ($caseSensitive === null) {
            // For queries using the default collation (no explicit case) we can use the WHERE .. NOT IN .. syntax,
            // providing simpler SQL than many WHERE .. AND .. fragments.
            // If values is an empty array, fall back to 3.1 behaviour and use empty string comparison
            if (empty($values)) {
                $values = array('');
            }
            $placeholders = DB::placeholders($values);
            return $query->where(array(
                "$column NOT IN ($placeholders)" => $values
            ));
        } else {
            // Generate reusable comparison clause
            $comparisonClause = DB::get_conn()->comparisonClause(
                $column,
                null,
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
        return $this->getValue() === array() || $this->getValue() === null || $this->getValue() === '';
    }
}
