<?php

namespace LeKoala\Encrypt;

use SilverStripe\Security\Security;
use ParagonIE\CipherSweet\Contract\KeyProviderInterface;
use ParagonIE\CipherSweet\Exception\CipherSweetException;
use ParagonIE\CipherSweet\KeyProvider\MultiTenantProvider;

/**
 * This class provides a multi tenant key provider
 * Each user gets its own key to encrypt its data
 *
 * - getTenant() selects a KeyProvider based on a given tenant.
 * - getTenantFromRow() gets the tenant ID (array key) based on the data stored in an encrypted row.
 * - injectTenantMetadata() injects some breadcrumb for getTenantFromRow() to use to select the appropriate key.
 *
 * These methods were designed to be generalizable:
 * If you implement AWS KMS support, for example, you'd probably store an encrypted data key with injectTenantMetadata()
 * and then ask KMS to decrypt it in getTenantFromRow() (unless it's cached).
 */
class MemberKeyProvider extends MultiTenantProvider
{
    /**
     * @var int
     */
    protected $forcedTenant;

    /**
     * MultiTenantProvider constructor.
     *
     * @param array<array-key, KeyProviderInterface> $keyProviders
     * @param array-key|null $active
     */
    public function __construct(array $keyProviders, string|int|null $active = null)
    {
        if ($active === null && Security::getCurrentUser()) {
            $active = Security::getCurrentUser()->ID;
        }
        parent::__construct($keyProviders, $active);
    }

    /**
     * @param array-key $name
     * @return KeyProviderInterface
     * @throws CipherSweetException
     * @psalm-suppress PossiblyNullArrayOffset
     */
    public function getTenant(string|int $name): KeyProviderInterface
    {
        if (!array_key_exists($name, $this->tenants)) {
            throw new CipherSweetException("Tenant '{$name}' does not exist");
        }
        return $this->tenants[$this->active];
    }

    /**
     * @return KeyProviderInterface
     * @throws CipherSweetException
     */
    public function getActiveTenant(): KeyProviderInterface
    {
        if ($this->forcedTenant) {
            return $this->tenants[$this->forcedTenant];
        }
        $this->active = Security::getCurrentUser()->ID ?? $this->active;
        if (is_null($this->active)) {
            throw new CipherSweetException('Active tenant not set');
        }
        if (!array_key_exists($this->active, $this->tenants)) {
            throw new CipherSweetException("Tenant '{$this->active}' does not exist");
        }
        return $this->tenants[$this->active];
    }

    /**
     * @param array-key $index
     * @return static
     */
    public function setActiveTenant(string|int $index): static
    {
        if (!$index && Security::getCurrentUser()) {
            $index = Security::getCurrentUser();
        }
        $this->active = $index;
        return $this;
    }

    /**
     * @return int
     */
    public function getForcedTenant()
    {
        return $this->forcedTenant;
    }

    /**
     * @param int $index
     * @return self
     */
    public function setForcedTenant($index)
    {
        $this->forcedTenant = $index;
        return $this;
    }

    /**
     * Given a row of data, determine which tenant should be selected.
     *
     * This is not super useful since we mostly go through the ORM
     *
     * @param array<string,mixed> $row
     * @param string $tableName
     * @return string|int
     *
     * @throws CipherSweetException
     */
    public function getTenantFromRow(array $row, string $tableName): string|int
    {
        // Expect member bound encryption to have a Member relation
        if (isset($row['MemberID'])) {
            return $row['MemberID'];
        }
        return $this->active ?? 0;
    }

    /**
     * This is called when you encrypt a row, extra fields can be added
     * It's not really used in our case because we encrypt each fields
     * one by one anyway
     *
     * @param array<string,mixed> $row
     * @param string $tableName
     * @return array<string,mixed>
     */
    public function injectTenantMetadata(array $row, string $tableName): array
    {
        // If our class uses encryption per user, inject member id
        $row['MemberID'] = $this->active;
        return $row;
    }
}
