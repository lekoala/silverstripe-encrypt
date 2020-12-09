<?php

namespace LeKoala\SilverStripeEncrypt\Tests;

use LeKoala\SilverStripeEncrypt\DBEncryptedHTMLText;
use LeKoala\SilverStripeEncrypt\DBEncryptedText;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;

class EncryptedModel extends DataObject implements TestOnly
{
    private static $table_name = 'EncryptedModel';

    private static $db = [
        "EncryptedText" => DBEncryptedText::class,
        "EncryptedHTMLText" => DBEncryptedHTMLText::class,
    ];
}
