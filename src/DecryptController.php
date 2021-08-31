<?php

namespace LeKoala\Encrypt;

use SilverStripe\Assets\File;
use SilverStripe\Control\Controller;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;
use SilverStripe\Versioned\Versioned;

/**
 * Easily decrypt your files
 */
class DecryptController extends Controller
{
    public function index()
    {
        $request = $this->getRequest();
        $ID = $request->getVar("ID");
        $Hash = $request->getVar("Hash");

        if (!$ID || !$Hash) {
            return $this->httpError(404);
        }

        /** @var File|EncryptedDBFile $File  */
        $File = File::get()->byID($ID);
        if (!$File) {
            $File = Versioned::get_latest_version(File::class, $ID);
        }
        if (!$File) {
            return $this->httpError(404);
        }

        // Verify hash
        $FileHash = substr($File->File->Hash, 0, 10);
        if ($Hash != $FileHash && !Permission::check("CMS_ACCESS")) {
            return $this->httpError(404);
        }

        // Check protected
        $sendProtected = $this->config()->send_protected;
        $adminSendProtected = $this->config()->admin_send_protected;
        $currentUserID = Security::getCurrentUser()->ID ?? 0;
        $isOwner = $File->OwnerID === $currentUserID;
        if ($File->getVisibility() == "protected") {
            if (!$sendProtected && !$isOwner) {
                if ($adminSendProtected && Permission::check("CMS_ACCESS")) {
                    // We can proceed
                } else {
                    return $this->httpError(404);
                }
            }
        }

        EncryptHelper::sendDecryptedFile($File);
    }
}
