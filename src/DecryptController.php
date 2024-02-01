<?php

namespace LeKoala\Encrypt;

use SilverStripe\Assets\File;
use SilverStripe\Security\Security;
use SilverStripe\Control\Controller;
use SilverStripe\Security\Permission;
use SilverStripe\Versioned\Versioned;
use SilverStripe\Control\HTTPResponse;

/**
 * Easily decrypt your files
 */
class DecryptController extends Controller
{
    /**
     * @return HTTPResponse|void
     */
    public function index()
    {
        $request = $this->getRequest();
        $ID = (int) $request->getVar("ID");
        $Hash = $request->getVar("Hash");

        if (!$ID || !$Hash) {
            return $this->httpError(404);
        }

        $sendDraft = $this->config()->send_draft;

        /** @var File|null $File */
        $File = File::get()->byID($ID);
        if (!$File && $sendDraft && class_exists(Versioned::class)) {
            /** @var File|null $File */
            $File = Versioned::get_one_by_stage(File::class, Versioned::DRAFT, "ID = " . $ID);
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
