// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

func organizationResourceCopyMetadata(source CipherDocument, key []byte) ([]byte, error) {
	object, err := documentObject(source)
	if err != nil {
		return nil, err
	}
	delete(object, "organizationId")
	delete(object, "collectionIds")
	delete(object, "attachments")
	if err = validateCopyObject(object); err != nil {
		return nil, err
	}
	itemKey, err := cipherItemKey(object, key)
	if err != nil {
		return nil, err
	}
	defer clear(itemKey)
	if err = transformCompleteCipher(object, itemKey, false); err != nil {
		return nil, err
	}
	for _, name := range []string{"object", "key", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedFor", "encryptedByKeyId", "lastKnownRevisionDate"} {
		delete(object, name)
	}
	object["folderId"] = nil
	file := backupFile{Format: backupSignature, Version: 1, Folders: []Folder{}, Items: []map[string]any{object}}
	data, err := json.Marshal(file)
	if err != nil {
		return nil, ErrProtocol
	}
	if _, err = decodeBackup(data, MyGoBackup); err != nil {
		clear(data)
		return nil, err
	}
	return data, nil
}

// WriteOrganizationCipherResourceCopy prepares only the selected readable,
// editable source. It does not require or pretend to perform a whole-org export.
func (s *Session) WriteOrganizationCipherResourceCopy(ctx context.Context, vault *VaultData, sourceID string, grant *ItemAuthorization, writer io.Writer, persist func(SessionCheckpoint) error) (*ResourceBackupPublication, error) {
	if writer == nil {
		return nil, ErrValidation
	}
	s.mu.Lock()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	source, key, err := s.organizationDocumentLocked(vault, sourceID, data)
	var meta struct {
		OrganizationID string
		Reprompt       int
		Edit           bool
	}
	if err == nil && json.Unmarshal(source.JSON, &meta) != nil {
		err = ErrProtocol
	}
	if err == nil && (!meta.Edit || (meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, source))) {
		err = ErrPermission
	}
	var metadata []byte
	if err == nil {
		metadata, err = organizationResourceCopyMetadata(source, key)
	}
	publication := &ResourceBackupPublication{vault: vault, session: s, revision: s.authorizationRevision, epoch: s.authorizationEpoch, ids: []string{sourceID}}
	data.close()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer clear(metadata)
	grants := map[string]*ItemAuthorization{sourceID: grant}
	resources, err := s.backupResourceDescriptions(vault, []string{sourceID}, grants)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(source.JSON)
	manifest := resourceManifest{Format: resourceBackupSignature, Version: 1, OrganizationID: meta.OrganizationID, CopyCipherID: sourceID, CopySourceDigest: hex.EncodeToString(digest[:]), Metadata: metadata, Resources: resources}
	return s.writeResourceArchive(ctx, vault, grants, manifest, publication, writer, persist)
}

func validateOrganizationResourceCopyPlan(plan *ResourceImportPlan, source CipherDocument, ownerKey []byte, sourceID, orgID string) error {
	if plan == nil || plan.file == nil || plan.manifest.CopyCipherID != sourceID || plan.manifest.OrganizationID != orgID {
		return ErrValidation
	}
	digest := sha256.Sum256(source.JSON)
	if plan.manifest.CopySourceDigest != hex.EncodeToString(digest[:]) {
		return ErrConflict
	}
	expected, err := organizationResourceCopyMetadata(source, ownerKey)
	if err != nil {
		return err
	}
	defer clear(expected)
	if !rawJSONEqual(expected, plan.manifest.Metadata) {
		return ErrConflict
	}
	object, err := documentObject(source)
	if err != nil {
		return err
	}
	key, err := cipherItemKey(object, ownerKey)
	if err != nil {
		return err
	}
	defer clear(key)
	records, err := attachmentRecords(source)
	if err != nil {
		return err
	}
	if len(records) != len(plan.manifest.Resources) {
		return ErrConflict
	}
	for i, record := range records {
		resource := plan.manifest.Resources[i]
		name, err := DecryptString(record.FileName, key)
		if err != nil {
			return err
		}
		equal := resource.CipherID == sourceID && resource.AttachmentID == record.ID && resource.FileName == string(name)
		clear(name)
		if !equal {
			return ErrConflict
		}
	}
	return nil
}
