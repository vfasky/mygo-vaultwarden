// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
)

// CopyPersonalResourceMetadata begins a multi-step copy only after all source
// files have passed archive preflight. The caller must retain the plan and
// restore/verify every resource before reporting a complete copy. Source data
// and attachments remain untouched; ambiguous creates must never be repeated.
func (s *Session) CopyPersonalResourceMetadata(ctx context.Context, vault *VaultData, plan *ResourceImportPlan, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	if plan == nil || plan.file == nil || plan.manifest.OrganizationID != "" {
		return CipherDocument{}, ErrValidation
	}
	file, err := decodeBackup(plan.manifest.Metadata, MyGoBackup)
	if err != nil {
		return CipherDocument{}, err
	}
	if len(file.Items) != 1 {
		return CipherDocument{}, ErrValidation
	}
	sourceID := file.Items[0]["id"].(string)
	metadata, err := s.exportPersonalBackup(ctx, vault, []string{sourceID}, MyGoBackup, map[string]*ItemAuthorization{sourceID: grant}, true)
	if err != nil {
		return CipherDocument{}, err
	}
	defer clear(metadata)
	if !rawJSONEqual(metadata, plan.manifest.Metadata) {
		return CipherDocument{}, ErrConflict
	}
	descriptions, err := s.backupResourceDescriptions(vault, []string{sourceID}, map[string]*ItemAuthorization{sourceID: grant})
	if err != nil {
		return CipherDocument{}, err
	}
	if len(descriptions) != len(plan.manifest.Resources) {
		return CipherDocument{}, ErrConflict
	}
	for i, resource := range descriptions {
		saved := plan.manifest.Resources[i]
		if resource.CipherID != saved.CipherID || resource.AttachmentID != saved.AttachmentID || resource.FileName != saved.FileName {
			return CipherDocument{}, ErrConflict
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherDocument{}, err
	}
	defer finish()
	source, err := s.personalDocumentLocked(vault, sourceID)
	if err != nil {
		return CipherDocument{}, err
	}
	var meta struct{ Reprompt int }
	json.Unmarshal(source.JSON, &meta)
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, source) {
			return ErrPermission
		}
		return nil
	}
	if err = guard(); err != nil {
		return CipherDocument{}, err
	}
	item := file.Items[0]
	delete(item, "deletedDate")
	delete(item, "archivedDate")
	document, err := encryptImportedItem(item, s.key, s.account)
	if err != nil {
		return CipherDocument{}, err
	}
	created, err := s.createGuardedCipherDocumentLocked(ctx, document, persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	var result struct{ ID string }
	if json.Unmarshal(created.JSON, &result) != nil || !validObjectID(result.ID) || result.ID == sourceID {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	return created, nil
}
