// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

// CopyOrganizationCipher copies supported complete standard records into an
// explicitly selected organization collection. Unknown extensions, attachments
// and FIDO2 fail before HTTP; they are never silently discarded. The source is
// unchanged. The new item has a new key, ID and creation/revision dates.
func (s *Session) CopyOrganizationCipher(ctx context.Context, vault *VaultData, sourceID, targetOrgID, targetCollectionID string, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	return s.copyOrganizationCipher(ctx, vault, sourceID, targetOrgID, targetCollectionID, grant, persist, nil)
}

// CopyOrganizationResourceMetadata starts a complete staged copy after all
// binary resources have been verified. Restore and verify the plan's files
// against the returned new ID before reporting completion.
func (s *Session) CopyOrganizationResourceMetadata(ctx context.Context, vault *VaultData, sourceID, targetOrgID, targetCollectionID string, plan *ResourceImportPlan, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	if plan == nil {
		return CipherDocument{}, ErrValidation
	}
	return s.copyOrganizationCipher(ctx, vault, sourceID, targetOrgID, targetCollectionID, grant, persist, plan)
}

func (s *Session) copyOrganizationCipher(ctx context.Context, vault *VaultData, sourceID, targetOrgID, targetCollectionID string, grant *ItemAuthorization, persist func(SessionCheckpoint) error, resources *ResourceImportPlan) (CipherDocument, error) {
	if !validObjectID(sourceID) || !validObjectID(targetOrgID) || !validObjectID(targetCollectionID) {
		return CipherDocument{}, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherDocument{}, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return CipherDocument{}, err
	}
	defer data.close()
	source, sourceKey, err := s.organizationDocumentLocked(vault, sourceID, data)
	if err != nil {
		return CipherDocument{}, err
	}
	var identity struct{ OrganizationID *string }
	if json.Unmarshal(source.JSON, &identity) != nil || identity.OrganizationID == nil {
		return CipherDocument{}, ErrIdentity
	}
	metadata, err := validateOrganizationState(source, *identity.OrganizationID, CipherTrash)
	if err != nil {
		return CipherDocument{}, err
	}
	if !data.writableCollection(targetOrgID, targetCollectionID) {
		return CipherDocument{}, ErrPermission
	}
	authorized := s.validItemAuthorizationLocked(grant, source)
	if *metadata.Reprompt != 0 && !authorized {
		return CipherDocument{}, ErrPermission
	}
	copySource := source
	if resources != nil {
		if err := validateOrganizationResourceCopyPlan(resources, source, sourceKey, sourceID, *identity.OrganizationID); err != nil {
			return CipherDocument{}, err
		}
		object, err := documentObject(source)
		if err != nil {
			return CipherDocument{}, err
		}
		delete(object, "attachments")
		copySource.JSON, err = json.Marshal(object)
		if err != nil {
			return CipherDocument{}, ErrProtocol
		}
	}
	document, err := copyOrganizationDocument(copySource, sourceKey, data.keys[targetOrgID], s.account, targetOrgID, authorized)
	if err != nil {
		return CipherDocument{}, err
	}
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if *metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, source) {
			return ErrPermission
		}
		return nil
	}
	guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, *identity.OrganizationID, metadata.Type, persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, targetOrgID, metadata.Type, persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return CipherDocument{}, err
	}
	found := false
	for _, raw := range policies.ciphers {
		var id struct{ ID string }
		if json.Unmarshal(raw, &id) != nil {
			return CipherDocument{}, ErrProtocol
		}
		if id.ID != sourceID {
			continue
		}
		if found {
			return CipherDocument{}, ErrProtocol
		}
		found = true
		live, err := validateOrganizationState(CipherDocument{JSON: raw}, *identity.OrganizationID, CipherTrash)
		if err != nil {
			return CipherDocument{}, err
		}
		if live.Type != metadata.Type || *live.Reprompt != *metadata.Reprompt || !sameOptional(live.RevisionDate, metadata.RevisionDate) {
			return CipherDocument{}, ErrConflict
		}
	}
	if !found {
		return CipherDocument{}, ErrConflict
	}
	body, err := json.Marshal(map[string]any{"cipher": json.RawMessage(document.JSON), "collectionIds": []string{targetCollectionID}})
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, "/api/ciphers/create", "application/json", string(body), persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	if status != http.StatusOK {
		return CipherDocument{}, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	result := CipherDocument{JSON: response}
	fields, err := DecryptCipherDocument(result, data.keys[targetOrgID])
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if !validObjectID(fields.ID) || fields.ID == sourceID || fields.OrganizationID == nil || *fields.OrganizationID != targetOrgID {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}

func copyOrganizationDocument(source CipherDocument, sourceKey, targetKey []byte, account, targetOrgID string, authorized bool) (CipherDocument, error) {
	object, err := documentObject(source)
	if err != nil {
		return CipherDocument{}, err
	}
	// Ownership and collection authorization are checked by the Session caller.
	// Strip only these routing fields for the shared strict crypto/schema helper;
	// no personal API endpoint is called, and all opaque fields remain for validation.
	delete(object, "organizationId")
	delete(object, "collectionIds")
	raw, err := json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	copied, err := copyAuthorizedPersonalCipherDocument(CipherDocument{JSON: raw}, sourceKey, account, authorized)
	if err != nil {
		return CipherDocument{}, err
	}
	object, err = documentObject(copied)
	if err != nil {
		return CipherDocument{}, err
	}
	key, err := cipherItemKey(object, sourceKey)
	if err != nil {
		return CipherDocument{}, err
	}
	defer clear(key)
	wrapped, err := EncryptString(key, targetKey)
	if err != nil {
		return CipherDocument{}, err
	}
	object["key"], object["organizationId"] = wrapped, targetOrgID
	// A folder belongs to the source account's personal organization of entries;
	// organization copies start unfiled instead of assigning another scope's folder.
	object["folderId"] = nil
	raw, err = json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	return CipherDocument{JSON: raw}, nil
}
