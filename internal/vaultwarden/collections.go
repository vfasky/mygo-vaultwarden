// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"strings"
)

// CollectionDraft is an authenticated, revision-bound detail response. Keeping
// the opaque original prevents a name-only PUT from deleting access assignments.
// Callers may edit Name; access editing uses a separate, explicit operation.
type CollectionDraft struct {
	Name                         string
	Access                       []CollectionAccess
	AccessLoaded, GroupsEnabled  bool
	originalAccess               map[string]CollectionAccess
	id, organizationID, revision string
	scope                        Scope
	raw                          map[string]json.RawMessage
}

func (d *CollectionDraft) Clone() *CollectionDraft {
	if d == nil {
		return nil
	}
	copy := *d
	copy.Access = append([]CollectionAccess(nil), d.Access...)
	return &copy
}

func (d *CollectionDraft) ID() string {
	if d == nil {
		return ""
	}
	return d.id
}
func (d *CollectionDraft) Close() {
	if d != nil {
		*d = CollectionDraft{}
	}
}

func collectionManager(data *organizationVault, orgID, collectionID string) error {
	for _, org := range data.organizations {
		if org.ID != orgID {
			continue
		}
		if org.Type != 0 && org.Type != 1 && org.Type != 4 {
			return ErrPermission
		}
		if collectionID == "" {
			if !org.CanCreateCollections() {
				return ErrPermission
			}
			return nil
		}
		for _, collection := range data.collections {
			if collection.ID == collectionID && collection.OrganizationID == orgID && collection.Manage {
				return nil
			}
		}
	}
	return ErrPermission
}

func validateCollectionAccess(raw json.RawMessage) error {
	var entries []map[string]json.RawMessage
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &entries) != nil || len(entries) > 100000 {
		return ErrProtocol
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		var id string
		if json.Unmarshal(entry["id"], &id) != nil || !validObjectID(id) || seen[id] {
			return ErrIdentity
		}
		seen[id] = true
		for _, name := range []string{"readOnly", "hidePasswords", "manage"} {
			var value *bool
			if json.Unmarshal(entry[name], &value) != nil || value == nil {
				return ErrProtocol
			}
		}
	}
	return nil
}

// CollectionDetails reads the complete access details, not the sync projection.
func (s *Session) CollectionDetails(ctx context.Context, vault *VaultData, orgID, collectionID string, persist func(SessionCheckpoint) error) (*CollectionDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	if err := collectionManager(data, orgID, collectionID); err != nil {
		return nil, err
	}
	draft := &CollectionDraft{organizationID: orgID, id: collectionID, revision: s.authorizationRevision, scope: vault.Scope}
	if draft.revision == "" {
		return nil, ErrExpired
	}
	if collectionID == "" {
		draft.raw = map[string]json.RawMessage{"users": json.RawMessage(`[]`), "groups": json.RawMessage(`[]`), "externalId": json.RawMessage(`null`)}
		return draft, nil
	}
	guard := s.organizationManagementGuardLocked(draft.revision)
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+orgID+"/collections/"+collectionID+"/details", "", "", persist, guard)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, cipherUpdateStatusError(status, body)
	}
	var identity struct{ ID, OrganizationID, Name string }
	if json.Unmarshal(body, &draft.raw) != nil || json.Unmarshal(body, &identity) != nil {
		return nil, ErrProtocol
	}
	if identity.ID != collectionID || identity.OrganizationID != orgID {
		return nil, ErrIdentity
	}
	for _, name := range []string{"users", "groups"} {
		if err := validateCollectionAccess(draft.raw[name]); err != nil {
			return nil, err
		}
	}
	plain, err := vaultcrypto.DecryptString(identity.Name, data.keys[orgID])
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	draft.Name = string(plain)
	if ctx.Err() != nil {
		draft.Close()
		return nil, ErrCancelled
	}
	return draft, nil
}

// SaveCollection preserves complete users/groups/externalId and opaque fields.
// Vaultwarden replaces assignments without a CAS or an encompassing transaction;
// callers must sync after every outcome and must not retry an ambiguous write.
func (s *Session) SaveCollection(ctx context.Context, vault *VaultData, draft *CollectionDraft, isolate, persist func(SessionCheckpoint) error) error {
	if draft == nil || strings.TrimSpace(draft.Name) == "" || len(draft.Name) > 1024 {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if vault == nil || draft.scope != vault.Scope || draft.revision == "" || draft.revision != s.authorizationRevision {
		return ErrExpired
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	if err := collectionManager(data, draft.organizationID, draft.id); err != nil {
		return err
	}
	for _, name := range []string{"users", "groups"} {
		if err := validateCollectionAccess(draft.raw[name]); err != nil {
			return err
		}
	}
	body, accessChanged, err := draft.collectionWriteBody()
	if err != nil {
		return err
	}
	if accessChanged && draft.id != "" {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		if isolate == nil {
			return ErrCheckpoint
		}
		if err := s.checkpointLocked(isolate); err != nil {
			return ErrCheckpoint
		}
	}
	// Re-read immediately before replacing access, refusing stale detail edits.
	// This narrows the server's missing-CAS race without claiming atomicity.
	// Isolation precedes even this GET when access is changing.
	guard := s.organizationManagementGuardLocked(draft.revision)
	path := "/api/organizations/" + draft.organizationID + "/collections"
	method := http.MethodPost
	if draft.id != "" {
		path += "/" + draft.id
		method = http.MethodPut
		status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, path+"/details", "", "", persist, guard)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return cipherUpdateStatusError(status, body)
		}
		var current map[string]json.RawMessage
		if json.Unmarshal(body, &current) != nil {
			return ErrProtocol
		}
		if !equalCollectionDetail(current, draft.raw) {
			return ErrConflict
		}
	}
	encrypted, err := vaultcrypto.EncryptString([]byte(draft.Name), data.keys[draft.organizationID])
	if err != nil {
		return err
	}
	body["name"], _ = json.Marshal(encrypted)
	encoded, err := json.Marshal(body)
	if err != nil {
		return ErrProtocol
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", string(encoded), persist, guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var result struct{ ID, OrganizationID string }
	if json.Unmarshal(response, &result) != nil || !validObjectID(result.ID) || result.OrganizationID != draft.organizationID || (draft.id != "" && result.ID != draft.id) {
		return &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}

func equalCollectionDetail(a, b map[string]json.RawMessage) bool {
	// Normalize insignificant JSON whitespace, retaining number precision and all
	// extension fields. Array reorder is conservatively treated as a conflict.
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(left) == string(right)
}

func (s *Session) DeleteCollection(ctx context.Context, vault *VaultData, draft *CollectionDraft, isolate, persist func(SessionCheckpoint) error) error {
	if draft == nil || draft.id == "" {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if vault == nil || draft.scope != vault.Scope || draft.revision == "" || draft.revision != s.authorizationRevision {
		return ErrExpired
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	if err := collectionManager(data, draft.organizationID, draft.id); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if isolate == nil {
		return ErrCheckpoint
	}
	if err := s.checkpointLocked(isolate); err != nil {
		return ErrCheckpoint
	}
	guard := s.organizationManagementGuardLocked(draft.revision)
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodDelete, "/api/organizations/"+draft.organizationID+"/collections/"+draft.id, "", "", persist, guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, body)}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
