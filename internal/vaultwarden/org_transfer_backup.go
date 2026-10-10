// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/url"
)

const organizationBackupFormat = "mygo-organization-backup"

type OrganizationBackupCollection struct {
	ID                         string  `json:"id"`
	OrganizationID             string  `json:"organizationId"`
	Name                       string  `json:"name"`
	ExternalID                 *string `json:"externalId"`
	Type                       int     `json:"type"`
	DefaultUserCollectionEmail *string `json:"defaultUserCollectionEmail"`
}
type organizationBackup struct {
	Format         string                         `json:"format"`
	Version        int                            `json:"version"`
	OrganizationID string                         `json:"organizationId"`
	Collections    []OrganizationBackupCollection `json:"collections"`
	Items          []map[string]any               `json:"items"`
}

// OrganizationImportPlan holds plaintext in memory. Clear after completion,
// cancel, lock or scope change. Plans never contain API tokens or organization keys.
type OrganizationImportPlan struct{ file organizationBackup }

func (p *OrganizationImportPlan) Clear() {
	if p != nil {
		p.file = organizationBackup{}
	}
}
func (p *OrganizationImportPlan) PreviewItems() []ImportPreview {
	if p == nil {
		return nil
	}
	out := make([]ImportPreview, 0, len(p.file.Items))
	for _, item := range p.file.Items {
		identity, err := backupItemIdentity(item)
		if err != nil {
			return nil
		}
		out = append(out, ImportPreview{Name: identity.Name, Type: identity.Type, Archived: item["archivedDate"] != nil, Deleted: item["deletedDate"] != nil})
	}
	return out
}
func (p *OrganizationImportPlan) Collections() []OrganizationBackupCollection {
	if p == nil {
		return nil
	}
	out := append([]OrganizationBackupCollection(nil), p.file.Collections...)
	for i := range out {
		if out[i].ExternalID != nil {
			value := *out[i].ExternalID
			out[i].ExternalID = &value
		}
	}
	return out
}

// This versioned format preserves standard fields (including legacy URI aliases,
// checksums and personal archive/favorite metadata) which official plaintext
// importers may normalize. It does not claim encrypted/password-protected backup.
func ParseOrganizationImport(raw []byte) (*OrganizationImportPlan, error) {
	if len(raw) == 0 || len(raw) > maxResponse || strictJSON(raw) != nil {
		return nil, ErrValidation
	}
	root, err := documentObject(CipherDocument{JSON: raw})
	if err != nil {
		return nil, err
	}
	if err := copyKeys(root, "format", "version", "organizationId", "collections", "items"); err != nil {
		return nil, err
	}
	var file organizationBackup
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, ErrValidation
	}
	if file.Format != organizationBackupFormat || file.Version != 1 || !validObjectID(file.OrganizationID) || len(file.Collections) > 10000 || len(file.Items) == 0 || len(file.Items) > 10000 {
		return nil, ErrValidation
	}
	collections := map[string]bool{}
	for _, c := range file.Collections {
		if !validObjectID(c.ID) || collections[c.ID] || c.OrganizationID != file.OrganizationID || c.Name == "" || len(c.Name) > 10000 || c.Type != 0 || c.DefaultUserCollectionEmail != nil {
			return nil, ErrValidation
		}
		collections[c.ID] = true
	}
	items := map[string]bool{}
	for _, item := range file.Items {
		id, ok := item["id"].(string)
		if !ok || !validObjectID(id) || items[id] || item["organizationId"] != file.OrganizationID {
			return nil, ErrIdentity
		}
		items[id] = true
		relations, ok := item["collectionIds"].([]any)
		if !ok {
			return nil, ErrProtocol
		}
		seen := map[string]bool{}
		for _, rawID := range relations {
			id, ok := rawID.(string)
			if !ok || !collections[id] || seen[id] {
				return nil, ErrValidation
			}
			seen[id] = true
		}
		if err := validateOrganizationBackupItem(item); err != nil {
			return nil, err
		}
	}
	return &OrganizationImportPlan{file: file}, nil
}

func validateOrganizationBackupItem(item map[string]any) error {
	local := map[string]any{}
	for k, v := range item {
		local[k] = v
	}
	delete(local, "organizationId")
	delete(local, "collectionIds")
	return validateBackupItem(local, MyGoBackup)
}

// WithOrganizationBackup calls the official organization export endpoint. save
// must perform a user-confirmed, exclusive private-file write (0600, no symlink
// following/overwrite) and may not re-enter Session. All rows must be supported;
// no partial/empty backup is returned when a row cannot be preserved safely.
func (s *Session) WithOrganizationBackup(ctx context.Context, vault *VaultData, orgID string, grants map[string]*ItemAuthorization, confirmed bool, save func([]byte) error, persist func(SessionCheckpoint) error) error {
	return s.withOrganizationBackup(ctx, vault, orgID, grants, confirmed, save, persist, false)
}

func (s *Session) withOrganizationBackup(ctx context.Context, vault *VaultData, orgID string, grants map[string]*ItemAuthorization, confirmed bool, save func([]byte) error, persist func(SessionCheckpoint) error, resources bool) error {
	if !confirmed || save == nil || !validObjectID(orgID) {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	admin := false
	for _, org := range data.organizations {
		if org.ID == orgID && (org.Type == 0 || org.Type == 1) {
			admin = true
		}
	}
	if !admin {
		return ErrPermission
	}
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return err
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return err
	}
	member, ok := policies.memberships[orgID]
	if !ok || *member.Status != 2 || !*member.Enabled || (*member.Type != 0 && *member.Type != 1) {
		return ErrPermission
	}
	// Use the snapshot-bound documents for grants and live sync for revocation.
	live := map[string]CipherDocument{}
	for _, raw := range policies.ciphers {
		var id struct{ ID string }
		if json.Unmarshal(raw, &id) != nil {
			return ErrProtocol
		}
		if _, exists := live[id.ID]; exists {
			return ErrProtocol
		}
		live[id.ID] = CipherDocument{JSON: raw}
	}
	guard := s.orgOperationGuardLocked()
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+orgID+"/export", "", "", persist, guard)
	if err != nil {
		return err
	}
	defer clear(response)
	if status != http.StatusOK {
		return cipherUpdateStatusError(status, response)
	}
	var payload struct {
		Collections []json.RawMessage
		Ciphers     []json.RawMessage
	}
	if json.Unmarshal(response, &payload) != nil || payload.Collections == nil || payload.Ciphers == nil {
		return ErrProtocol
	}
	file := organizationBackup{Format: organizationBackupFormat, Version: 1, OrganizationID: orgID, Collections: []OrganizationBackupCollection{}, Items: []map[string]any{}}
	seenCollections := map[string]bool{}
	for _, raw := range payload.Collections {
		object, err := documentObject(CipherDocument{JSON: raw})
		if err != nil {
			return err
		}
		if err := copyKeys(object, "id", "organizationId", "name", "externalId", "object", "type", "defaultUserCollectionEmail"); err != nil {
			return err
		}
		var c OrganizationBackupCollection
		if json.Unmarshal(raw, &c) != nil || c.OrganizationID != orgID || !validObjectID(c.ID) || seenCollections[c.ID] {
			return ErrIdentity
		}
		name, err := vaultcrypto.DecryptString(c.Name, data.keys[orgID])
		if err != nil {
			return err
		}
		c.Name = string(name)
		clear(name)
		seenCollections[c.ID] = true
		file.Collections = append(file.Collections, c)
	}
	seen := map[string]bool{}
	for _, raw := range payload.Ciphers {
		object, err := documentObject(CipherDocument{JSON: raw})
		if err != nil {
			return err
		}
		id, ok := object["id"].(string)
		if !ok || seen[id] || object["organizationId"] != orgID {
			return ErrIdentity
		}
		seen[id] = true
		snapshot, _, err := s.organizationDocumentLocked(vault, id, data)
		if err != nil {
			return err
		}
		local, err := validateOrganizationState(snapshot, orgID, CipherTrash)
		if err != nil {
			return err
		}
		current, err := validateOrganizationState(live[id], orgID, CipherTrash)
		if err != nil {
			return err
		}
		if local.Type != current.Type || *local.Reprompt != *current.Reprompt || !sameOptional(local.RevisionDate, current.RevisionDate) {
			return ErrConflict
		}
		if policies.restricts(&orgID, current.Type) {
			return ErrPermission
		}
		if *local.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[id], snapshot) {
			return ErrPermission
		}
		if local.RevisionDate == nil || object["revisionDate"] != *local.RevisionDate {
			return ErrConflict
		}
		// Export omits user-only access flags; authority comes from authenticated sync.
		object["edit"], object["viewPassword"] = true, true
		org, relations := object["organizationId"], object["collectionIds"]
		delete(object, "organizationId")
		delete(object, "collectionIds")
		if resources {
			delete(object, "attachments")
		}
		if err := validateCopyObject(object); err != nil {
			return err
		}
		key, err := cipherItemKey(object, data.keys[orgID])
		if err != nil {
			return err
		}
		err = transformCompleteCipher(object, key, false)
		clear(key)
		if err != nil {
			return err
		}
		object["organizationId"], object["collectionIds"] = org, relations
		if object["collectionIds"] == nil {
			object["collectionIds"] = []any{}
		}
		for _, name := range []string{"object", "key", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedFor", "encryptedByKeyId", "lastKnownRevisionDate", "attachments"} {
			delete(object, name)
		}
		localObject, err := documentObject(snapshot)
		if err != nil {
			return err
		}
		for _, name := range []string{"favorite", "archivedDate", "folderId"} {
			object[name] = localObject[name]
		}
		if err := validateOrganizationBackupItem(object); err != nil {
			return err
		}
		file.Items = append(file.Items, object)
	}
	if len(file.Items) == 0 {
		return ErrNotFound
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return ErrProtocol
	}
	defer clear(encoded)
	plan, err := ParseOrganizationImport(encoded)
	if err != nil {
		return err
	}
	plan.Clear()
	if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
		return err
	}
	// Revalidate expiring grants after decrypting the complete export.
	for id := range seen {
		doc := data.documents[id]
		var m struct{ Reprompt int }
		_ = json.Unmarshal(doc.JSON, &m)
		if m.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[id], doc) {
			return ErrPermission
		}
	}
	return save(encoded)
}

// ImportOrganizationBackup sends one official nontransactional import request.
// mappings maps each source collection to an existing target ID; an empty value
// explicitly creates a new collection. HTTP 200 is only acknowledgement: VW
// ignores individual cipher errors internally, so every item needs reconciliation.
func (s *Session) ImportOrganizationBackup(ctx context.Context, vault *VaultData, orgID string, plan *OrganizationImportPlan, mappings map[string]string, confirmed bool, persist func(SessionCheckpoint) error) (OrganizationOperationResult, error) {
	var result OrganizationOperationResult
	if !confirmed || plan == nil || plan.file.Format != organizationBackupFormat || !validObjectID(orgID) {
		return result, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return result, err
	}
	defer data.close()
	var target *Organization
	for i := range data.organizations {
		if data.organizations[i].ID == orgID {
			target = &data.organizations[i]
		}
	}
	if target == nil {
		return result, ErrPermission
	}
	if len(mappings) != len(plan.file.Collections) {
		return result, ErrValidation
	}
	type relation struct {
		Key   int `json:"key"`
		Value int `json:"value"`
	}
	collections := []map[string]any{}
	indices := map[string]int{}
	for i, c := range plan.file.Collections {
		id, ok := mappings[c.ID]
		if !ok {
			return result, ErrValidation
		}
		if id != "" && (!validObjectID(id) || !data.writableCollection(orgID, id)) {
			return result, ErrPermission
		}
		if id == "" && !target.CanCreateCollections() {
			return result, ErrPermission
		}
		name, err := vaultcrypto.EncryptString([]byte(c.Name), data.keys[orgID])
		if err != nil {
			return result, err
		}
		collection := map[string]any{"name": name, "externalId": c.ExternalID}
		if id != "" {
			collection["id"] = id
		}
		collections = append(collections, collection)
		indices[c.ID] = i
	}
	ciphers := []json.RawMessage{}
	relationships := []relation{}
	kinds := map[int]bool{}
	for i, item := range plan.file.Items {
		// The official endpoint returns no new IDs and ignores lifecycle/folder
		// fields. Refuse these records rather than silently restoring them active.
		if item["deletedDate"] != nil || item["archivedDate"] != nil || item["folderId"] != nil {
			return result, ErrUnsupportedEdit
		}
		identity, err := backupItemIdentity(item)
		if err != nil {
			return result, err
		}
		if err := validateOrganizationBackupItem(item); err != nil {
			return result, err
		}
		kinds[identity.Type] = true
		encrypted, err := encryptImportedItem(item, data.keys[orgID], s.account)
		if err != nil {
			return result, err
		}
		object, err := documentObject(encrypted)
		if err != nil {
			return result, err
		}
		object["organizationId"] = orgID
		object["folderId"] = nil
		raw, err := json.Marshal(object)
		if err != nil {
			return result, ErrProtocol
		}
		ciphers = append(ciphers, raw)
		relations, ok := item["collectionIds"].([]any)
		if !ok {
			return result, ErrProtocol
		}
		seen := map[string]bool{}
		for _, rawID := range relations {
			id, ok := rawID.(string)
			if !ok || seen[id] {
				return result, ErrProtocol
			}
			index, exists := indices[id]
			if !exists {
				return result, ErrProtocol
			}
			seen[id] = true
			relationships = append(relationships, relation{Key: i, Value: index})
		}
		result.IDs = append(result.IDs, identity.ID)
	}
	guard := s.orgOperationGuardLocked()
	for kind := range kinds {
		guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, orgID, kind, persist, guard)
		if err != nil {
			return result, err
		}
	}
	body, err := json.Marshal(map[string]any{"ciphers": ciphers, "collections": collections, "collectionRelationships": relationships})
	if err != nil {
		return result, ErrProtocol
	}
	before, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return result, err
	}
	beforeIDs := organizationCipherIDs(before.ciphers, orgID)
	if err := s.checkOperationPoliciesLocked(ctx, before); err != nil {
		return result, err
	}
	result.ReconcileRequired = true
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, "/api/ciphers/import-organization?organizationId="+url.QueryEscape(orgID), "application/json", string(body), persist, guard)
	reconciliation := s.reconcileOrganizationImportLocked(ctx, orgID, beforeIDs, ciphers, plan, mappings, persist)
	result.ImportReconciliation = &reconciliation
	if err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return result, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	if ctx.Err() != nil {
		return result, &MutationUncertainError{Cause: ErrCancelled}
	}
	// Applied deliberately remains false; no per-item receipt exists upstream.
	return result, nil
}
