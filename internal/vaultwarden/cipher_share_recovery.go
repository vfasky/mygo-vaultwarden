// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"reflect"
)

const cipherShareRecoveryFormat = "mygo-legacy-share-recovery"

type cipherShareRecoveryHeader struct {
	Format         string `json:"format"`
	Version        int    `json:"version"`
	Scope          Scope  `json:"scope"`
	OperationID    string `json:"operationId"`
	CipherID       string `json:"cipherId"`
	OrganizationID string `json:"organizationId"`
	Revision       string `json:"revision"`
}
type cipherShareRecoveryFile struct {
	cipherShareRecoveryHeader
	Ciphertext string `json:"ciphertext"`
}
type cipherShareRecoveryPayload struct {
	cipherShareRecoveryHeader
	Stage    string          `json:"stage"`
	Original json.RawMessage `json:"original"`
	Target   json.RawMessage `json:"target"`
	ItemKey  string          `json:"itemKey"`
}

// Share recovery states classify a fresh inspection; they are not recovery-file fields.
const (
	ShareRecoveryMissing         = "missing"
	ShareRecoveryExternalChange  = "external_change"
	ShareRecoveryOldPersonal     = "old_personal"
	ShareRecoveryNewOrganization = "new_organization"
	ShareRecoveryOldWrapping     = "old_wrapping"
	ShareRecoveryNewWrapping     = "new_wrapping"
	ShareRecoveryRemoteAdded     = "remote_added"
)

func ShareRecoveryStateText(state string) string {
	switch state {
	case ShareRecoveryMissing:
		return i18n.T("state.share.missing")
	case ShareRecoveryExternalChange:
		return i18n.T("state.share.external_change")
	case ShareRecoveryOldPersonal:
		return i18n.T("state.share.old_personal")
	case ShareRecoveryNewOrganization:
		return i18n.T("state.share.new_organization")
	case ShareRecoveryOldWrapping:
		return i18n.T("state.share.old_wrapping")
	case ShareRecoveryNewWrapping:
		return i18n.T("state.share.new_wrapping")
	case ShareRecoveryRemoteAdded:
		return i18n.T("state.share.remote_added")
	default:
		return state
	}
}

type CipherShareRecoveryAttachment struct{ ID, State string }
type CipherShareRecoveryInspection struct {
	CipherID, OrganizationID, OperationID, CipherState string
	Attachments                                        []CipherShareRecoveryAttachment
	CanRepair                                          bool
}

func encodeCipherShareRecovery(scope Scope, original CipherDocument, target map[string]any, orgID, wrappedItemKey string, ownerKey []byte) ([]byte, error) {
	var meta struct{ ID, RevisionDate string }
	if json.Unmarshal(original.JSON, &meta) != nil || !validObjectID(meta.ID) || meta.RevisionDate == "" {
		return nil, ErrProtocol
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrEncryption
	}
	header := cipherShareRecoveryHeader{Format: cipherShareRecoveryFormat, Version: 1, Scope: scope, OperationID: hex.EncodeToString(nonce), CipherID: meta.ID, OrganizationID: orgID, Revision: meta.RevisionDate}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return nil, ErrProtocol
	}
	defer clear(targetJSON)
	payload := cipherShareRecoveryPayload{cipherShareRecoveryHeader: header, Stage: "prepared", Original: original.JSON, Target: targetJSON, ItemKey: wrappedItemKey}
	plain, err := json.Marshal(payload)
	if err != nil || len(plain) > MaxBackupSize/2 {
		clear(plain)
		return nil, ErrValidation
	}
	defer clear(plain)
	ciphertext, err := vaultcrypto.EncryptString(plain, ownerKey)
	if err != nil {
		return nil, err
	}
	file, err := json.Marshal(cipherShareRecoveryFile{cipherShareRecoveryHeader: header, Ciphertext: ciphertext})
	if err != nil {
		return nil, ErrProtocol
	}
	// Read using freshly decoded material, not the in-memory migration key.
	recovered, err := decodeCipherShareRecovery(file, scope, ownerKey)
	if err != nil {
		clear(file)
		return nil, err
	}
	clear(recovered.Original)
	clear(recovered.Target)
	return file, nil
}
func decodeCipherShareRecovery(raw []byte, scope Scope, key []byte) (cipherShareRecoveryPayload, error) {
	var payload cipherShareRecoveryPayload
	if strictJSON(raw) != nil {
		return payload, ErrProtocol
	}
	var envelope cipherShareRecoveryFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Format != cipherShareRecoveryFormat || envelope.Version != 1 || envelope.Scope != scope || !validObjectID(envelope.CipherID) || !validObjectID(envelope.OrganizationID) || len(envelope.OperationID) != 32 || envelope.Revision == "" {
		return payload, ErrIdentity
	}
	if _, err := hex.DecodeString(envelope.OperationID); err != nil {
		return payload, ErrProtocol
	}
	plain, err := vaultcrypto.DecryptString(envelope.Ciphertext, key)
	if err != nil {
		return payload, err
	}
	defer clear(plain)
	if strictJSON(plain) != nil {
		return payload, ErrProtocol
	}
	decoder = json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || payload.cipherShareRecoveryHeader != envelope.cipherShareRecoveryHeader || payload.Stage != "prepared" {
		return payload, ErrProtocol
	}
	original, err := documentObject(CipherDocument{JSON: payload.Original})
	if err != nil {
		return payload, err
	}
	target, err := documentObject(CipherDocument{JSON: payload.Target})
	if err != nil {
		return payload, err
	}
	if original["id"] != payload.CipherID || original["organizationId"] != nil || original["revisionDate"] != payload.Revision || target["id"] != payload.CipherID || target["organizationId"] != payload.OrganizationID {
		return payload, ErrIdentity
	}
	itemKey, err := vaultcrypto.DecryptString(payload.ItemKey, key)
	if err != nil {
		return payload, err
	}
	defer clear(itemKey)
	if len(itemKey) != 64 || bytes.Equal(itemKey, key) {
		return payload, ErrEncryption
	}
	if err = transformCompleteCipher(target, itemKey, false); err != nil {
		return payload, err
	}
	return payload, nil
}

func shareRecoveryComparable(object map[string]any) map[string]any {
	result := map[string]any{}
	ignored := map[string]bool{}
	for _, name := range []string{"object", "id", "revisionDate", "creationDate", "lastKnownRevisionDate", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedFor", "attachments", "attachments2", "collectionIds"} {
		ignored[name] = true
	}
	for key, value := range object {
		if !ignored[key] {
			result[key] = value
		}
	}
	// Vaultwarden's response derives login.uri from the first canonical URI,
	// replacing the independently encrypted legacy alias in the request. Compare
	// that one documented alias as the server represents it; every other field
	// (including unknown null extensions) remains part of the exact comparison.
	normalizeResponseLoginAlias(result)
	return result
}
func shareRecoveryAttachments(object map[string]any) (map[string]map[string]any, error) {
	result := map[string]map[string]any{}
	if object["attachments"] == nil {
		return result, nil
	}
	rows, ok := object["attachments"].([]any)
	if !ok {
		return nil, ErrProtocol
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, ErrProtocol
		}
		id, ok := row["id"].(string)
		if !ok || !validObjectID(id) || result[id] != nil {
			return nil, ErrProtocol
		}
		result[id] = map[string]any{"key": row["key"], "fileName": row["fileName"]}
	}
	return result, nil
}
func shareRecoveryAttachmentSnapshots(object map[string]any) (map[string]map[string]any, error) {
	if _, err := shareRecoveryAttachments(object); err != nil {
		return nil, err
	}
	result := map[string]map[string]any{}
	rows, _ := object["attachments"].([]any)
	for _, value := range rows {
		row := value.(map[string]any)
		copy := map[string]any{}
		for key, value := range row {
			if key != "url" {
				copy[key] = value
			}
		}
		result[row["id"].(string)] = copy
	}
	return result, nil
}

func inspectShareRecovery(payload cipherShareRecoveryPayload, current CipherDocument) (CipherShareRecoveryInspection, error) {
	result := CipherShareRecoveryInspection{CipherID: payload.CipherID, OrganizationID: payload.OrganizationID, OperationID: payload.OperationID, CipherState: ShareRecoveryMissing}
	if len(current.JSON) == 0 {
		return result, nil
	}
	old, err := documentObject(CipherDocument{JSON: payload.Original})
	if err != nil {
		return result, err
	}
	target, err := documentObject(CipherDocument{JSON: payload.Target})
	if err != nil {
		return result, err
	}
	actual, err := documentObject(current)
	if err != nil {
		return result, err
	}
	result.CipherState = ShareRecoveryExternalChange
	if reflect.DeepEqual(shareRecoveryComparable(actual), shareRecoveryComparable(old)) {
		result.CipherState = ShareRecoveryOldPersonal
	}
	if reflect.DeepEqual(shareRecoveryComparable(actual), shareRecoveryComparable(target)) {
		result.CipherState = ShareRecoveryNewOrganization
	}
	originals, err := shareRecoveryAttachmentSnapshots(old)
	if err != nil {
		return result, err
	}
	desired, err := shareRecoveryAttachmentSnapshots(target)
	if err != nil {
		return result, err
	}
	observed, err := shareRecoveryAttachmentSnapshots(actual)
	if err != nil {
		return result, err
	}
	safe := result.CipherState == ShareRecoveryOldPersonal || result.CipherState == ShareRecoveryNewOrganization
	needsRepair := false
	for id, original := range originals {
		state := ShareRecoveryExternalChange
		if observed[id] == nil {
			state = ShareRecoveryMissing
		} else if reflect.DeepEqual(observed[id], original) {
			state = ShareRecoveryOldWrapping
		} else if reflect.DeepEqual(observed[id], desired[id]) {
			state = ShareRecoveryNewWrapping
		}
		result.Attachments = append(result.Attachments, CipherShareRecoveryAttachment{ID: id, State: state})
		if state == ShareRecoveryExternalChange || state == ShareRecoveryMissing {
			safe = false
		}
		if (result.CipherState == ShareRecoveryOldPersonal && state == ShareRecoveryNewWrapping) || (result.CipherState == ShareRecoveryNewOrganization && state == ShareRecoveryOldWrapping) {
			needsRepair = true
		}
	}
	for id := range observed {
		if originals[id] == nil {
			safe = false
			result.Attachments = append(result.Attachments, CipherShareRecoveryAttachment{ID: id, State: ShareRecoveryRemoteAdded})
		}
	}
	result.CanRepair = safe && needsRepair
	return result, nil
}

// InspectCipherShareRecovery requires a new server read. The encrypted file is
// recovery material only: it is neither a write authorization nor permission to
// take an organization-owned item back into a personal vault.
func (s *Session) InspectCipherShareRecovery(ctx context.Context, vault *VaultData, raw []byte, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherShareRecoveryInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherShareRecoveryInspection{}, err
	}
	defer finish()
	payload, _, _, inspection, err := s.inspectCipherShareRecoveryLocked(ctx, vault, raw, grant, persist)
	defer clear(payload.Original)
	defer clear(payload.Target)
	return inspection, err
}
func (s *Session) inspectCipherShareRecoveryLocked(ctx context.Context, vault *VaultData, raw []byte, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (cipherShareRecoveryPayload, CipherDocument, map[string]any, CipherShareRecoveryInspection, error) {
	var payload cipherShareRecoveryPayload
	var current CipherDocument
	var inspection CipherShareRecoveryInspection
	if vault == nil {
		return payload, current, nil, inspection, ErrIdentity
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return payload, current, nil, inspection, err
	}
	var err error
	payload, err = decodeCipherShareRecovery(raw, vault.Scope, s.key)
	if err != nil {
		return payload, current, nil, inspection, err
	}
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return payload, current, nil, inspection, err
	}
	for _, doc := range policies.ciphers {
		var meta struct{ ID string }
		if json.Unmarshal(doc, &meta) != nil {
			return payload, current, nil, inspection, ErrProtocol
		}
		if meta.ID == payload.CipherID {
			if current.JSON != nil {
				return payload, current, nil, inspection, ErrProtocol
			}
			current = CipherDocument{JSON: doc}
		}
	}
	if current.JSON == nil {
		inspection, err = inspectShareRecovery(payload, current)
		return payload, current, nil, inspection, err
	}
	object, err := documentObject(current)
	if err != nil {
		return payload, current, nil, inspection, err
	}
	var authenticated CipherDocument
	if orgID, ok := object["organizationId"].(string); ok && orgID != "" {
		data, e := s.organizationVaultLocked(vault)
		if e != nil {
			return payload, current, nil, inspection, e
		}
		authenticated, _, err = s.organizationDocumentLocked(vault, payload.CipherID, data)
		data.close()
	} else {
		authenticated, err = s.personalDocumentLocked(vault, payload.CipherID)
	}
	if err != nil {
		return payload, current, nil, inspection, err
	}
	// Publish/accept the fresh snapshot before inspecting mixed metadata. A stale
	// local snapshot must not authorize repair against a newer server document.
	if !attachmentSameDocument(authenticated, current, false, false) {
		return payload, current, nil, inspection, ErrConflict
	}
	var meta struct {
		Reprompt           int
		Type               int
		OrganizationID     *string
		Edit, ViewPassword bool
		DeletedDate        *string
	}
	if json.Unmarshal(current.JSON, &meta) != nil {
		return payload, current, nil, inspection, ErrProtocol
	}
	if !meta.ViewPassword || policies.restricts(meta.OrganizationID, meta.Type) || (meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, authenticated)) {
		return payload, current, nil, inspection, ErrPermission
	}
	inspection, err = inspectShareRecovery(payload, current)
	inspection.CanRepair = inspection.CanRepair && meta.Edit && meta.DeletedDate == nil
	return payload, current, object, inspection, err
}

// RepairCipherShareRecovery repairs only attachment wrappers toward the current
// cipher's already-established ownership/key. All cipher data must still match
// the saved old or new version; external edits/missing/additional files refuse.
func (s *Session) RepairCipherShareRecovery(ctx context.Context, vault *VaultData, raw []byte, confirmed bool, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	if !confirmed {
		return ErrPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	payload, current, object, inspection, err := s.inspectCipherShareRecoveryLocked(ctx, vault, raw, grant, persist)
	defer clear(payload.Original)
	defer clear(payload.Target)
	if err != nil {
		return err
	}
	if !inspection.CanRepair {
		return ErrConflict
	}
	desiredRaw := payload.Original
	if inspection.CipherState == ShareRecoveryNewOrganization {
		desiredRaw = payload.Target
	}
	desired, err := documentObject(CipherDocument{JSON: desiredRaw})
	if err != nil {
		return err
	}
	wrappers, err := shareRecoveryAttachments(desired)
	if err != nil {
		return err
	}
	object["attachments2"], object["encryptedFor"], object["lastKnownRevisionDate"] = wrappers, s.account, object["revisionDate"]
	body, err := json.Marshal(object)
	if err != nil {
		return ErrProtocol
	}
	defer clear(body)
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		var meta struct{ Reprompt int }
		json.Unmarshal(current.JSON, &meta)
		if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, current) {
			return ErrPermission
		}
		return nil
	}
	var meta struct {
		Type           int
		OrganizationID *string
	}
	json.Unmarshal(current.JSON, &meta)
	if meta.OrganizationID == nil {
		guard, err = s.personalCipherPolicyGuardLocked(ctx, meta.Type, persist, guard)
	} else {
		var data *organizationVault
		data, err = s.organizationVaultLocked(vault)
		if err == nil {
			guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, *meta.OrganizationID, meta.Type, persist, guard)
			data.close()
		}
	}
	if err != nil {
		return err
	}
	status, _, err := s.authenticatedGuardedLocked(ctx, http.MethodPut, "/api/ciphers/"+payload.CipherID, "application/json", string(body), persist, guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: statusError(status)}
	}
	return nil
}
