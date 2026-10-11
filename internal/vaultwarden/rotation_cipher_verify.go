// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"reflect"
)

// These states are observations, not permission to clear a recovery journal.
// Empty inventories return new only after exact inventory validation.
type RotationCipherState string

const (
	RotationCipherOld          RotationCipherState = "old"
	RotationCipherNew          RotationCipherState = "new"
	RotationCipherMixed        RotationCipherState = "mixed"
	RotationCipherExternal     RotationCipherState = "external"
	RotationCipherMissing      RotationCipherState = "missing"
	RotationCipherUnverifiable RotationCipherState = "unverifiable"
)

type RotationCipherResourceVerification struct {
	Kind  string
	ID    string
	State RotationCipherState
}
type RotationCipherVerification struct {
	State     RotationCipherState
	Resources []RotationCipherResourceVerification
}
type RotationCipherVerificationInput struct {
	Scope, CurrentScope       Scope
	OriginalSync, CurrentSync json.RawMessage
	Target                    RotationCipherResources
	OldUserKey, NewUserKey    []byte
}

// rotationCipherExpected projects the stored request onto the original sync.
// All request fields must be present exactly as conversion emits them; no raw
// reply fields or silently ignored extensions are accepted as a request.
func rotationCipherExpected(old map[string]any, raw json.RawMessage, account string) (map[string]any, error) {
	dto, err := rotationCipherObject(raw)
	if err != nil {
		return nil, err
	}
	allowed := append(append([]string{}, rotationCipherDTOFields...), "encryptedFor", "lastKnownRevisionDate", "attachments2")
	if err = copyKeys(dto, allowed...); err != nil {
		return nil, err
	}
	oldID, oldIDOK := old["id"].(string)
	dtoID, dtoIDOK := dto["id"].(string)
	oldRevision, oldRevisionOK := old["revisionDate"].(string)
	dtoRevision, dtoRevisionOK := dto["lastKnownRevisionDate"].(string)
	if !oldIDOK || !dtoIDOK || !validObjectID(oldID) || !oldRevisionOK || !dtoRevisionOK {
		return nil, ErrProtocol
	}
	if dtoID != oldID || dto["encryptedFor"] != account || dtoRevision != oldRevision {
		return nil, ErrIdentity
	}
	encoded, _ := json.Marshal(old)
	expected, err := rotationCipherObject(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	for _, name := range rotationCipherDTOFields {
		_, had := old[name]
		value, has := dto[name]
		if had != has {
			return nil, ErrProtocol
		}
		if has {
			expected[name] = value
		}
	}
	wrappers, ok := dto["attachments2"].(map[string]any)
	if !ok {
		return nil, ErrProtocol
	}
	attachments, err := backupObjectRows(expected["attachments"])
	if err != nil {
		return nil, err
	}
	if len(wrappers) != len(attachments) {
		return nil, ErrProtocol
	}
	for _, attachment := range attachments {
		id, ok := attachment["id"].(string)
		if !ok || !validObjectID(id) {
			return nil, ErrProtocol
		}
		wrapper, ok := wrappers[id].(map[string]any)
		if !ok || len(wrapper) != 2 {
			return nil, ErrProtocol
		}
		for _, name := range []string{"key", "fileName"} {
			text, ok := wrapper[name].(string)
			if !ok || text == "" {
				return nil, ErrEncryption
			}
			attachment[name] = text
		}
	}
	normalizeResponseLoginAlias(expected)
	return expected, nil
}

// Semantic validation is separate from ciphertext observation. It proves the
// recorded target preserves every field and independent binary key. No fresh
// randomized ciphertext is generated during recovery verification.
func rotationCipherPlain(object map[string]any, key []byte) (map[string]any, error) {
	encoded, _ := json.Marshal(object)
	result, err := rotationCipherObject(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	itemKey, err := cipherItemKey(result, key)
	if err != nil {
		return nil, err
	}
	defer clear(itemKey)
	if err = transformCompleteCipher(result, itemKey, false); err != nil {
		return nil, err
	}
	if err = prepareLegacyCipherURIs(result); err != nil {
		return nil, err
	}
	if wrapped, _ := result["key"].(string); wrapped != "" {
		result["key"] = string(itemKey)
	}
	rows, err := backupObjectRows(result["attachments"])
	if err != nil {
		return nil, err
	}
	for _, attachment := range rows {
		if err = transformField(attachment, "fileName", itemKey, false); err != nil {
			return nil, err
		}
		wrapped, ok := attachment["key"].(string)
		if !ok || wrapped == "" {
			return nil, ErrEncryption
		}
		plain, e := vaultcrypto.DecryptString(wrapped, itemKey)
		if e != nil {
			return nil, e
		}
		if len(plain) != 64 {
			clear(plain)
			return nil, ErrEncryption
		}
		attachment["key"] = string(plain)
		clear(plain)
	}
	normalizeResponseLoginAlias(result)
	return result, nil
}
func rotationCipherComparable(object map[string]any, personal bool) (map[string]any, error) {
	// Callers exclusively own these decoded maps. Revision advances in cipher.save;
	// attachment URL is generated at response time (attachment.rs::to_json).
	if personal {
		delete(object, "revisionDate")
	}
	rows, err := backupObjectRows(object["attachments"])
	if err != nil {
		return nil, err
	}
	for _, attachment := range rows {
		if _, exists := attachment["url"]; exists {
			attachment["url"] = ""
		}
	}
	normalizeResponseLoginAlias(object)
	return object, nil
}
func rotationCipherRows(rows []json.RawMessage) (map[string]map[string]any, error) {
	result := map[string]map[string]any{}
	for _, raw := range rows {
		object, err := rotationCipherObject(raw)
		if err != nil {
			return nil, err
		}
		id, ok := object["id"].(string)
		if !ok || !validObjectID(id) || result[id] != nil {
			return nil, ErrProtocol
		}
		if _, err := shareRecoveryAttachments(object); err != nil {
			return nil, err
		}
		rows, err := backupObjectRows(object["attachments"])
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if url, exists := row["url"]; exists {
				if _, ok := url.(string); !ok {
					return nil, ErrProtocol
				}
			}
		}
		result[id] = object
	}
	return result, nil
}

// Exact recursive old/new leaf comparison also detects partial fields within a
// cipher or attachment. Keys and array order remain part of the contract.
func rotationCipherLeaves(old, target, current any) (oldSeen, newSeen, valid bool) {
	if reflect.DeepEqual(current, old) && reflect.DeepEqual(current, target) {
		return false, false, true
	}
	if reflect.DeepEqual(current, old) {
		return true, false, true
	}
	if reflect.DeepEqual(current, target) {
		return false, true, true
	}
	om, ok := old.(map[string]any)
	tm, tok := target.(map[string]any)
	cm, cok := current.(map[string]any)
	if ok && tok && cok && len(om) == len(tm) && len(om) == len(cm) {
		for name, o := range om {
			t, hasT := tm[name]
			c, hasC := cm[name]
			if !hasT || !hasC {
				return false, false, false
			}
			a, b, v := rotationCipherLeaves(o, t, c)
			if !v {
				return false, false, false
			}
			oldSeen = oldSeen || a
			newSeen = newSeen || b
		}
		return oldSeen, newSeen, true
	}
	oa, ok := old.([]any)
	ta, tok := target.([]any)
	ca, cok := current.([]any)
	if ok && tok && cok && len(oa) == len(ta) && len(oa) == len(ca) {
		for i := range oa {
			a, b, v := rotationCipherLeaves(oa[i], ta[i], ca[i])
			if !v {
				return false, false, false
			}
			oldSeen = oldSeen || a
			newSeen = newSeen || b
		}
		return oldSeen, newSeen, true
	}
	return false, false, false
}
func rotationCipherObserved(old, target, current any) RotationCipherState {
	a, b, valid := rotationCipherLeaves(old, target, current)
	if !valid {
		return RotationCipherExternal
	}
	if a && b {
		return RotationCipherMixed
	}
	if a {
		return RotationCipherOld
	}
	return RotationCipherNew
}

// VerifyAccountRotationCipherResources is read-only and borrows all secrets.
// Scope/CurrentScope must come from the controller's authenticated old journal
// and fresh login. It does not attest fresh authentication, epochs, Sends,
// recovery recipients, or attachment binary downloads and never repairs/replays.
func VerifyAccountRotationCipherResources(ctx context.Context, input RotationCipherVerificationInput) (RotationCipherVerification, error) {
	result := RotationCipherVerification{State: RotationCipherUnverifiable, Resources: []RotationCipherResourceVerification{}}
	if input.Scope != input.CurrentScope {
		return result, ErrIdentity
	}
	borrowed := AccountRotationInput{Scope: input.Scope, Sync: input.OriginalSync, OldUserKey: input.OldUserKey, NewUserKey: input.NewUserKey}
	if len(input.NewUserKey) != 64 || bytes.Equal(input.OldUserKey, input.NewUserKey) {
		return result, ErrEncryption
	}
	ready, err := AnalyzeAccountRotationCipherResources(ctx, borrowed)
	if err != nil {
		return result, err
	}
	if !ready.Ready {
		return result, &RotationCipherPreparationError{Readiness: ready}
	}
	original, _ := rotationCipherInventoryFrom(input.OriginalSync, input.Scope)
	current, err := rotationCipherInventoryFrom(input.CurrentSync, input.CurrentScope)
	if err != nil {
		return result, err
	}
	originalCiphers, err := rotationCipherRows(original.ciphers)
	if err != nil {
		return result, err
	}
	currentCiphers, err := rotationCipherRows(current.ciphers)
	if err != nil {
		return result, err
	}
	targets, err := rotationCipherRows(input.Target.Ciphers)
	if err != nil || input.Target.Ciphers == nil {
		return result, ErrProtocol
	}
	want := []string{}
	got := []string{}
	for id, object := range originalCiphers {
		if object["organizationId"] == nil {
			want = append(want, id)
		}
	}
	for id := range targets {
		got = append(got, id)
	}
	if err = accountExactIDs(want, got); err != nil {
		return result, err
	}
	for _, raw := range original.ciphers {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		old, err := rotationCipherObject(raw)
		if err != nil {
			return result, err
		}
		id, ok := old["id"].(string)
		if !ok || !validObjectID(id) {
			return result, ErrProtocol
		}
		expected := old
		personal := old["organizationId"] == nil
		if personal {
			targetRaw, _ := json.Marshal(targets[id])
			expected, err = rotationCipherExpected(old, targetRaw, input.Scope.Account)
			clear(targetRaw)
			if err != nil {
				return result, rotationCipherError(id, err)
			}
			if err = rotationCipherValidate(expected, input.Scope.Account); err != nil {
				return result, err
			}
			plainOld, e := rotationCipherPlain(old, input.OldUserKey)
			if e != nil {
				return result, e
			}
			plainNew, e := rotationCipherPlain(expected, input.NewUserKey)
			if e != nil {
				return result, e
			}
			if !reflect.DeepEqual(plainOld, plainNew) {
				return result, ErrConflict
			}
		}
		state := RotationCipherMissing
		if actual := currentCiphers[id]; actual != nil {
			// Validate the structure before comparable's attachment traversal.
			if _, e := shareRecoveryAttachments(actual); e != nil {
				state = RotationCipherUnverifiable
			} else {
				oldComparable, e := rotationCipherComparable(old, personal)
				if e != nil {
					return result, e
				}
				expectedComparable, e := rotationCipherComparable(expected, personal)
				if e != nil {
					return result, e
				}
				actualComparable, e := rotationCipherComparable(actual, personal)
				if e != nil {
					return result, e
				}
				state = rotationCipherObserved(oldComparable, expectedComparable, actualComparable)
			}
		}
		result.Resources = append(result.Resources, RotationCipherResourceVerification{Kind: "cipher", ID: id, State: state})
	}
	for id := range currentCiphers {
		if originalCiphers[id] == nil {
			result.Resources = append(result.Resources, RotationCipherResourceVerification{Kind: "cipher", ID: id, State: RotationCipherExternal})
		}
	}
	originalFolders, err := rotationCipherRows(original.folders)
	if err != nil {
		return result, err
	}
	currentFolders, err := rotationCipherRows(current.folders)
	if err != nil {
		return result, err
	}
	folderTargets := map[string]AccountRotationFolder{}
	if input.Target.Folders == nil {
		return result, ErrProtocol
	}
	for _, folder := range input.Target.Folders {
		if folderTargets[folder.ID].ID != "" {
			return result, ErrProtocol
		}
		folderTargets[folder.ID] = folder
	}
	want = []string{}
	got = []string{}
	for id := range originalFolders {
		want = append(want, id)
	}
	for id := range folderTargets {
		got = append(got, id)
	}
	if err = accountExactIDs(want, got); err != nil {
		return result, err
	}
	for _, raw := range original.folders {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		folder, e := rotationCipherFolder(raw)
		if e != nil {
			return result, e
		}
		oldPlain, e := vaultcrypto.DecryptString(folder.Name, input.OldUserKey)
		if e != nil {
			return result, e
		}
		newPlain, e := vaultcrypto.DecryptString(folderTargets[folder.ID].Name, input.NewUserKey)
		same := reflect.DeepEqual(oldPlain, newPlain)
		clear(oldPlain)
		clear(newPlain)
		if e != nil {
			return result, e
		}
		if !same {
			return result, ErrConflict
		}
		old := originalFolders[folder.ID]
		expected, _ := rotationCipherObject(raw)
		expected["name"] = folderTargets[folder.ID].Name
		state := RotationCipherMissing
		if actual := currentFolders[folder.ID]; actual != nil {
			if _, e := rotationCipherFolder(mustRotationCipherJSON(actual)); e != nil {
				state = RotationCipherUnverifiable
			} else {
				// Folder::save updates revisionDate; all other metadata stays exact.
				delete(old, "revisionDate")
				delete(expected, "revisionDate")
				delete(actual, "revisionDate")
				state = rotationCipherObserved(old, expected, actual)
			}
		}
		result.Resources = append(result.Resources, RotationCipherResourceVerification{Kind: "folder", ID: folder.ID, State: state})
	}
	for id := range currentFolders {
		if originalFolders[id] == nil {
			result.Resources = append(result.Resources, RotationCipherResourceVerification{Kind: "folder", ID: id, State: RotationCipherExternal})
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	result.State = RotationCipherNew
	seenOld, seenNew := false, false
	for _, row := range result.Resources {
		switch row.State {
		case RotationCipherUnverifiable, RotationCipherMissing, RotationCipherExternal:
			result.State = row.State
			return result, nil
		case RotationCipherMixed:
			seenOld = true
			seenNew = true
		case RotationCipherOld:
			seenOld = true
		case RotationCipherNew:
			// Unchanged organization resources do not turn an all-old rotation mixed.
			if row.Kind != "cipher" || originalCiphers[row.ID]["organizationId"] == nil {
				seenNew = true
			}
		}
	}
	if seenOld && seenNew {
		result.State = RotationCipherMixed
	} else if seenOld {
		result.State = RotationCipherOld
	}
	return result, nil
}
func mustRotationCipherJSON(object map[string]any) json.RawMessage {
	raw, _ := json.Marshal(object)
	return raw
}
