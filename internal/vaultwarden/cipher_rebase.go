// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sort"
)

// CipherChange describes presence of changes, never their secret values. Paths
// are fixed schema names, not user supplied field names or plaintext.
type CipherChange struct {
	Path          string
	Local, Remote bool
	CanApply      bool
	SameValue     bool
}

// CipherRebase is an in-process comparison against one authenticated snapshot.
// Private fields prevent a UI choice from changing permissions or key material.
type CipherRebase struct {
	session  *Session
	revision string
	latest   CipherDocument
	merged   CipherFields
	changes  []CipherChange
	values   map[string]any
	grant    *ItemAuthorization
}

func cipherEditableValues(f CipherFields) map[string]any {
	values := map[string]any{"name": f.Name, "notes": f.Notes, "folderId": f.FolderID, "favorite": f.Favorite, "fields": f.Fields, "passwordHistory": f.PasswordHistory}
	section := cipherSections[f.Type]
	fields := map[string]map[string]any{"login": f.Login, "secureNote": f.SecureNote, "card": f.Card, "identity": f.Identity, "sshKey": f.SSHKey, "bankAccount": f.BankAccount, "driversLicense": f.DriversLicense, "passport": f.Passport}[section]
	for _, key := range cipherSecrets[section] {
		values[section+"."+key] = fields[key]
	}
	if f.Type == 1 {
		values["login.uris"] = fields["uris"]
	}
	if f.Type == 2 {
		values["secureNote.type"] = fields["type"]
	}
	return values
}

// ComparePersonalCipher never performs network IO. Call after a successful full
// sync, binding its authenticated revision. Even if reprompt was removed remotely,
// comparing a formerly protected draft requires fresh authorization of the item.
func (s *Session) ComparePersonalCipher(vault *VaultData, revision string, base CipherDocument, draft CipherFields, grant *ItemAuthorization) (*CipherRebase, []CipherChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision == "" || revision != s.authorizationRevision {
		return nil, nil, ErrExpired
	}
	latest, err := s.personalDocumentLocked(vault, draft.ID)
	if err != nil {
		return nil, nil, err
	}
	oldObject, err := documentObject(base)
	if err != nil {
		return nil, nil, err
	}
	newObject, err := documentObject(latest)
	if err != nil {
		return nil, nil, err
	}
	// Ownership, deletion, schema and key transitions must be reviewed by opening
	// the new item, never by carrying an old draft over the transition.
	for _, key := range []string{"id", "type", "organizationId", "encryptedByKeyId", "reprompt", "deletedDate"} {
		if !reflect.DeepEqual(oldObject[key], newObject[key]) {
			return nil, nil, ErrConflict
		}
	}
	if oldObject["organizationId"] != nil || newObject["deletedDate"] != nil {
		return nil, nil, ErrPermission
	}
	oldKey, err := cipherItemKey(oldObject, s.key)
	if err != nil {
		return nil, nil, err
	}
	defer clear(oldKey)
	newKey, err := cipherItemKey(newObject, s.key)
	if err != nil {
		return nil, nil, err
	}
	defer clear(newKey)
	if !bytes.Equal(oldKey, newKey) {
		return nil, nil, ErrConflict
	}
	original, err := DecryptCipherDocument(base, s.key)
	if err != nil {
		return nil, nil, err
	}
	remote, err := DecryptCipherDocument(latest, s.key)
	if err != nil {
		return nil, nil, err
	}
	if !original.Edit || !remote.Edit || !original.ViewPassword || !remote.ViewPassword {
		return nil, nil, ErrPermission
	}
	if (original.Reprompt != 0 || remote.Reprompt != 0) && !s.validItemAuthorizationLocked(grant, latest) {
		return nil, nil, ErrPermission
	}
	if draft.ID != original.ID || draft.Type != original.Type || draft.RevisionDate != original.RevisionDate || !historySubsequence(draft.PasswordHistory, original.PasswordHistory) {
		return nil, nil, ErrConflict
	}
	// Round trip creates independent maps, slices and pointers owned by the plan.
	data, err := json.Marshal(draft)
	if err != nil {
		return nil, nil, ErrProtocol
	}
	defer clear(data)
	var local CipherFields
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&local) != nil {
		return nil, nil, ErrProtocol
	}
	b, l, r := cipherEditableValues(original), cipherEditableValues(local), cipherEditableValues(remote)
	plan := &CipherRebase{session: s, revision: revision, latest: latest, merged: remote, values: l, grant: grant}
	for path, baseline := range b {
		change := CipherChange{Path: path, Local: !reflect.DeepEqual(baseline, l[path]), Remote: !reflect.DeepEqual(baseline, r[path]), CanApply: true, SameValue: reflect.DeepEqual(l[path], r[path])}
		// Arrays have no stable row IDs. A simultaneous remote edit cannot safely be
		// matched by position; retain remote rows and require editing the fresh form.
		if (path == "fields" || path == "login.uris") && change.Local && change.Remote && !reflect.DeepEqual(l[path], r[path]) {
			change.CanApply = false
		}
		if path == "passwordHistory" && change.Local {
			// Remove only observed entries, preserving remote additions and extensions.
			removed := []map[string]any{}
			i := 0
			for _, entry := range original.PasswordHistory {
				if i < len(local.PasswordHistory) && reflect.DeepEqual(entry, local.PasswordHistory[i]) {
					i++
				} else {
					removed = append(removed, entry)
				}
			}
			// History is newest first. Match from the end so newly prepended
			// duplicates do not get mistaken for the entries we observed.
			drop := make([]bool, len(remote.PasswordHistory))
			for index := len(remote.PasswordHistory) - 1; index >= 0; index-- {
				entry := remote.PasswordHistory[index]
				match := -1
				for j, old := range removed {
					if reflect.DeepEqual(entry, old) {
						match = j
						break
					}
				}
				if match >= 0 {
					drop[index] = true
					removed = append(removed[:match], removed[match+1:]...)
				}
			}
			kept := make([]map[string]any, 0, len(remote.PasswordHistory))
			for index, entry := range remote.PasswordHistory {
				if !drop[index] {
					kept = append(kept, entry)
				}
			}
			plan.values[path] = kept
		}
		if change.Local || change.Remote {
			plan.changes = append(plan.changes, change)
		}
	}
	sort.Slice(plan.changes, func(i, j int) bool { return plan.changes[i].Path < plan.changes[j].Path })
	return plan, append([]CipherChange(nil), plan.changes...), nil
}

// ApplyPersonalCipherComparison only returns a fresh draft; saving is a separate
// explicit operation and still uses the server's non-CAS revision check.
func (s *Session) ApplyPersonalCipherComparison(vault *VaultData, revision string, plan *CipherRebase, localPaths []string) (CipherDocument, CipherFields, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if plan == nil || plan.session != s || revision != plan.revision || revision != s.authorizationRevision {
		return CipherDocument{}, CipherFields{}, ErrExpired
	}
	latest, err := s.personalDocumentLocked(vault, plan.merged.ID)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	if sha256.Sum256(latest.JSON) != sha256.Sum256(plan.latest.JSON) {
		return CipherDocument{}, CipherFields{}, ErrConflict
	}
	if plan.merged.Reprompt != 0 && !s.validItemAuthorizationLocked(plan.grant, latest) {
		return CipherDocument{}, CipherFields{}, ErrPermission
	}
	// Decrypt afresh so neither the plan nor a previous result is mutated.
	fields, err := DecryptCipherDocument(latest, s.key)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	for _, path := range localPaths {
		allowed := false
		for _, change := range plan.changes {
			if change.Path == path && change.Local && change.CanApply {
				allowed = true
				break
			}
		}
		if !allowed {
			return CipherDocument{}, CipherFields{}, ErrUnsupportedEdit
		}
		value := plan.values[path]
		switch path {
		case "name":
			fields.Name = value.(string)
		case "notes":
			fields.Notes = value.(*string)
		case "folderId":
			fields.FolderID = value.(*string)
		case "favorite":
			fields.Favorite = value.(bool)
		case "fields":
			fields.Fields = value.([]map[string]any)
		case "passwordHistory":
			fields.PasswordHistory = value.([]map[string]any)
		default:
			sections := map[string]map[string]any{"login": fields.Login, "secureNote": fields.SecureNote, "card": fields.Card, "identity": fields.Identity, "sshKey": fields.SSHKey, "bankAccount": fields.BankAccount, "driversLicense": fields.DriversLicense, "passport": fields.Passport}
			for section, values := range sections {
				prefix := section + "."
				if len(path) > len(prefix) && path[:len(prefix)] == prefix {
					values[path[len(prefix):]] = value
					break
				}
			}
		}
	}
	// Detach selected maps and pointers from the reusable immutable plan.
	encoded, err := json.Marshal(fields)
	if err != nil {
		return CipherDocument{}, CipherFields{}, ErrProtocol
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var detached CipherFields
	if decoder.Decode(&detached) != nil {
		return CipherDocument{}, CipherFields{}, ErrProtocol
	}
	fields = detached
	// Existing encryption validation is also applied before exposing the draft.
	if _, err := encryptCipherDocument(latest, fields, s.key, s.account, fields.Reprompt == 0 || s.validItemAuthorizationLocked(plan.grant, latest)); err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	return latest, fields, nil
}
