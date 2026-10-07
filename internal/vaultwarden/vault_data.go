// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "encoding/json"

// VaultData is the complete server-encrypted sync document inside the locally
// authenticated snapshot. It never belongs in status or AutoFill metadata. The
// snapshot's lease revision, not a server cipher revision, authorizes its use.
type VaultData struct {
	Version int    `json:"version"`
	Scope   Scope  `json:"scope"`
	Sync    []byte `json:"sync"`
}

func (v *VaultData) Documents(scope Scope) ([]CipherDocument, error) {
	if v == nil || v.Version != 1 || v.Scope != scope || scope.Account == "" || scope.Server == "" {
		return nil, ErrIdentity
	}
	if len(v.Sync) == 0 || len(v.Sync) > maxResponse {
		return nil, ErrProtocol
	}
	var data struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
		Ciphers []json.RawMessage `json:"ciphers"`
	}
	if json.Unmarshal(v.Sync, &data) != nil || data.Profile.ID != scope.Account || data.Ciphers == nil || len(data.Ciphers) > 100000 {
		return nil, ErrProtocol
	}
	seen := map[string]bool{}
	result := make([]CipherDocument, 0, len(data.Ciphers))
	for _, raw := range data.Ciphers {
		var identity struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &identity) != nil || !validObjectID(identity.ID) || seen[identity.ID] {
			return nil, ErrProtocol
		}
		seen[identity.ID] = true
		result = append(result, CipherDocument{JSON: raw})
	}
	return result, nil
}

type VaultEntry struct {
	OrganizationID                        string
	CollectionIDs                         []string
	Readable                              bool
	ID, Title, Username, URL              string
	FolderID                              string
	Type                                  int
	Favorite, Archived, Deleted, Editable bool
	RequiresPassword                      bool
}

// PersonalEntries returns display metadata only, never notes or secret fields.
// Unsupported/reprompt records remain discoverable but cannot be opened.
func (s *Session) PersonalEntries(vault *VaultData) ([]VaultEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || vault == nil {
		return nil, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	entries := make([]VaultEntry, 0, len(documents))
	for _, document := range documents {
		var metadata struct {
			ID                        string
			FolderID                  *string
			Type                      int
			OrganizationID            *string
			Reprompt                  int
			Edit                      bool
			ViewPassword              *bool
			Favorite                  bool
			ArchivedDate, DeletedDate *string
		}
		if json.Unmarshal(document.JSON, &metadata) != nil {
			return nil, ErrProtocol
		}
		if metadata.OrganizationID != nil {
			continue
		}
		entry := VaultEntry{ID: metadata.ID, Type: metadata.Type, Title: "受保护或暂不支持的项目", Favorite: metadata.Favorite, Archived: metadata.ArchivedDate != nil, Deleted: metadata.DeletedDate != nil}
		if metadata.FolderID != nil {
			entry.FolderID = *metadata.FolderID
		}
		if metadata.Reprompt == 0 && (metadata.ViewPassword == nil || *metadata.ViewPassword) {
			if fields, err := DecryptCipherDocument(document, s.key); err == nil {
				entry.Title, entry.Editable = fields.Name, fields.Edit && fields.ViewPassword
				entry.Username, _ = fields.Login["username"].(string)
				if uris, ok := fields.Login["uris"].([]any); ok && len(uris) > 0 {
					if uri, ok := uris[0].(map[string]any); ok {
						entry.URL, _ = uri["uri"].(string)
					}
				}
			}
		}
		if metadata.Reprompt == 1 && metadata.Edit && metadata.ViewPassword != nil && *metadata.ViewPassword {
			entry.RequiresPassword = true // Opens the password reauthentication form only.
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ReadPersonalCipher only decrypts a document from an authenticated complete
// snapshot. Callers must first verify its current local snapshot lease.
func (s *Session) ReadPersonalCipher(vault *VaultData, id string) (CipherDocument, CipherFields, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || vault == nil {
		return CipherDocument{}, CipherFields{}, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	for _, document := range documents {
		var metadata struct {
			ID             string
			OrganizationID *string
			Reprompt       int
			ViewPassword   *bool
		}
		if json.Unmarshal(document.JSON, &metadata) != nil {
			return CipherDocument{}, CipherFields{}, ErrProtocol
		}
		if metadata.ID != id {
			continue
		}
		if metadata.OrganizationID != nil || metadata.Reprompt != 0 || (metadata.ViewPassword != nil && !*metadata.ViewPassword) {
			return CipherDocument{}, CipherFields{}, ErrPermission
		}
		fields, err := DecryptCipherDocument(document, s.key)
		return document, fields, err
	}
	return CipherDocument{}, CipherFields{}, ErrNotFound
}
