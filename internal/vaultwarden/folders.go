// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

// Folder names are decrypted only from an authenticated full vault snapshot.
type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Session) PersonalFolders(vault *VaultData) ([]Folder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || vault == nil {
		return nil, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	if _, err := vault.Documents(vault.Scope); err != nil {
		return nil, err
	}
	var data struct {
		Folders []Folder `json:"folders"`
	}
	if json.Unmarshal(vault.Sync, &data) != nil || len(data.Folders) > 100000 {
		return nil, ErrProtocol
	}
	seen := map[string]bool{}
	for i := range data.Folders {
		folder := &data.Folders[i]
		if !validObjectID(folder.ID) || seen[folder.ID] {
			return nil, ErrProtocol
		}
		seen[folder.ID] = true
		plain, err := DecryptString(folder.Name, s.key)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(plain) {
			clear(plain)
			return nil, ErrEncryption
		}
		folder.Name = string(plain)
		clear(plain)
	}
	sort.Slice(data.Folders, func(i, j int) bool {
		if data.Folders[i].Name == data.Folders[j].Name {
			return data.Folders[i].ID < data.Folders[j].ID
		}
		return data.Folders[i].Name < data.Folders[j].Name
	})
	return data.Folders, nil
}

// SaveFolder sends one encrypted create/update. The server has no folder CAS;
// callers bind the draft to their local snapshot and sync after success.
func (s *Session) SaveFolder(ctx context.Context, scope Scope, id, name string, persist func(SessionCheckpoint) error) (Folder, error) {
	if (id != "" && !validObjectID(id)) || strings.TrimSpace(name) == "" || len(name) > 4096 || !utf8.ValidString(name) {
		return Folder{}, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return Folder{}, err
	}
	defer finish()
	if err = s.requireScopeLocked(scope); err != nil {
		return Folder{}, err
	}
	encrypted, err := EncryptString([]byte(name), s.key)
	if err != nil {
		return Folder{}, err
	}
	body, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{encrypted})
	method, endpoint := http.MethodPost, "/api/folders"
	if id != "" {
		method, endpoint = http.MethodPut, endpoint+"/"+id
	}
	status, data, err := s.authenticatedLocked(ctx, method, endpoint, "application/json", string(body), persist)
	if err != nil {
		return Folder{}, err
	}
	if status != http.StatusOK {
		return Folder{}, mutationStatusError(status)
	}
	var result Folder
	if json.Unmarshal(data, &result) != nil || !validObjectID(result.ID) || (id != "" && result.ID != id) {
		return Folder{}, &MutationUncertainError{Cause: ErrProtocol}
	}
	plain, err := DecryptString(result.Name, s.key)
	defer clear(plain)
	if err != nil || string(plain) != name {
		return Folder{}, &MutationUncertainError{Cause: ErrEncryption}
	}
	if ctx.Err() != nil {
		return Folder{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	result.Name = name
	return result, nil
}

func (s *Session) DeleteFolder(ctx context.Context, scope Scope, id string, persist func(SessionCheckpoint) error) error {
	if !validObjectID(id) {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err = s.requireScopeLocked(scope); err != nil {
		return err
	}
	status, _, err := s.authenticatedLocked(ctx, http.MethodDelete, "/api/folders/"+id, "", "", persist)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return mutationStatusError(status)
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
