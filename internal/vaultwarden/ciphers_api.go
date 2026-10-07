// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

// CipherAction names server operations with distinct soft/hard-delete semantics.
// Callers must obtain explicit confirmation before permanent deletion.
type CipherAction string

const (
	CipherTrash             CipherAction = "trash"
	CipherRestore           CipherAction = "restore"
	CipherArchive           CipherAction = "archive"
	CipherUnarchive         CipherAction = "unarchive"
	CipherDeletePermanently CipherAction = "deletePermanently"
)

// ChangeCipherState performs exactly one mutation and returns no optimistic local
// state. After success the caller must sync using its existing revision lease.
func (s *Session) ChangeCipherState(ctx context.Context, scope Scope, id string, action CipherAction, persist func(SessionCheckpoint) error) error {
	if !validObjectID(id) {
		return ErrValidation
	}
	method, endpoint := http.MethodPut, "/api/ciphers/"+id
	switch action {
	case CipherTrash:
		endpoint += "/delete"
	case CipherRestore:
		endpoint += "/restore"
	case CipherArchive:
		endpoint += "/archive"
	case CipherUnarchive:
		endpoint += "/unarchive"
	case CipherDeletePermanently:
		method = http.MethodDelete
	default:
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := s.requireScopeLocked(scope); err != nil {
		return err
	}
	status, _, err := s.authenticatedLocked(ctx, method, endpoint, "", "", persist)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return statusError(status)
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

func (s *Session) requireScopeLocked(scope Scope) error {
	if s.account == "" || scope.Account != s.account || scope.Server != s.client.base.String() {
		return ErrIdentity
	}
	return nil
}

// SetCipherPersonalMetadata uses Vaultwarden's partial update so a favorite or
// folder change never overwrites encrypted content or another user's metadata.
func (s *Session) SetCipherPersonalMetadata(ctx context.Context, scope Scope, id string, folderID *string, favorite bool, persist func(SessionCheckpoint) error) error {
	if !validObjectID(id) || (folderID != nil && !validObjectID(*folderID)) {
		return ErrValidation
	}
	body, _ := json.Marshal(struct {
		FolderID *string `json:"folderId"`
		Favorite bool    `json:"favorite"`
	}{folderID, favorite})
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := s.requireScopeLocked(scope); err != nil {
		return err
	}
	status, _, err := s.authenticatedLocked(ctx, http.MethodPut, "/api/ciphers/"+id+"/partial", "application/json", string(body), persist)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return statusError(status)
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

func (s *Session) UpdatePersonalCipher(ctx context.Context, scope Scope, document CipherDocument, fields CipherFields, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	if !validObjectID(fields.ID) {
		return CipherDocument{}, ErrValidation
	}
	if fields.OrganizationID != nil {
		return CipherDocument{}, ErrPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherDocument{}, err
	}
	defer finish()
	if err := s.requireScopeLocked(scope); err != nil {
		return CipherDocument{}, err
	}
	encrypted, err := EncryptCipherDocument(document, fields, s.key, s.account)
	if err != nil {
		return CipherDocument{}, err
	}
	status, data, err := s.authenticatedLocked(ctx, http.MethodPut, "/api/ciphers/"+fields.ID, "application/json", string(encrypted.JSON), persist)
	if err != nil {
		return CipherDocument{}, err
	}
	if status != http.StatusOK {
		return CipherDocument{}, statusError(status)
	}
	result := CipherDocument{JSON: data}
	updated, err := DecryptCipherDocument(result, s.key)
	if err != nil {
		return CipherDocument{}, err
	}
	if updated.ID != fields.ID || updated.OrganizationID != nil {
		return CipherDocument{}, ErrIdentity
	}
	if ctx.Err() != nil {
		return CipherDocument{}, ErrCancelled
	}
	return result, nil
}
