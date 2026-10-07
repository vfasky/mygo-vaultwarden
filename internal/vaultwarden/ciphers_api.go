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
	return s.changeCipherState(ctx, scope, id, action, persist, nil)
}

func (s *Session) ChangePersonalCipherStateAuthorized(ctx context.Context, scope Scope, document CipherDocument, action CipherAction, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	var metadata struct {
		ID                 string
		OrganizationID     *string
		Reprompt           int
		Edit, ViewPassword bool
	}
	if json.Unmarshal(document.JSON, &metadata) != nil {
		return ErrProtocol
	}
	guard := func() error {
		if metadata.OrganizationID != nil || !metadata.Edit || !metadata.ViewPassword || metadata.Reprompt < 0 || metadata.Reprompt > 1 {
			return ErrPermission
		}
		if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
			return ErrPermission
		}
		return nil
	}
	return s.changeCipherState(ctx, scope, metadata.ID, action, persist, guard)
}

func (s *Session) changeCipherState(ctx context.Context, scope Scope, id string, action CipherAction, persist func(SessionCheckpoint) error, guard func() error) error {
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
	status, _, err := s.authenticatedGuardedLocked(ctx, method, endpoint, "", "", persist, guard)
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
		return mutationStatusError(status)
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}

func (s *Session) UpdatePersonalCipher(ctx context.Context, scope Scope, document CipherDocument, fields CipherFields, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	return s.UpdatePersonalCipherAuthorized(ctx, scope, document, fields, nil, persist)
}

func (s *Session) UpdatePersonalCipherAuthorized(ctx context.Context, scope Scope, document CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
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
	var metadata struct{ Reprompt int }
	if json.Unmarshal(document.JSON, &metadata) != nil {
		return CipherDocument{}, ErrProtocol
	}
	guard := func() error {
		if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
			return ErrPermission
		}
		return nil
	}
	if err := guard(); err != nil {
		return CipherDocument{}, err
	}
	encrypted, err := encryptCipherDocument(document, fields, s.key, s.account, s.validItemAuthorizationLocked(grant, document))
	if err != nil {
		return CipherDocument{}, err
	}
	status, data, err := s.authenticatedGuardedLocked(ctx, http.MethodPut, "/api/ciphers/"+fields.ID, "application/json", string(encrypted.JSON), persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	if status != http.StatusOK {
		return CipherDocument{}, mutationStatusError(status)
	}
	result := CipherDocument{JSON: data}
	updated, err := DecryptCipherDocument(result, s.key)
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if updated.ID != fields.ID || updated.OrganizationID != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
