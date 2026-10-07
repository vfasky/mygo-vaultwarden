// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"net/http"
)

func (s *Session) CreatePersonalCipher(ctx context.Context, scope Scope, fields CipherFields, persist func(SessionCheckpoint) error) (CipherDocument, error) {
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
	document, err := NewPersonalCipher(fields, s.key, s.account)
	if err != nil {
		return CipherDocument{}, err
	}
	return s.createCipherDocumentLocked(ctx, document, persist)
}

func (s *Session) createCipherDocumentLocked(ctx context.Context, document CipherDocument, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	return s.createGuardedCipherDocumentLocked(ctx, document, persist, nil)
}

func (s *Session) createGuardedCipherDocumentLocked(ctx context.Context, document CipherDocument, persist func(SessionCheckpoint) error, guard func() error) (CipherDocument, error) {
	status, data, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, "/api/ciphers", "application/json", string(document.JSON), persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	if status != http.StatusOK {
		return CipherDocument{}, mutationStatusError(status)
	}
	result := CipherDocument{JSON: data}
	created, err := DecryptCipherDocument(result, s.key)
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if !validObjectID(created.ID) || created.OrganizationID != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
