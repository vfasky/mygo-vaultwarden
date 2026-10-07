// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"time"
)

// ItemAuthorization is an in-process capability. Its contents are deliberately
// private; neither a public snapshot revision nor a serialized token grants it.
// The UI must still verify its authenticated snapshot lease before every use.
type ItemAuthorization struct {
	session        *Session
	scope          Scope
	revision, item string
	document       [32]byte
	epoch          uint64
	expires        time.Time
}

// BindSnapshotRevision revokes every grant when the authenticated local snapshot
// changes. Call only after the storage lease has been verified. It does not by
// itself grant permission to decrypt any protected item.
// ExpiresAt is display metadata only; callers must still use the guarded APIs.
func (g *ItemAuthorization) ExpiresAt() time.Time {
	if g == nil {
		return time.Time{}
	}
	return g.expires
}

func (s *Session) BindSnapshotRevision(scope Scope, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrExpired
	}
	if err := s.requireScopeLocked(scope); err != nil {
		return err
	}
	if revision == "" {
		return ErrIdentity
	}
	if s.authorizationRevision != revision {
		s.authorizationEpoch++
		s.authorizationRevision = revision
	}
	return nil
}

func (s *Session) RevokeItemAuthorizations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizationEpoch++
}

func (s *Session) validItemAuthorizationLocked(grant *ItemAuthorization, document CipherDocument) bool {
	if !s.itemSessionActiveLocked() {
		return false
	}
	return grant != nil && grant.session == s && !s.closed &&
		grant.scope == (Scope{Server: s.client.base.String(), Account: s.account}) &&
		grant.revision != "" && grant.revision == s.authorizationRevision &&
		grant.epoch == s.authorizationEpoch && time.Now().Before(grant.expires) &&
		grant.document == sha256.Sum256(document.JSON)
}

func (s *Session) itemSessionActiveLocked() bool {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	return !s.closed && !s.stopping
}

func (s *Session) personalDocumentLocked(vault *VaultData, id string) (CipherDocument, error) {
	if !s.itemSessionActiveLocked() || vault == nil {
		return CipherDocument{}, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return CipherDocument{}, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return CipherDocument{}, err
	}
	for _, document := range documents {
		var metadata struct {
			ID             string
			OrganizationID *string
			Reprompt       int
			ViewPassword   *bool
		}
		if json.Unmarshal(document.JSON, &metadata) != nil {
			return CipherDocument{}, ErrProtocol
		}
		if metadata.ID != id {
			continue
		}
		if metadata.OrganizationID != nil || metadata.Reprompt < 0 || metadata.Reprompt > 1 || metadata.ViewPassword == nil || !*metadata.ViewPassword {
			return CipherDocument{}, ErrPermission
		}
		return document, nil
	}
	return CipherDocument{}, ErrNotFound
}

// AuthorizePersonalItem verifies the master password using the authenticated
// snapshot's domain-separated key. KDF runs without holding the session mutex,
// so Close can revoke immediately. No password or verifier is kept in a grant.
func (s *Session) AuthorizePersonalItem(ctx context.Context, vault *VaultData, revision, id string, password []byte) (*ItemAuthorization, error) {
	return s.authorizeItem(ctx, vault, revision, id, password, false)
}

func (s *Session) AuthorizeOrganizationItem(ctx context.Context, vault *VaultData, revision, id string, password []byte) (*ItemAuthorization, error) {
	return s.authorizeItem(ctx, vault, revision, id, password, true)
}

func (s *Session) authorizeItem(ctx context.Context, vault *VaultData, revision, id string, password []byte, organization bool) (*ItemAuthorization, error) {
	if len(password) == 0 || len(password) > 4096 {
		return nil, ErrValidation
	}
	s.mu.Lock()
	var document CipherDocument
	var err error
	if organization {
		var data *organizationVault
		data, err = s.organizationVaultLocked(vault)
		if err == nil {
			document, _, err = s.organizationDocumentLocked(vault, id, data)
			data.close()
		}
	} else {
		document, err = s.personalDocumentLocked(vault, id)
	}
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if revision == "" || revision != s.authorizationRevision || s.passwordUnlock == nil {
		s.mu.Unlock()
		return nil, ErrExpired
	}
	config := s.passwordUnlock.Config
	epoch := s.authorizationEpoch
	expected := append([]byte(nil), s.passwordUnlock.Key...)
	s.mu.Unlock()
	defer clear(expected)
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	derived, err := DeriveSnapshotUnlockKey(password, config)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	if !s.itemSessionActiveLocked() || s.authorizationEpoch != epoch || s.authorizationRevision != revision {
		return nil, ErrExpired
	}
	if subtle.ConstantTimeCompare(derived, expected) != 1 {
		return nil, ErrPermission
	}
	return &ItemAuthorization{session: s, scope: vault.Scope, revision: revision, item: id, document: sha256.Sum256(document.JSON), epoch: epoch, expires: time.Now().Add(30 * time.Second)}, nil
}

func (s *Session) PersonalItemRequiresPassword(vault *VaultData, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	document, err := s.personalDocumentLocked(vault, id)
	if err != nil {
		return false
	}
	var metadata struct {
		Reprompt int
		Edit     bool
	}
	return json.Unmarshal(document.JSON, &metadata) == nil && metadata.Reprompt == 1 && metadata.Edit
}

func (s *Session) ReadPersonalCipherAuthorized(vault *VaultData, id string, grant *ItemAuthorization) (CipherDocument, CipherFields, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	document, err := s.personalDocumentLocked(vault, id)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	var metadata struct{ Reprompt int }
	if json.Unmarshal(document.JSON, &metadata) != nil {
		return CipherDocument{}, CipherFields{}, ErrProtocol
	}
	if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
		return CipherDocument{}, CipherFields{}, ErrPermission
	}
	fields, err := DecryptCipherDocument(document, s.key)
	return document, fields, err
}
