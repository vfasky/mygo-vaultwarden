// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"time"
)

type PasswordHistoryValue struct{ Password, LastUsedDate string }

// WithCipherPasswordHistory lends saved history and the snapshot authentication
// key for one synchronous native display authorization. The key must not be
// retained; displayed values must be cleared at the returned deadline or lock.
func (s *Session) WithCipherPasswordHistory(vault *VaultData, revision, id string, grant *ItemAuthorization, use func([]PasswordHistoryValue, []byte, time.Time) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vault == nil || revision == "" || revision != s.authorizationRevision || s.passwordUnlock == nil || use == nil {
		return ErrExpired
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return err
	}
	var selected CipherDocument
	var organization bool
	for _, document := range documents {
		var meta struct {
			ID             string
			OrganizationID *string
		}
		if json.Unmarshal(document.JSON, &meta) != nil {
			return ErrProtocol
		}
		if meta.ID == id {
			selected = document
			organization = meta.OrganizationID != nil
			break
		}
	}
	if selected.JSON == nil {
		return ErrNotFound
	}
	ownerKey := s.key
	if organization {
		data, e := s.organizationVaultLocked(vault)
		if e != nil {
			return e
		}
		defer data.close()
		selected, ownerKey, err = s.organizationDocumentLocked(vault, id, data)
	} else {
		selected, err = s.personalDocumentLocked(vault, id)
	}
	if err != nil {
		return err
	}
	var meta struct{ Reprompt int }
	if json.Unmarshal(selected.JSON, &meta) != nil {
		return ErrProtocol
	}
	if meta.Reprompt < 0 || meta.Reprompt > 1 {
		return ErrPermission
	}
	if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, selected) {
		return ErrPermission
	}
	fields, err := DecryptCipherDocument(selected, ownerKey)
	if err != nil {
		return err
	}
	if !fields.ViewPassword || len(fields.PasswordHistory) > 10000 {
		return ErrPermission
	}
	history := make([]PasswordHistoryValue, 0, len(fields.PasswordHistory))
	defer clear(history)
	total := 0
	for _, entry := range fields.PasswordHistory {
		password, ok := entry["password"].(string)
		if !ok {
			return ErrProtocol
		}
		date, ok := entry["lastUsedDate"].(string)
		if !ok || len(password) > 65536 {
			return ErrProtocol
		}
		total += len(password) + len(date)
		if total > MaxBackupSize {
			return ErrValidation
		}
		history = append(history, PasswordHistoryValue{Password: password, LastUsedDate: date})
	}
	deadline := time.Now().Add(30 * time.Second)
	if meta.Reprompt != 0 && grant.expires.Before(deadline) {
		deadline = grant.expires
	}
	key := append([]byte(nil), s.passwordUnlock.Key...)
	defer clear(key)
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || s.closed {
		return ErrExpired
	}
	return use(history, key, deadline)
}
