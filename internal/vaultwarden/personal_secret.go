// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"time"
)

// WithPersonalSecret lends a persisted password/TOTP and snapshot authentication
// key for one synchronous UI-thread operation. The receiver must not retain them
// or call back into Session. Lock order: Session.mu -> Swift main (already on UI)
// -> snapshot file lease. Workers must never use this callback to wait on UI.
func (s *Session) WithPersonalSecret(vault *VaultData, revision, id, kind string, grant *ItemAuthorization, use func(secret string, unlockKey []byte, expires time.Time) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	document, err := s.personalDocumentLocked(vault, id)
	if err != nil {
		return err
	}
	if revision == "" || revision != s.authorizationRevision || s.passwordUnlock == nil || use == nil {
		return ErrExpired
	}
	var metadata struct{ Reprompt int }
	if json.Unmarshal(document.JSON, &metadata) != nil {
		return ErrProtocol
	}
	if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
		return ErrPermission
	}
	fields, err := DecryptCipherDocument(document, s.key)
	if err != nil {
		return err
	}
	if fields.Type != 1 || !fields.ViewPassword {
		return ErrPermission
	}
	now := time.Now()
	deadline := now.Add(30 * time.Second)
	if metadata.Reprompt != 0 && grant.expires.Before(deadline) {
		deadline = grant.expires
	}
	var secret string
	switch kind {
	case "password":
		secret, _ = fields.Login["password"].(string)
	case "totp":
		seed, _ := fields.Login["totp"].(string)
		code, err := GenerateTOTP(seed, now)
		if err != nil {
			return err
		}
		secret = code.Code
		if code.ValidUntil.Before(deadline) {
			deadline = code.ValidUntil
		}
	default:
		return ErrValidation
	}
	if len(secret) == 0 || len(secret) > 65536 {
		return ErrValidation
	}
	key := append([]byte(nil), s.passwordUnlock.Key...)
	defer clear(key)
	return use(secret, key, deadline)
}
