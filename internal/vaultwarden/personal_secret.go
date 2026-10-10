// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/totp"
	"time"
)

// WithPersonalSecret lends a persisted password/TOTP and snapshot authentication
// key for one synchronous UI-thread operation. The receiver must not retain them
// or call back into Session. Lock order: Session.mu -> Swift main (already on UI)
// -> snapshot file lease. Workers must never use this callback to wait on UI.
func (s *Session) WithPersonalSecret(vault *VaultData, revision, id, kind string, grant *ItemAuthorization, use func(secret string, unlockKey []byte, expires time.Time) error) error {
	return s.withItemSecret(vault, revision, id, kind, grant, use, false)
}

func (s *Session) WithOrganizationSecret(vault *VaultData, revision, id, kind string, grant *ItemAuthorization, use func(secret string, unlockKey []byte, expires time.Time) error) error {
	return s.withItemSecret(vault, revision, id, kind, grant, use, true)
}

func (s *Session) withItemSecret(vault *VaultData, revision, id, kind string, grant *ItemAuthorization, use func(secret string, unlockKey []byte, expires time.Time) error, organization bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var document CipherDocument
	var err error
	ownerKey := s.key
	if organization {
		var data *organizationVault
		data, err = s.organizationVaultLocked(vault)
		if err != nil {
			return err
		}
		defer data.close()
		document, ownerKey, err = s.organizationDocumentLocked(vault, id, data)
	} else {
		document, err = s.personalDocumentLocked(vault, id)
	}
	if err != nil {
		return err
	}
	if revision == "" || revision != s.authorizationRevision || (s.passwordUnlock == nil && !s.runtimeOnly) || use == nil {
		return ErrExpired
	}
	var metadata struct{ Reprompt int }
	if json.Unmarshal(document.JSON, &metadata) != nil {
		return ErrProtocol
	}
	if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
		return ErrPermission
	}
	fields, err := DecryptCipherDocument(document, ownerKey)
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
		code, err := totp.Generate(seed, now)
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
	key, err := s.secretProtectionKeyLocked()
	if err != nil {
		return err
	}
	deadline = s.secretDeadlineLocked(deadline)
	defer clear(key)
	if !s.itemSessionActiveLocked() {
		return ErrExpired
	}
	return use(secret, key, deadline)
}
