// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"reflect"
)

func (v *organizationVault) writableCollection(orgID, collectionID string) bool {
	if v.keys[orgID] == nil {
		return false
	}
	for _, c := range v.collections {
		if c.ID == collectionID && c.OrganizationID == orgID {
			return !c.ReadOnly && !c.HidePasswords
		}
	}
	return false
}

// CreateOrganizationCipher wraps a new random item key in the target organization
// key. Collection write permission comes from server-resolved sync details.
func (s *Session) CreateOrganizationCipher(ctx context.Context, vault *VaultData, orgID, collectionID string, fields CipherFields, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	return s.writeOrganizationCipher(ctx, vault, orgID, collectionID, CipherDocument{}, fields, nil, persist, nil)
}

// SharePersonalCipher moves ownership using an independent item key. Existing
// item keys retain opaque fields; audited legacy fields receive a new random key.
// Keyless attachments must be upgraded before sharing.
func (s *Session) SharePersonalCipher(ctx context.Context, vault *VaultData, orgID, collectionID string, document CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	if fields.ID == "" {
		return CipherDocument{}, ErrValidation
	}
	return s.writeOrganizationCipher(ctx, vault, orgID, collectionID, document, fields, grant, persist, nil)
}

// SharePersonalCipherWithRecovery requires the production caller to atomically
// persist the account-bound encrypted recovery file before a legacy attachment
// rewrap. The callback must not reenter Session; a failed save sends no share.
func (s *Session) SharePersonalCipherWithRecovery(ctx context.Context, vault *VaultData, orgID, collectionID string, document CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error, persistRecovery func([]byte) error) (CipherDocument, error) {
	if fields.ID == "" {
		return CipherDocument{}, ErrValidation
	}
	return s.writeOrganizationCipher(ctx, vault, orgID, collectionID, document, fields, grant, persist, persistRecovery)
}

func CipherShareRequiresRecovery(document CipherDocument) bool {
	object, err := documentObject(document)
	if err != nil {
		return true
	}
	key, _ := object["key"].(string)
	return key == "" && !emptyCopyArray(object["attachments"])
}

func (s *Session) writeOrganizationCipher(ctx context.Context, vault *VaultData, orgID, collectionID string, document CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error, persistRecovery func([]byte) error) (CipherDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherDocument{}, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return CipherDocument{}, err
	}
	defer data.close()
	if !data.writableCollection(orgID, collectionID) || fields.OrganizationID != nil {
		return CipherDocument{}, ErrPermission
	}
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	reprompt := 0
	var encrypted CipherDocument
	endpoint, method := "/api/ciphers/create", http.MethodPost
	if fields.ID == "" {
		encrypted, err = NewPersonalCipher(fields, data.keys[orgID], s.account)
	} else {
		original, e := s.personalDocumentLocked(vault, fields.ID)
		if e != nil {
			return CipherDocument{}, e
		}
		if !bytes.Equal(original.JSON, document.JSON) {
			return CipherDocument{}, ErrConflict
		}
		var meta struct {
			Reprompt    int
			DeletedDate *string
		}
		_ = json.Unmarshal(document.JSON, &meta)
		if meta.DeletedDate != nil {
			return CipherDocument{}, ErrPermission
		}
		reprompt = meta.Reprompt
		encrypted, err = encryptCipherDocument(document, fields, s.key, s.account, s.validItemAuthorizationLocked(grant, document))
		endpoint, method = "/api/ciphers/"+fields.ID+"/share", http.MethodPut
	}
	if err != nil {
		return CipherDocument{}, err
	}
	object, err := documentObject(encrypted)
	if err != nil {
		return CipherDocument{}, err
	}
	recoveryKey := ""
	if fields.ID != "" {
		// Even with an independent item key, a keyless binary still uses the
		// current owner key. It must be upgraded before ownership changes.
		if raw := object["attachments"]; raw != nil {
			rows, ok := raw.([]any)
			if !ok {
				return CipherDocument{}, ErrProtocol
			}
			for _, raw := range rows {
				row, ok := raw.(map[string]any)
				if !ok {
					return CipherDocument{}, ErrProtocol
				}
				if key, ok := row["key"].(string); !ok || key == "" {
					return CipherDocument{}, ErrUnsupportedEdit
				}
			}
		}
		wrapped, hasKey := object["key"].(string)
		legacy := object["key"] == nil || (hasKey && wrapped == "")
		var key []byte
		if legacy {
			key = make([]byte, 64)
			if _, err = rand.Read(key); err != nil {
				return CipherDocument{}, ErrEncryption
			}
			defer clear(key)
			if err = rekeyLegacyShare(object, s.key, key); err != nil {
				return CipherDocument{}, err
			}
			if !emptyCopyArray(object["attachments"]) {
				if persistRecovery == nil {
					return CipherDocument{}, ErrUnsupportedEdit
				}
				wrappers, e := shareRecoveryAttachments(object)
				if e != nil {
					return CipherDocument{}, e
				}
				object["attachments2"] = wrappers
				recoveryKey, err = vaultcrypto.EncryptString(key, s.key)
				if err != nil {
					return CipherDocument{}, err
				}
			}
		} else {
			key, err = cipherItemKey(object, s.key)
			if err != nil {
				return CipherDocument{}, err
			}
			defer clear(key)
		}
		// Never grant an organization the account key, even if a malformed item
		// happens to wrap the account key as its allegedly independent item key.
		if bytes.Equal(key, s.key) {
			return CipherDocument{}, ErrPermission
		}
		object["key"], err = vaultcrypto.EncryptString(key, data.keys[orgID])
		if err != nil {
			return CipherDocument{}, err
		}
	}
	object["organizationId"] = orgID
	body, err := json.Marshal(map[string]any{"cipher": object, "collectionIds": []string{collectionID}})
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
			return ErrPermission
		}
		return nil
	}
	guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, orgID, fields.Type, persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	if recoveryKey != "" {
		file, err := encodeCipherShareRecovery(vault.Scope, document, object, orgID, recoveryKey, s.key)
		if err != nil {
			return CipherDocument{}, err
		}
		err = persistRecovery(file)
		clear(file)
		if err != nil {
			return CipherDocument{}, err
		}
		if ctx.Err() != nil {
			return CipherDocument{}, ErrCancelled
		}
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, method, endpoint, "application/json", string(body), persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	// Sharing is not transactional on the server: even a validation rejection
	// may have linked a collection. Always require sync before another attempt.
	if status != http.StatusOK {
		return CipherDocument{}, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	result := CipherDocument{JSON: response}
	updated, err := DecryptCipherDocument(result, data.keys[orgID])
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if !validObjectID(updated.ID) || (fields.ID != "" && updated.ID != fields.ID) || updated.OrganizationID == nil || *updated.OrganizationID != orgID {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if recoveryKey != "" {
		actual, e := documentObject(result)
		if e != nil {
			return CipherDocument{}, &MutationUncertainError{Cause: e}
		}
		wrappers, e := shareRecoveryAttachments(actual)
		if e != nil || !reflect.DeepEqual(wrappers, object["attachments2"]) {
			return CipherDocument{}, &MutationUncertainError{Cause: ErrConflict}
		}
	}
	if ctx.Err() != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
