// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/json"
)

// CopyPersonalCipher copies the edited draft without modifying the source. The
// caller must hold the snapshot revision lease used to open the source document.
func (s *Session) CopyPersonalCipher(ctx context.Context, scope Scope, source CipherDocument, fields CipherFields, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	return s.CopyPersonalCipherAuthorized(ctx, scope, source, fields, nil, persist)
}

func (s *Session) CopyPersonalCipherAuthorized(ctx context.Context, scope Scope, source CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
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
	if fields.OrganizationID != nil || !validObjectID(fields.ID) {
		return CipherDocument{}, ErrPermission
	}
	// Inspect the original before applying edits: deleting an unknown field in
	// the draft must not turn an unsupported copy into silently lossy success.
	object, err := documentObject(source)
	if err != nil {
		return CipherDocument{}, err
	}
	if err = validateCopyObject(object); err != nil {
		return CipherDocument{}, err
	}
	var metadata struct{ Reprompt int }
	if json.Unmarshal(source.JSON, &metadata) != nil {
		return CipherDocument{}, ErrProtocol
	}
	guard := func() error {
		if metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, source) {
			return ErrPermission
		}
		return nil
	}
	if err := guard(); err != nil {
		return CipherDocument{}, err
	}
	authorized := s.validItemAuthorizationLocked(grant, source)
	edited, err := encryptCipherDocument(source, fields, s.key, s.account, authorized)
	if err != nil {
		return CipherDocument{}, err
	}
	document, err := copyAuthorizedPersonalCipherDocument(edited, s.key, s.account, authorized)
	if err != nil {
		return CipherDocument{}, err
	}
	result, err := s.createGuardedCipherDocumentLocked(ctx, document, persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	created, err := DecryptCipherDocument(result, s.key)
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if created.ID == fields.ID {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	return result, nil
}

// The allowlist is intentional. Unknown data may be encrypted with the old item
// key; even null extensions are refused until their schema is understood.
func copyKeys(object map[string]any, names ...string) error {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for name := range object {
		if !allowed[name] {
			return ErrUnsupportedEdit
		}
	}
	return nil
}
func emptyCopyArray(value any) bool {
	if value == nil {
		return true
	}
	values, ok := value.([]any)
	return ok && len(values) == 0
}
func validateCopyObject(object map[string]any) error {
	if err := copyKeys(object, "object", "id", "type", "name", "notes", "key", "folderId", "favorite", "reprompt", "revisionDate", "creationDate", "deletedDate", "archivedDate", "organizationId", "organizationUseTotp", "collectionIds", "attachments", "edit", "viewPassword", "permissions", "encryptedFor", "encryptedByKeyId", "lastKnownRevisionDate", "fields", "passwordHistory", "login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport"); err != nil {
		return err
	}
	if object["organizationId"] != nil || object["edit"] != true || object["viewPassword"] != true {
		return ErrPermission
	}
	if object["encryptedByKeyId"] != nil || !emptyCopyArray(object["attachments"]) || !emptyCopyArray(object["collectionIds"]) {
		return ErrUnsupportedEdit
	}
	if raw := object["permissions"]; raw != nil {
		permissions, ok := raw.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		if err := copyKeys(permissions, "delete", "restore"); err != nil {
			return err
		}
	}
	typeNumber, ok := object["type"].(json.Number)
	if !ok {
		return ErrProtocol
	}
	kind, err := typeNumber.Int64()
	if err != nil || cipherSections[int(kind)] == "" {
		return ErrProtocol
	}
	for _, section := range cipherSections {
		if object[section] == nil {
			continue
		}
		if section != cipherSections[int(kind)] {
			return ErrUnsupportedEdit
		}
		detail, ok := object[section].(map[string]any)
		if !ok {
			return ErrProtocol
		}
		allowed := append([]string(nil), cipherSecrets[section]...)
		if section == "secureNote" {
			allowed = append(allowed, "type")
		}
		if section == "login" {
			allowed = append(allowed, "uri", "uris", "passwordRevisionDate", "autofillOnPageLoad", "fido2Credentials")
			if err := validateFIDO2Credentials(detail["fido2Credentials"]); err != nil {
				return err
			}
			if err := copyArrayKeys(detail["uris"], "uri", "uriChecksum", "match"); err != nil {
				return err
			}
		}
		if err := copyKeys(detail, allowed...); err != nil {
			return err
		}
	}
	if err := copyArrayKeys(object["fields"], "name", "value", "type", "linkedId"); err != nil {
		return err
	}
	return copyArrayKeys(object["passwordHistory"], "password", "lastUsedDate")
}
func copyArrayKeys(raw any, names ...string) error {
	if raw == nil {
		return nil
	}
	values, ok := raw.([]any)
	if !ok || len(values) > 10000 {
		return ErrProtocol
	}
	for _, value := range values {
		entry, ok := value.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		if err := copyKeys(entry, names...); err != nil {
			return err
		}
	}
	return nil
}
func copyPersonalCipherDocument(source CipherDocument, ownerKey []byte, account string) (CipherDocument, error) {
	return copyAuthorizedPersonalCipherDocument(source, ownerKey, account, false)
}

func copyAuthorizedPersonalCipherDocument(source CipherDocument, ownerKey []byte, account string, authorized bool) (CipherDocument, error) {
	object, err := documentObject(source)
	if err != nil {
		return CipherDocument{}, err
	}
	if err := validateCopyObject(object); err != nil {
		return CipherDocument{}, err
	}
	fields, err := DecryptCipherDocument(source, ownerKey)
	if err != nil {
		return CipherDocument{}, err
	}
	if account == "" || (fields.Reprompt != 0 && (fields.Reprompt != 1 || !authorized)) {
		return CipherDocument{}, ErrPermission
	}
	oldKey, err := cipherItemKey(object, ownerKey)
	if err != nil {
		return CipherDocument{}, err
	}
	defer clear(oldKey)
	if err := transformCompleteCipher(object, oldKey, false); err != nil {
		return CipherDocument{}, err
	}
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return CipherDocument{}, ErrEncryption
	}
	defer clear(key)
	wrapped, err := EncryptString(key, ownerKey)
	if err != nil {
		return CipherDocument{}, err
	}
	for _, name := range []string{"object", "id", "revisionDate", "creationDate", "lastKnownRevisionDate", "deletedDate", "archivedDate", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedByKeyId", "attachments", "collectionIds"} {
		delete(object, name)
	}
	object["key"], object["encryptedFor"] = wrapped, account
	if err := transformCompleteCipher(object, key, true); err != nil {
		return CipherDocument{}, err
	}
	data, err := json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	return CipherDocument{JSON: data}, nil
}
