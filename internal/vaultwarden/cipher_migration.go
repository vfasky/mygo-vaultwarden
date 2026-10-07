// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// Every string below is an EncString in the official Fido2Credential wire
// model; creationDate alone is plaintext. Source: Bitwarden clients commit
// 5983f56ce0cf924eea56c7d8f066f7885825a7ce, libs/common/src/vault/models/domain/
// fido2-credential.ts. Keep this transform separate from
// ordinary editing, which must preserve opaque credentials under the same key.
var fido2SecretFields = []string{"credentialId", "keyType", "keyAlgorithm", "keyCurve", "keyValue", "rpId", "userHandle", "userName", "counter", "rpName", "userDisplayName", "discoverable"}

func validateFIDO2Credentials(raw any) error {
	if raw == nil {
		return nil
	}
	values, ok := raw.([]any)
	if !ok {
		return ErrProtocol
	}
	if len(values) > 100 {
		return fmt.Errorf("单条项目超过本客户端 100 条通行密钥的资源限值：%w", ErrValidation)
	}
	allowed := append(append([]string(nil), fido2SecretFields...), "creationDate")
	for _, raw := range values {
		value, ok := raw.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		if err := copyKeys(value, allowed...); err != nil {
			return err
		}
		for _, name := range fido2SecretFields {
			field, exists := value[name]
			optional := name == "userHandle" || name == "userName" || name == "rpName" || name == "userDisplayName"
			if optional && (!exists || field == nil) {
				continue
			}
			if _, ok := field.(string); !ok {
				return ErrUnsupportedEdit
			}
		}
		date, ok := value["creationDate"].(string)
		if !ok {
			return ErrProtocol
		}
		if _, err := time.Parse(time.RFC3339Nano, date); err != nil {
			return ErrProtocol
		}
	}
	return nil
}

// transformCompleteCipher is exclusively for audited cross-key copies and
// plaintext backups. Unknown fields are rejected by callers before conversion.
func prepareLegacyCipherURIs(object map[string]any) error {
	login, ok := object["login"].(map[string]any)
	if !ok || login["uri"] == nil {
		return nil
	}
	alias, ok := login["uri"].(string)
	if !ok {
		return ErrProtocol
	}
	if login["uris"] == nil {
		hash := sha256.Sum256([]byte(alias))
		login["uris"] = []any{map[string]any{"uri": alias, "match": nil, "uriChecksum": base64.StdEncoding.EncodeToString(hash[:])}}
		return nil
	}
	rows, ok := login["uris"].([]any)
	if !ok || len(rows) == 0 {
		return ErrUnsupportedEdit
	}
	first, ok := rows[0].(map[string]any)
	if !ok || first["uri"] != alias {
		return ErrUnsupportedEdit
	}
	return nil
}

func transformCompleteCipher(object map[string]any, key []byte, encrypt bool) error {
	if encrypt {
		if err := prepareLegacyCipherURIs(object); err != nil {
			return err
		}
	}
	if err := transformCipher(object, key, encrypt); err != nil {
		return err
	}
	if login, ok := object["login"].(map[string]any); ok {
		if err := validateFIDO2Credentials(login["fido2Credentials"]); err != nil {
			return err
		}
		return transformArray(login, "fido2Credentials", fido2SecretFields, key, encrypt)
	}
	return nil
}

func validateMigrationAttachments(raw any) error {
	if err := copyArrayKeys(raw, "object", "id", "url", "fileName", "size", "sizeName", "key"); err != nil {
		return err
	}
	rows, _ := raw.([]any)
	for _, value := range rows {
		object := value.(map[string]any)["object"]
		if object != nil && object != "attachment" {
			return ErrUnsupportedEdit
		}
	}
	return nil
}

// rekeyLegacyShare never shares an owner key. Keyed attachments retain their
// binary ciphertext and independent key; only that key wrapper and name change.
// Keyless binaries must first be upgraded with the public attachment API.
func rekeyLegacyShare(object map[string]any, oldKey, newKey []byte) error {
	attachments := object["attachments"]
	delete(object, "attachments")
	err := validateCopyObject(object)
	object["attachments"] = attachments
	if err != nil {
		return err
	}
	if err := validateMigrationAttachments(attachments); err != nil {
		return err
	}
	if list, ok := attachments.([]any); ok {
		for _, raw := range list {
			entry := raw.(map[string]any)
			wrapped, ok := entry["key"].(string)
			if !ok || wrapped == "" {
				return ErrUnsupportedEdit
			}
			key, err := DecryptString(wrapped, oldKey)
			if err != nil {
				return err
			}
			if len(key) != 64 {
				clear(key)
				return ErrEncryption
			}
			entry["key"], err = EncryptString(key, newKey)
			clear(key)
			if err != nil {
				return err
			}
			if err := transformField(entry, "fileName", oldKey, false); err != nil {
				return err
			}
			if err := transformField(entry, "fileName", newKey, true); err != nil {
				return err
			}
		}
	}
	if err := transformCompleteCipher(object, oldKey, false); err != nil {
		return err
	}
	return transformCompleteCipher(object, newKey, true)
}
