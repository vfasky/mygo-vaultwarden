// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"time"
)

// RotationCipherResources owns encrypted output only; it does not cover Sends or
// recovery recipients and must be composed with their respective adapters.
type RotationCipherResources struct {
	Ciphers []json.RawMessage
	Folders []AccountRotationFolder
}
type RotationCipherPreparation struct {
	CipherID     string
	AttachmentID string
	Reason       string
	Deleted      bool
}
type RotationCipherReadiness struct {
	Ready        bool
	Preparations []RotationCipherPreparation
}

// RotationCipherPreparationError is actionable metadata, never plaintext or keys.
type RotationCipherPreparationError struct{ Readiness RotationCipherReadiness }

func (e *RotationCipherPreparationError) Error() string {
	return "account rotation requires independent attachment key preparation"
}
func (e *RotationCipherPreparationError) Unwrap() error { return ErrUnsupportedEdit }

type rotationCipherInventory struct {
	ciphers, folders []json.RawMessage
}

func rotationCipherInventoryFrom(sync json.RawMessage, scope Scope) (rotationCipherInventory, error) {
	var out rotationCipherInventory
	if scope.Server == "" || !validObjectID(scope.Account) || strictJSON(sync) != nil {
		return out, ErrIdentity
	}
	var wire struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
		Ciphers []json.RawMessage `json:"ciphers"`
		Folders []json.RawMessage `json:"folders"`
	}
	if json.Unmarshal(sync, &wire) != nil || wire.Profile.ID != scope.Account {
		return out, ErrIdentity
	}
	for _, rows := range [][]json.RawMessage{wire.Ciphers, wire.Folders} {
		ids, err := accountRawIDs(rows, false)
		if err != nil {
			return out, err
		}
		if err = accountExactIDs(ids, ids); err != nil {
			return out, err
		}
	}
	out.ciphers, out.folders = wire.Ciphers, wire.Folders
	return out, nil
}
func rotationCipherObject(raw json.RawMessage) (map[string]any, error) {
	if strictJSON(raw) != nil {
		return nil, ErrProtocol
	}
	return documentObject(CipherDocument{JSON: raw})
}
func rotationCipherValidate(object map[string]any, account string) error {
	id, ok := object["id"].(string)
	if !ok || !validObjectID(id) || object["organizationId"] != nil {
		return ErrIdentity
	}
	if v := object["encryptedFor"]; v != nil && v != account {
		return ErrIdentity
	}
	attachments := object["attachments"]
	delete(object, "attachments")
	err := validateCopyObject(object)
	object["attachments"] = attachments
	if err != nil {
		return err
	}
	if err = validateMigrationAttachments(attachments); err != nil {
		return err
	}
	if _, err = shareRecoveryAttachments(object); err != nil {
		return err
	}
	kind, ok := object["type"].(json.Number)
	if !ok {
		return ErrProtocol
	}
	n, err := kind.Int64()
	if err != nil {
		return ErrProtocol
	}
	if _, ok = object[cipherSections[int(n)]].(map[string]any); !ok {
		return ErrProtocol
	}
	if name, ok := object["name"].(string); !ok || name == "" {
		return ErrEncryption
	}
	if revision, ok := object["revisionDate"].(string); !ok {
		return ErrProtocol
	} else if _, err = time.Parse(time.RFC3339Nano, revision); err != nil {
		return ErrProtocol
	}
	if reprompt := object["reprompt"]; reprompt != nil && reprompt != json.Number("0") && reprompt != json.Number("1") {
		return ErrProtocol
	}
	return nil
}
func rotationCipherFolder(raw json.RawMessage) (AccountRotationFolder, error) {
	var folder AccountRotationFolder
	object, err := rotationCipherObject(raw)
	if err != nil {
		return folder, err
	}
	if err = copyKeys(object, "id", "name", "object", "revisionDate"); err != nil {
		return folder, err
	}
	if v := object["object"]; v != nil && v != "folder" {
		return folder, ErrProtocol
	}
	if json.Unmarshal(raw, &folder) != nil || !validObjectID(folder.ID) || folder.Name == "" {
		return folder, ErrProtocol
	}
	return folder, nil
}

// AnalyzeAccountRotationCipherResources borrows all input. No transport or Session
// methods are called. Legacy binary files use the OWNER key even on keyed ciphers.
// The host must upgrade, verify/delete explicitly, then obtain a fresh sync.
func AnalyzeAccountRotationCipherResources(ctx context.Context, input AccountRotationInput) (RotationCipherReadiness, error) {
	result := RotationCipherReadiness{Preparations: []RotationCipherPreparation{}}
	if len(input.OldUserKey) != 64 {
		return result, ErrEncryption
	}
	inventory, err := rotationCipherInventoryFrom(input.Sync, input.Scope)
	if err != nil {
		return result, err
	}
	for _, raw := range inventory.ciphers {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		object, e := rotationCipherObject(raw)
		if e != nil {
			return result, e
		}
		if org := object["organizationId"]; org != nil {
			id, ok := org.(string)
			if !ok || !validObjectID(id) {
				return result, ErrIdentity
			}
			continue
		}
		if e = rotationCipherValidate(object, input.Scope.Account); e != nil {
			return result, e
		}
		key, e := cipherItemKey(object, input.OldUserKey)
		if e != nil {
			return result, e
		}
		if wrapped, _ := object["key"].(string); wrapped != "" && bytes.Equal(key, input.OldUserKey) {
			clear(key)
			return result, ErrEncryption
		}
		e = transformCompleteCipher(object, key, false)
		if e == nil {
			rows, _ := object["attachments"].([]any)
			for _, row := range rows {
				attachment := row.(map[string]any)
				if name, ok := attachment["fileName"].(string); !ok || name == "" {
					e = ErrProtocol
					break
				}
				if e = transformField(attachment, "fileName", key, false); e != nil {
					break
				}
				wrapped, ok := attachment["key"].(string)
				if attachment["key"] != nil && !ok {
					e = ErrProtocol
					break
				}
				if wrapped == "" {
					result.Preparations = append(result.Preparations, RotationCipherPreparation{CipherID: object["id"].(string), AttachmentID: attachment["id"].(string), Reason: "owner-key-binary: upgrade, verify both files, explicitly delete original, fresh sync", Deleted: object["deletedDate"] != nil})
					continue
				}
				var attachmentKey []byte
				attachmentKey, e = vaultcrypto.DecryptString(wrapped, key)
				if e == nil && (len(attachmentKey) != 64 || bytes.Equal(attachmentKey, input.OldUserKey)) {
					e = ErrEncryption
				}
				clear(attachmentKey)
				if e != nil {
					break
				}
			}
		}
		clear(key)
		if e != nil {
			return result, e
		}
	}
	for _, raw := range inventory.folders {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		folder, e := rotationCipherFolder(raw)
		if e != nil {
			return result, e
		}
		plain, e := vaultcrypto.DecryptString(folder.Name, input.OldUserKey)
		clear(plain)
		if e != nil {
			return result, e
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	result.Ready = len(result.Preparations) == 0
	return result, nil
}

// ConvertAccountRotationCipherResources constructs CipherData, not a sync reply.
// Unknown schema is rejected before returning any request. It never mutates input.
func ConvertAccountRotationCipherResources(ctx context.Context, input AccountRotationInput) (RotationCipherResources, error) {
	empty := RotationCipherResources{}
	if len(input.NewUserKey) != 64 || bytes.Equal(input.OldUserKey, input.NewUserKey) {
		return empty, ErrEncryption
	}
	ready, err := AnalyzeAccountRotationCipherResources(ctx, input)
	if err != nil {
		return empty, err
	}
	if !ready.Ready {
		return empty, &RotationCipherPreparationError{Readiness: ready}
	}
	inventory, _ := rotationCipherInventoryFrom(input.Sync, input.Scope)
	result := RotationCipherResources{Ciphers: []json.RawMessage{}, Folders: []AccountRotationFolder{}}
	for _, raw := range inventory.ciphers {
		if err = ctx.Err(); err != nil {
			return empty, err
		}
		object, _ := rotationCipherObject(raw)
		if object["organizationId"] != nil {
			continue
		}
		if wrapped, _ := object["key"].(string); wrapped != "" {
			key, e := cipherItemKey(object, input.OldUserKey)
			if e != nil {
				return empty, e
			}
			object["key"], err = vaultcrypto.EncryptString(key, input.NewUserKey)
			clear(key)
		} else {
			err = rekeyLegacyShare(object, input.OldUserKey, input.NewUserKey)
		}
		if err != nil {
			return empty, err
		}
		dto := map[string]any{}
		for _, name := range rotationCipherDTOFields {
			if value, ok := object[name]; ok {
				dto[name] = value
			}
		}
		dto["encryptedFor"] = input.Scope.Account
		dto["lastKnownRevisionDate"] = object["revisionDate"]
		dto["attachments2"], err = shareRecoveryAttachments(object)
		if err != nil {
			return empty, err
		}
		encoded, e := json.Marshal(dto)
		if e != nil {
			return empty, e
		}
		result.Ciphers = append(result.Ciphers, encoded)
	}
	for _, raw := range inventory.folders {
		if err = ctx.Err(); err != nil {
			return empty, err
		}
		folder, _ := rotationCipherFolder(raw)
		folder, err = AccountRewrapRotationFolder(folder, input.OldUserKey, input.NewUserKey)
		if err != nil {
			return empty, err
		}
		result.Folders = append(result.Folders, folder)
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	return result, nil
}

// Fixed CipherData in Vaultwarden 1.37.4 ciphers.rs:260-326. deletedDate is
// deliberately absent: update_cipher_from_data retains existing deleted_at.
var rotationCipherDTOFields = []string{"id", "folderId", "organizationId", "key", "encryptedByKeyId", "type", "name", "notes", "fields", "login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport", "favorite", "reprompt", "passwordHistory", "archivedDate"}

func rotationCipherError(id string, err error) error {
	return fmt.Errorf("rotation cipher %s: %w", id, err)
}
