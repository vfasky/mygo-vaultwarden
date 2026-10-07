// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
)

// CipherDocument retains the original encrypted JSON, including extensions that
// this client cannot edit. It must only be carried in the authenticated encrypted
// snapshot; even encrypted field values are not display-list metadata.
type CipherDocument struct {
	JSON json.RawMessage `json:"json"`
}

// CipherFields contains locally decrypted editable fields. The source document
// and its unchanged item key must accompany an update: unknown fields (including
// passkeys) remain encrypted under that same key and are never synthesized.
type CipherFields struct {
	ID              string
	Type            int
	Name            string
	Notes           *string
	FolderID        *string
	OrganizationID  *string
	Favorite        bool
	Reprompt        int
	RevisionDate    string
	ArchivedDate    *string
	DeletedDate     *string
	Edit            bool
	ViewPassword    bool
	Login           map[string]any
	SecureNote      map[string]any
	Card            map[string]any
	Identity        map[string]any
	SSHKey          map[string]any
	Fields          []map[string]any
	PasswordHistory []map[string]any
}

var cipherSections = map[int]string{1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey"}
var cipherSecrets = map[string][]string{
	"login":    {"username", "password", "totp"},
	"card":     {"cardholderName", "brand", "number", "expMonth", "expYear", "code"},
	"identity": {"title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber"},
	"sshKey":   {"privateKey", "publicKey", "keyFingerprint"},
}

func documentObject(document CipherDocument) (map[string]any, error) {
	if len(document.JSON) == 0 || len(document.JSON) > maxResponse {
		return nil, ErrProtocol
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(document.JSON))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil {
		return nil, ErrProtocol
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, ErrProtocol
	}
	return object, nil
}
func cipherItemKey(object map[string]any, userKey []byte) ([]byte, error) {
	if wrapped, ok := object["key"]; ok && wrapped != nil && wrapped != "" {
		value, ok := wrapped.(string)
		if !ok {
			return nil, ErrEncryption
		}
		key, err := DecryptString(value, userKey)
		if err != nil {
			return nil, err
		}
		if len(key) != 64 {
			clear(key)
			return nil, ErrEncryption
		}
		return key, nil
	}
	if len(userKey) != 64 {
		return nil, ErrEncryption
	}
	return append([]byte(nil), userKey...), nil
}
func transformField(object map[string]any, name string, key []byte, encrypt bool) error {
	value, exists := object[name]
	if !exists || value == nil {
		return nil
	}
	text, ok := value.(string)
	if !ok {
		return ErrProtocol
	}
	if encrypt {
		encoded, err := EncryptString([]byte(text), key)
		if err != nil {
			return err
		}
		object[name] = encoded
		return nil
	}
	// Only absent/null represents an optional missing field. An empty encrypted
	// string cannot silently turn an unsupported/corrupt field into success.
	plain, err := decryptText(&text, key)
	if err != nil {
		return err
	}
	object[name] = plain
	return nil
}
func transformCipher(object map[string]any, key []byte, encrypt bool) error {
	for _, name := range []string{"name", "notes"} {
		if err := transformField(object, name, key, encrypt); err != nil {
			return err
		}
	}
	for section, names := range cipherSecrets {
		raw := object[section]
		if raw == nil {
			continue
		}
		values, ok := raw.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		for _, name := range names {
			if err := transformField(values, name, key, encrypt); err != nil {
				return err
			}
		}
		if section == "login" {
			if err := transformArray(values, "uris", []string{"uri"}, key, encrypt); err != nil {
				return err
			}
		}
	}
	if err := transformArray(object, "fields", []string{"name", "value"}, key, encrypt); err != nil {
		return err
	}
	return transformArray(object, "passwordHistory", []string{"password"}, key, encrypt)
}
func transformArray(object map[string]any, name string, fields []string, key []byte, encrypt bool) error {
	if object[name] == nil {
		return nil
	}
	values, ok := object[name].([]any)
	if !ok || len(values) > 10000 {
		return ErrProtocol
	}
	for _, raw := range values {
		entry, ok := raw.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		for _, field := range fields {
			if err := transformField(entry, field, key, encrypt); err != nil {
				return err
			}
		}
	}
	return nil
}
func decodeCipherFields(object map[string]any) (CipherFields, error) {
	// Decode once through a typed boundary; retaining the original object is what
	// preserves unknown encrypted extensions, not a lossy struct round trip.
	data, err := json.Marshal(object)
	if err != nil {
		return CipherFields{}, ErrProtocol
	}
	defer clear(data)
	var fields CipherFields
	if json.Unmarshal(data, &fields) != nil || cipherSections[fields.Type] == "" || fields.Name == "" || len(fields.Name) > 4096 {
		return CipherFields{}, ErrProtocol
	}
	return fields, nil
}
func DecryptCipherDocument(document CipherDocument, ownerKey []byte) (CipherFields, error) {
	object, err := documentObject(document)
	if err != nil {
		return CipherFields{}, err
	}
	key, err := cipherItemKey(object, ownerKey)
	if err != nil {
		return CipherFields{}, err
	}
	defer clear(key)
	if err := transformCipher(object, key, false); err != nil {
		return CipherFields{}, err
	}
	return decodeCipherFields(object)
}

// EncryptCipherDocument updates only supported fields. It never changes keys,
// ownership, type, revision or opaque extensions. Copy/share/key rotation need a
// separate complete transform and must not reuse this operation.
func EncryptCipherDocument(document CipherDocument, fields CipherFields, ownerKey []byte, account string) (CipherDocument, error) {
	object, err := documentObject(document)
	if err != nil {
		return CipherDocument{}, err
	}
	original, err := DecryptCipherDocument(document, ownerKey)
	if err != nil {
		return CipherDocument{}, err
	}
	if account == "" || fields.ID != original.ID || fields.Type != original.Type || fields.RevisionDate != original.RevisionDate || !sameOptional(fields.OrganizationID, original.OrganizationID) {
		return CipherDocument{}, ErrIdentity
	}
	if _, err := time.Parse(time.RFC3339Nano, original.RevisionDate); err != nil {
		return CipherDocument{}, ErrConflict
	}
	if !original.Edit || original.Reprompt != 0 || !original.ViewPassword {
		return CipherDocument{}, ErrPermission
	}
	if fields.Name == "" || len(fields.Name) > 4096 || fields.Reprompt < 0 || fields.Reprompt > 1 {
		return CipherDocument{}, ErrValidation
	}
	if !reflect.DeepEqual(fields.Fields, original.Fields) || !reflect.DeepEqual(fields.PasswordHistory, original.PasswordHistory) || !sameOptional(fields.ArchivedDate, original.ArchivedDate) || !sameOptional(fields.DeletedDate, original.DeletedDate) {
		return CipherDocument{}, ErrUnsupportedEdit
	}
	if fields.Type == 1 && (!reflect.DeepEqual(fields.Login["uris"], original.Login["uris"]) || !reflect.DeepEqual(fields.Login["password"], original.Login["password"])) {
		return CipherDocument{}, ErrUnsupportedEdit
	}
	key, err := cipherItemKey(object, ownerKey)
	if err != nil {
		return CipherDocument{}, err
	}
	defer clear(key)
	// Merge supported values into the original decrypted representation so new
	// server fields remain byte-equivalent encrypted values through the update.
	if err := transformCipher(object, key, false); err != nil {
		return CipherDocument{}, err
	}
	object["name"], object["notes"], object["folderId"] = fields.Name, nil, fields.FolderID
	if fields.Notes != nil {
		object["notes"] = *fields.Notes
	}
	object["favorite"], object["reprompt"] = fields.Favorite, fields.Reprompt
	section := cipherSections[fields.Type]
	incoming := map[string]map[string]any{"login": fields.Login, "secureNote": fields.SecureNote, "card": fields.Card, "identity": fields.Identity, "sshKey": fields.SSHKey}[section]
	existing, _ := object[section].(map[string]any)
	if existing == nil {
		return CipherDocument{}, ErrProtocol
	}
	// Only known section fields are writable through this boundary. Unknown
	// sensitive extensions must stay exactly as they arrived from the server.
	allowed := append([]string(nil), cipherSecrets[section]...)
	if section == "login" {
		allowed = append(allowed, "uris", "passwordRevisionDate")
	}
	if section == "secureNote" {
		allowed = append(allowed, "type")
	}
	for _, name := range allowed {
		if value, ok := incoming[name]; ok {
			existing[name] = value
		}
	}
	// Custom fields and history may carry unknown extension data; changes to
	// these arrays require a dedicated lossless editor. Preserve them here.
	object["encryptedFor"] = account
	object["lastKnownRevisionDate"] = original.RevisionDate
	if err := transformCipher(object, key, true); err != nil {
		return CipherDocument{}, err
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	return CipherDocument{JSON: encoded}, nil
}
func sameOptional(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func validObjectID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return !strings.Contains(id, "..")
}
