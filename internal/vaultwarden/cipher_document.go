// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	BankAccount     map[string]any
	DriversLicense  map[string]any
	Passport        map[string]any
	Fields          []map[string]any
	PasswordHistory []map[string]any
}

var cipherSections = map[int]string{1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport"}
var cipherSecrets = map[string][]string{
	"login":          {"username", "password", "totp"},
	"card":           {"cardholderName", "brand", "number", "expMonth", "expYear", "code"},
	"identity":       {"title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber"},
	"sshKey":         {"privateKey", "publicKey", "keyFingerprint"},
	"bankAccount":    {"bankName", "nameOnAccount", "accountType", "accountNumber", "routingNumber", "branchNumber", "pin", "swiftCode", "iban", "bankContactPhone"},
	"driversLicense": {"firstName", "middleName", "lastName", "dateOfBirth", "licenseNumber", "issuingCountry", "issuingState", "issueDate", "expirationDate", "issuingAuthority", "licenseClass"},
	"passport":       {"surname", "givenName", "dateOfBirth", "sex", "birthPlace", "nationality", "issuingCountry", "passportNumber", "passportType", "nationalIdentificationNumber", "issuingAuthority", "issueDate", "expirationDate"},
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
			// Vaultwarden also returns the encrypted first-URI alias for legacy
			// clients. It must be rekeyed alongside the canonical URI list.
			if err := transformField(values, "uri", key, encrypt); err != nil {
				return err
			}
			if err := transformArray(values, "uris", []string{"uri", "uriChecksum"}, key, encrypt); err != nil {
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&fields) != nil || cipherSections[fields.Type] == "" || fields.Name == "" || len(fields.Name) > 4096 {
		return CipherFields{}, ErrProtocol
	}
	if section, ok := object[cipherSections[fields.Type]].(map[string]any); !ok || section == nil {
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
	return encryptCipherDocument(document, fields, ownerKey, account, false)
}

func encryptCipherDocument(document CipherDocument, fields CipherFields, ownerKey []byte, account string, authorized bool) (CipherDocument, error) {
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
	if !original.Edit || (original.Reprompt != 0 && (original.Reprompt != 1 || !authorized)) || !original.ViewPassword {
		return CipherDocument{}, ErrPermission
	}
	if fields.Name == "" || len(fields.Name) > 4096 || fields.Reprompt < 0 || fields.Reprompt > 1 {
		return CipherDocument{}, ErrValidation
	}
	if !historySubsequence(fields.PasswordHistory, original.PasswordHistory) || !sameOptional(fields.ArchivedDate, original.ArchivedDate) || !sameOptional(fields.DeletedDate, original.DeletedDate) {
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
	if !reflect.DeepEqual(fields.Fields, original.Fields) {
		custom, err := cloneCustomFields(fields.Fields)
		if err != nil {
			return CipherDocument{}, err
		}
		object["fields"] = custom
	}
	if !reflect.DeepEqual(fields.PasswordHistory, original.PasswordHistory) {
		// Only removal is permitted. Clone retained entries so encryption never
		// mutates the UI draft, including any unknown history extensions.
		raw, err := json.Marshal(fields.PasswordHistory)
		if err != nil {
			return CipherDocument{}, ErrProtocol
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var history any
		err = decoder.Decode(&history)
		clear(raw)
		if err != nil {
			return CipherDocument{}, ErrProtocol
		}
		object["passwordHistory"] = history
	}
	object["favorite"], object["reprompt"] = fields.Favorite, fields.Reprompt
	section := cipherSections[fields.Type]
	incoming := map[string]map[string]any{"login": fields.Login, "secureNote": fields.SecureNote, "card": fields.Card, "identity": fields.Identity, "sshKey": fields.SSHKey, "bankAccount": fields.BankAccount, "driversLicense": fields.DriversLicense, "passport": fields.Passport}[section]
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
		if name == "uris" && reflect.DeepEqual(incoming[name], original.Login[name]) {
			continue
		}
		if value, ok := incoming[name]; ok {
			existing[name] = value
		}
	}
	if fields.Type == 1 && !reflect.DeepEqual(fields.Login["uris"], original.Login["uris"]) {
		if err := checksumURIs(existing); err != nil {
			return CipherDocument{}, err
		}
		if _, hasLegacyURI := existing["uri"]; hasLegacyURI {
			existing["uri"] = nil
			if uris, ok := existing["uris"].([]any); ok && len(uris) > 0 {
				existing["uri"] = uris[0].(map[string]any)["uri"]
			}
		}
	}
	if fields.Type == 1 && !reflect.DeepEqual(fields.Login["password"], original.Login["password"]) {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if previous, ok := original.Login["password"].(string); ok && previous != "" {
			history, _ := object["passwordHistory"].([]any)
			object["passwordHistory"] = append([]any{map[string]any{"password": previous, "lastUsedDate": now}}, history...)
		}
		existing["passwordRevisionDate"] = now
	}
	// History changes are generated above from the prior password; unknown
	// custom-field and history extensions remain under the unchanged item key.
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

// A draft may delete history entries, but cannot forge or reorder passwords,
// timestamps or opaque extensions. Duplicate entries consume distinct originals.
func historySubsequence(kept, original []map[string]any) bool {
	position := 0
	for _, entry := range kept {
		for position < len(original) && !reflect.DeepEqual(entry, original[position]) {
			position++
		}
		if position == len(original) {
			return false
		}
		position++
	}
	return true
}

// NewPersonalCipher creates a fresh item key and only accepts known input fields.
// Copying an existing cipher (especially passkeys/attachments) is a separate operation.
func NewPersonalCipher(fields CipherFields, ownerKey []byte, account string) (CipherDocument, error) {
	section := cipherSections[fields.Type]
	if section == "" || fields.Name == "" || len(fields.Name) > 4096 || fields.ID != "" || fields.OrganizationID != nil || fields.Reprompt < 0 || fields.Reprompt > 1 || account == "" {
		return CipherDocument{}, ErrValidation
	}
	if fields.Type == 5 {
		for _, name := range cipherSecrets["sshKey"] {
			if value, ok := fields.SSHKey[name].(string); !ok || value == "" {
				return CipherDocument{}, ErrValidation
			}
		}
	}
	if len(fields.PasswordHistory) != 0 {
		return CipherDocument{}, ErrUnsupportedEdit
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
	incoming := map[string]map[string]any{"login": fields.Login, "secureNote": fields.SecureNote, "card": fields.Card, "identity": fields.Identity, "sshKey": fields.SSHKey, "bankAccount": fields.BankAccount, "driversLicense": fields.DriversLicense, "passport": fields.Passport}[section]
	allowed := map[string]bool{}
	for _, name := range cipherSecrets[section] {
		allowed[name] = true
	}
	if section == "login" {
		allowed["uris"] = true
	}
	if section == "secureNote" {
		allowed["type"] = true
	}
	for name := range incoming {
		if !allowed[name] {
			return CipherDocument{}, ErrUnsupportedEdit
		}
	}
	for _, field := range fields.Fields {
		for name := range field {
			if name != "name" && name != "value" && name != "type" && name != "linkedId" {
				return CipherDocument{}, ErrUnsupportedEdit
			}
		}
	}
	detail := map[string]any{}
	for _, name := range cipherSecrets[section] {
		if value, exists := incoming[name]; exists {
			detail[name] = value
		}
	}
	if section == "login" {
		if uris, exists := incoming["uris"]; exists {
			if entries, ok := uris.([]any); ok {
				for _, raw := range entries {
					if entry, ok := raw.(map[string]any); ok {
						for name := range entry {
							if name != "uri" && name != "match" && name != "uriChecksum" {
								return CipherDocument{}, ErrUnsupportedEdit
							}
						}
					}
				}
			}
			detail["uris"] = uris
		}
		if err := checksumURIs(detail); err != nil {
			return CipherDocument{}, err
		}
	}
	if section == "secureNote" {
		detail["type"] = 0
	}
	object := map[string]any{"type": fields.Type, "name": fields.Name, "notes": nil, "folderId": fields.FolderID, "favorite": fields.Favorite, "reprompt": fields.Reprompt, "key": wrapped, "encryptedFor": account, section: detail, "fields": nil, "passwordHistory": nil}
	custom, err := cloneCustomFields(fields.Fields)
	if err != nil {
		return CipherDocument{}, err
	}
	object["fields"] = custom
	if fields.Notes != nil {
		object["notes"] = *fields.Notes
	}
	if err := transformCipher(object, key, true); err != nil {
		return CipherDocument{}, err
	}
	data, err := json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	return CipherDocument{JSON: data}, nil
}

func cloneCustomFields(fields []map[string]any) (any, error) {
	if fields == nil {
		return nil, nil
	}
	if len(fields) > 10000 {
		return nil, ErrValidation
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return nil, ErrValidation
	}
	var result []any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return nil, ErrValidation
	}
	return result, nil
}

func checksumURIs(login map[string]any) error {
	if login["uris"] == nil {
		return nil
	}
	encoded, err := json.Marshal(login["uris"])
	if err != nil {
		return ErrValidation
	}
	var uris []any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&uris) != nil || len(uris) > 128 {
		return ErrValidation
	}
	login["uris"] = uris
	for _, raw := range uris {
		uri, ok := raw.(map[string]any)
		if !ok {
			return ErrValidation
		}
		value, ok := uri["uri"].(string)
		if !ok || len(value) > 8192 {
			return ErrValidation
		}
		hash := sha256.Sum256([]byte(value))
		uri["uriChecksum"] = base64.StdEncoding.EncodeToString(hash[:])
	}
	return nil
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
