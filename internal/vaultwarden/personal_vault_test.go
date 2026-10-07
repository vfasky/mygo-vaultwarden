// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateEightCipherTypesWithIndependentKeys(t *testing.T) {
	key := bytes.Repeat([]byte{29}, 64)
	for kind := 1; kind <= 8; kind++ {
		t.Run(cipherSections[kind], func(t *testing.T) {
			fields := CipherFields{Type: kind, Name: "new secret title"}
			detail := map[string]any{}
			for _, name := range cipherSecrets[cipherSections[kind]] {
				detail[name] = "new secret " + name
			}
			switch kind {
			case 1:
				fields.Login = detail
			case 2:
				fields.SecureNote = detail
			case 3:
				fields.Card = detail
			case 4:
				fields.Identity = detail
			case 5:
				fields.SSHKey = detail
			case 6:
				fields.BankAccount = detail
			case 7:
				fields.DriversLicense = detail
			case 8:
				fields.Passport = detail
			}
			first, err := NewPersonalCipher(fields, key, "account-a")
			if err != nil {
				t.Fatal(err)
			}
			second, err := NewPersonalCipher(fields, key, "account-a")
			if err != nil {
				t.Fatal(err)
			}
			a, _ := documentObject(first)
			b, _ := documentObject(second)
			ka, err := cipherItemKey(a, key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(ka)
			kb, err := cipherItemKey(b, key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(kb)
			if bytes.Equal(ka, kb) || bytes.Equal(ka, key) {
				t.Fatal("item key reused")
			}
			got, err := DecryptCipherDocument(first, key)
			if err != nil || got.Name != fields.Name || got.Type != kind {
				t.Fatal("create decryption", err)
			}
			gotDetail := map[int]map[string]any{1: got.Login, 2: got.SecureNote, 3: got.Card, 4: got.Identity, 5: got.SSHKey, 6: got.BankAccount, 7: got.DriversLicense, 8: got.Passport}[kind]
			for name, value := range detail {
				if gotDetail[name] != value {
					t.Fatal("created field lost", name)
				}
			}
			if bytes.Contains(first.JSON, []byte("new secret")) {
				t.Fatal("plaintext field transmitted")
			}
			if a["encryptedFor"] != "account-a" || bytes.Contains(first.JSON, []byte(fields.Name)) {
				t.Fatal("unbound/plaintext create")
			}
		})
	}
}
func TestNewCipherRejectsOpaqueExtensionsAndMissingSSHMaterial(t *testing.T) {
	key := bytes.Repeat([]byte{2}, 64)
	for _, fields := range []CipherFields{
		{Type: 1, Name: "copy", Login: map[string]any{"fido2Credentials": []any{map[string]any{"keyValue": "opaque"}}}},
		{Type: 1, Name: "copy", Fields: []map[string]any{{"name": "field", "futureEncrypted": "opaque"}}},
		{Type: 1, Name: "copy", Login: map[string]any{"uris": []any{map[string]any{"uri": "https://example.invalid", "futureEncrypted": "opaque"}}}},
		{Type: 5, Name: "missing keys"},
	} {
		if _, err := NewPersonalCipher(fields, key, "account-a"); err == nil {
			t.Fatal("new key silently lost unknown data or SSH material")
		}
	}
}

func TestPasswordHistoryAndURIChangesPreserveExtensions(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 1)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.Login["password"] = "new password"
	uris := fields.Login["uris"].([]any)
	uri := uris[0].(map[string]any)
	uri["uri"] = "https://changed.example.invalid"
	before, _ := json.Marshal(fields)
	result, err := EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(fields)
	if !bytes.Equal(before, after) {
		t.Fatal("encryption mutated editable draft")
	}
	got, err := DecryptCipherDocument(result, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login["password"] != "new password" || len(got.PasswordHistory) != 2 || got.PasswordHistory[0]["password"] != "original password" {
		t.Fatal("password history missing")
	}
	checksum := sha256.Sum256([]byte("https://changed.example.invalid"))
	gotURI := got.Login["uris"].([]any)[0].(map[string]any)
	if gotURI["uriChecksum"] != base64.StdEncoding.EncodeToString(checksum[:]) {
		t.Fatal("URI checksum incorrect")
	}
	object, _ := documentObject(result)
	if object["login"].(map[string]any)["fido2Credentials"].([]any)[0].(map[string]any)["keyValue"] != "opaque future cipher text" {
		t.Fatal("lost passkey")
	}
}
func TestCustomFieldEditPreservesOpaqueExtensionsAndDraft(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 1)
	object, _ := documentObject(doc)
	custom := object["fields"].([]any)[0].(map[string]any)
	custom["futureValue"] = "opaque encrypted extension"
	custom["largeID"] = json.Number("9007199254740993")
	doc.JSON, _ = json.Marshal(object)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.Fields[0]["value"] = "edited custom secret"
	before, _ := json.Marshal(fields)
	updated, err := EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(fields)
	if !bytes.Equal(before, after) {
		t.Fatal("draft mutated")
	}
	decoded, err := DecryptCipherDocument(updated, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Fields[0]["value"] != "edited custom secret" || decoded.Fields[0]["largeID"] != json.Number("9007199254740993") || decoded.Fields[0]["futureValue"] != "opaque encrypted extension" {
		t.Fatal("custom extensions lost")
	}
	if bytes.Contains(updated.JSON, []byte("edited custom secret")) {
		t.Fatal("plaintext custom field transmitted")
	}
}

func TestMutationUnexpectedSuccessOrServerErrorIsUncertain(t *testing.T) {
	for _, status := range []int{201, 202, 500, 503} {
		var unknown *MutationUncertainError
		if !errors.As(mutationStatusError(status), &unknown) {
			t.Fatal("retryable mutation status", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 409, 429} {
		var unknown *MutationUncertainError
		if errors.As(mutationStatusError(status), &unknown) {
			t.Fatal("lost known rejection", status)
		}
	}
}

func TestSuccessfulWriteMalformedResponseIsUncertain(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 3)
	fields, _ := DecryptCipherDocument(doc, key)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.Write([]byte(`{"unexpected":true}`)) }))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	session.key = key
	defer session.Close()
	_, err := session.UpdatePersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, doc, fields, nil)
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) || requests != 1 {
		t.Fatal("unconfirmed update not classified", err)
	}
}
func TestCompleteVaultScopeUnknownDataAndPermissions(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 1)
	object, _ := documentObject(doc)
	object["archivedDate"] = "2026-01-01T00:00:00Z"
	doc.JSON, _ = json.Marshal(object)
	scope := Scope{Server: "http://127.0.0.1:9000", Account: "account-a"}
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account, "privateKey": "opaque-private"}, "ciphers": []json.RawMessage{doc.JSON}, "futureSection": map[string]any{"large": json.Number("9007199254740993")}})
	vault := &VaultData{Version: 1, Scope: scope, Sync: raw}
	documents, err := vault.Documents(scope)
	if err != nil || len(documents) != 1 {
		t.Fatal(err)
	}
	if _, err := vault.Documents(Scope{Server: scope.Server, Account: "other"}); err != ErrIdentity {
		t.Fatal("wrong account accepted")
	}
	session, _ := resumableFixture(t, scope.Server)
	session.key = key
	defer session.Close()
	entries, err := session.PersonalEntries(vault)
	if err != nil || len(entries) != 1 || !entries[0].Archived {
		t.Fatal("archive missing", err)
	}
	_, fields, err := session.ReadPersonalCipher(vault, "item-1")
	if err != nil || fields.Name != "原标题" {
		t.Fatal(err)
	}
	if !bytes.Contains(vault.Sync, []byte("9007199254740993")) {
		t.Fatal("unknown data lost")
	}
	object["reprompt"] = 1
	doc.JSON, _ = json.Marshal(object)
	vault.Sync, _ = json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account}, "ciphers": []json.RawMessage{doc.JSON}})
	if _, _, err := session.ReadPersonalCipher(vault, "item-1"); err != ErrPermission {
		t.Fatal("reprompt bypass")
	}
	entries, err = session.PersonalEntries(vault)
	if err != nil || entries[0].Title == "原标题" || entries[0].Editable {
		t.Fatal("reprompt metadata leaked")
	}
	session.Close()
	if _, err := session.PersonalEntries(vault); err != ErrExpired {
		t.Fatal("closed session read")
	}
}
