// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"reflect"
	"testing"
	"time"
)

func migrationFIDOFixture(t *testing.T, key []byte) (map[string]any, map[string]any) {
	t.Helper()
	// Official wire model's string metadata is encrypted too, including counter
	// and discoverable. Optional nulls and nanosecond creationDate are preserved.
	plain := map[string]any{"credentialId": "b64.credential", "keyType": "public-key", "keyAlgorithm": "ECDSA", "keyCurve": "P-256", "keyValue": "base64url-pkcs8", "rpId": "example.invalid", "userHandle": "handle", "userName": "user", "counter": "42", "rpName": nil, "userDisplayName": "显示名", "discoverable": "true", "creationDate": "2026-01-01T01:02:03.123456789Z"}
	encrypted := map[string]any{}
	for name, value := range plain {
		if name == "creationDate" || value == nil {
			encrypted[name] = value
			continue
		}
		var err error
		encrypted[name], err = vaultcrypto.EncryptString([]byte(value.(string)), key)
		if err != nil {
			t.Fatal(err)
		}
	}
	return plain, encrypted
}

func TestMigrationFIDO2CopyAndBackup(t *testing.T) {
	source, ownerKey := copyFixture(t, 1)
	object, _ := documentObject(source)
	oldKey, _ := cipherItemKey(object, ownerKey)
	defer clear(oldKey)
	plain, encrypted := migrationFIDOFixture(t, oldKey)
	object["login"].(map[string]any)["fido2Credentials"] = []any{encrypted}
	source.JSON, _ = json.Marshal(object)
	before := append([]byte(nil), source.JSON...)
	copied, err := copyPersonalCipherDocument(source, ownerKey, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	copyObject, _ := documentObject(copied)
	newKey, _ := cipherItemKey(copyObject, ownerKey)
	defer clear(newKey)
	credential := copyObject["login"].(map[string]any)["fido2Credentials"].([]any)[0].(map[string]any)
	for _, name := range fido2SecretFields {
		if plain[name] == nil {
			if credential[name] != nil {
				t.Fatal("null changed")
			}
			continue
		}
		text, err := vaultcrypto.DecryptString(credential[name].(string), newKey)
		if err != nil || string(text) != plain[name] {
			t.Fatalf("field %s not rekeyed", name)
		}
		clear(text)
		if _, err := vaultcrypto.DecryptString(credential[name].(string), oldKey); err == nil {
			t.Fatalf("old key opens %s", name)
		}
	}
	if !bytes.Equal(before, source.JSON) {
		t.Fatal("source mutated")
	}
	if err = transformCompleteCipher(copyObject, newKey, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(copyObject["login"].(map[string]any)["fido2Credentials"].([]any)[0], plain) {
		t.Fatal("credential changed")
	}
	// Ordinary same-key editing still treats FIDO2 as opaque.
	fields, err := DecryptCipherDocument(source, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "edited"
	updated, err := EncryptCipherDocument(source, fields, ownerKey, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	updatedObject, _ := documentObject(updated)
	if !reflect.DeepEqual(updatedObject["login"].(map[string]any)["fido2Credentials"], object["login"].(map[string]any)["fido2Credentials"]) {
		t.Fatal("ordinary edit rewrote passkey")
	}

	s, vault, ids := backupFixture(t, MyGoBackup, 1)
	defer s.Close()
	syncObject, _ := documentObject(CipherDocument{JSON: vault.Sync})
	item := syncObject["ciphers"].([]any)[0].(map[string]any)
	key, _ := cipherItemKey(item, s.key)
	_, encrypted = migrationFIDOFixture(t, key)
	clear(key)
	item["login"].(map[string]any)["fido2Credentials"] = []any{encrypted}
	vault.Sync, _ = json.Marshal(syncObject)
	installFixtureSnapshot(t, s, vault, "fido-backup")
	data, err := s.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	file, err := decodeBackup(data, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(file.Items[0]["login"].(map[string]any)["fido2Credentials"].([]any)[0], plain) {
		t.Fatal("backup lost credential")
	}
	imported, err := encryptImportedItem(file.Items[0], s.key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	importedObject, _ := documentObject(imported)
	key, _ = cipherItemKey(importedObject, s.key)
	defer clear(key)
	if err = transformCompleteCipher(importedObject, key, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(importedObject["login"].(map[string]any)["fido2Credentials"].([]any)[0], plain) {
		t.Fatal("import lost credential")
	}
}

func TestMigrationLegacyShareKeyedAttachment(t *testing.T) {
	source, ownerKey := copyFixture(t, 1)
	object, _ := documentObject(source)
	delete(object, "key") // fixture is legacy and encrypted under ownerKey
	newKey := bytes.Repeat([]byte{29}, 64)
	attachmentKey := bytes.Repeat([]byte{71}, 64)
	wrapped, _ := vaultcrypto.EncryptString(attachmentKey, ownerKey)
	filename, _ := vaultcrypto.EncryptString([]byte("附件.txt"), ownerKey)
	object["attachments"] = []any{map[string]any{"id": "file-1", "key": wrapped, "fileName": filename, "size": "42"}}
	plain, encrypted := migrationFIDOFixture(t, ownerKey)
	object["login"].(map[string]any)["fido2Credentials"] = []any{encrypted}
	if err := rekeyLegacyShare(object, ownerKey, newKey); err != nil {
		t.Fatal(err)
	}
	attachment := object["attachments"].([]any)[0].(map[string]any)
	key, err := vaultcrypto.DecryptString(attachment["key"].(string), newKey)
	if err != nil || !bytes.Equal(key, attachmentKey) {
		t.Fatal("attachment key changed")
	}
	clear(key)
	name, err := vaultcrypto.DecryptString(attachment["fileName"].(string), newKey)
	if err != nil || string(name) != "附件.txt" {
		t.Fatal("attachment name lost")
	}
	clear(name)
	if _, err = vaultcrypto.DecryptString(attachment["key"].(string), ownerKey); err == nil {
		t.Fatal("old owner key retained")
	}
	if err = transformCompleteCipher(object, newKey, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(object["login"].(map[string]any)["fido2Credentials"].([]any)[0], plain) {
		t.Fatal("legacy fido lost")
	}
}

func TestBackupPerItemAuthorizationAndPublication(t *testing.T) {
	s, vault, ids := backupFixture(t, MyGoBackup, 1, 2)
	defer s.Close()
	object, _ := documentObject(CipherDocument{JSON: vault.Sync})
	for _, raw := range object["ciphers"].([]any) {
		raw.(map[string]any)["reprompt"] = json.Number("1")
	}
	vault.Sync, _ = json.Marshal(object)
	installFixtureSnapshot(t, s, vault, "protected-backup")
	grants := map[string]*ItemAuthorization{}
	docs, _ := vault.Documents(vault.Scope)
	for _, doc := range docs {
		metadata, _ := documentObject(doc)
		id := metadata["id"].(string)
		grants[id] = &ItemAuthorization{session: s, scope: vault.Scope, revision: s.authorizationRevision, item: id, document: sha256.Sum256(doc.JSON), epoch: s.authorizationEpoch, expires: time.Now().Add(time.Minute)}
	}
	if data, err := s.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup); err == nil || data != nil {
		t.Fatal("unprotected bulk export")
	}
	data, err := s.ExportPersonalBackupAuthorized(context.Background(), vault, ids, MyGoBackup, grants)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	called := false
	publish := func() error { called = true; return nil }
	if err = s.PublishPersonalBackup(context.Background(), vault, ids, grants, publish); err != nil || !called {
		t.Fatal("valid publication rejected", err)
	}
	called = false
	grants[ids[1]] = grants[ids[0]]
	if data, err = s.ExportPersonalBackupAuthorized(context.Background(), vault, ids, MyGoBackup, grants); err == nil || data != nil {
		t.Fatal("grant crossed items")
	}
	if err = s.PublishPersonalBackup(context.Background(), vault, ids, grants, publish); err == nil || called {
		t.Fatal("cross-item publication")
	}
	grants[ids[0]].expires = time.Now().Add(-time.Second)
	if err = s.PublishPersonalBackup(context.Background(), vault, ids[:1], grants, publish); err == nil || called {
		t.Fatal("expired publication")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.PublishPersonalBackup(ctx, vault, ids, grants, publish); err != ErrCancelled || called {
		t.Fatal("cancel publication")
	}
}
