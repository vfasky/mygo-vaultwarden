// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func backupFixture(t *testing.T, format BackupFormat, kinds ...int) (*Session, *VaultData, []string) {
	t.Helper()
	scope := Scope{Server: "https://vault.example.invalid", Account: "account-a"}
	var docs []json.RawMessage
	var key []byte
	ids := []string{}
	for _, kind := range kinds {
		doc, k := copyFixture(t, kind)
		key = k
		object, _ := documentObject(doc)
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", kind)
		ids = append(ids, id)
		object["id"] = id
		object["folderId"] = "00000000-0000-4000-8000-000000000001"
		if format == BitwardenJSON {
			delete(object, "deletedDate")
			if kind == 1 {
				login := object["login"].(map[string]any)
				login["uris"].([]any)[0].(map[string]any)["uriChecksum"] = nil
			}
		}
		data, _ := json.Marshal(object)
		docs = append(docs, data)
	}
	s, _ := resumableFixture(t, scope.Server)
	s.key = key
	folderName, _ := EncryptString([]byte("备份文件夹"), key)
	emptyName, _ := EncryptString([]byte("空文件夹"), key)
	sync, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account}, "ciphers": docs, "folders": []Folder{{"00000000-0000-4000-8000-000000000001", folderName}, {"00000000-0000-4000-8000-000000000002", emptyName}}})
	v := &VaultData{Version: 1, Scope: scope, Sync: sync}
	installFixtureSnapshot(t, s, v, "backup-revision")
	return s, v, ids
}
func TestBackupEightTypesRoundTrip(t *testing.T) {
	s, v, ids := backupFixture(t, MyGoBackup, 1, 2, 3, 4, 5, 6, 7, 8)
	defer s.Close()
	data, err := s.ExportPersonalBackup(context.Background(), v, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	plan, err := ParseImport(data, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	if plan.Items != 8 || plan.Folders != 2 || plan.Deleted != 8 || plan.Archived != 8 {
		t.Fatalf("bad preview %+v", plan)
	}
	file, _ := decodeBackup(data, MyGoBackup)
	for _, original := range file.Items {
		encrypted, err := encryptImportedItem(original, s.key, "new-account")
		if err != nil {
			t.Fatal(err)
		}
		object, _ := documentObject(encrypted)
		key, err := cipherItemKey(object, s.key)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(key, s.key) {
			t.Fatal("reused user key")
		}
		if err = transformCipher(object, key, false); err != nil {
			t.Fatal(err)
		}
		clear(key)
		if object["encryptedFor"] != "new-account" {
			t.Fatal("wrong owner")
		}
		delete(object, "encryptedFor")
		delete(object, "key")
		expected := map[string]any{}
		for k, v := range original {
			expected[k] = v
		}
		for _, k := range []string{"id", "creationDate", "revisionDate", "deletedDate", "collectionIds"} {
			delete(expected, k)
		}
		if !reflect.DeepEqual(object, expected) {
			t.Fatalf("type %v lost fields", original["type"])
		}
	}
	if _, err = ParseImport(data, BitwardenJSON); err == nil {
		t.Fatal("proprietary accepted as official")
	}
}
func TestBackupOfficialSelectionAndUnsupported(t *testing.T) {
	s, v, ids := backupFixture(t, BitwardenJSON, 1, 2, 3, 4, 5, 6, 7, 8)
	defer s.Close()
	if data, err := s.ExportPersonalBackup(context.Background(), v, ids, BitwardenJSON); err == nil || data != nil {
		t.Fatal("Passport lost")
	}
	data, err := s.ExportPersonalBackup(context.Background(), v, ids[:7], BitwardenJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	plan, err := ParseImport(data, BitwardenJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	if plan.Items != 7 {
		t.Fatal("selection changed")
	}
	if bytes.Contains(data, []byte("encryptedFor")) || bytes.Contains(data, []byte("uriChecksum")) || bytes.Contains(data, []byte("\"key\"")) {
		t.Fatal("internal ciphertext metadata exported")
	}
	for _, scenario := range []string{"history", "extension", "attachment", "fido", "reprompt", "permission", "organization", "checksum", "alias", "settings"} {
		t.Run(scenario, func(t *testing.T) {
			session, vault, selected := backupFixture(t, BitwardenJSON, 1)
			defer session.Close()
			var sync map[string]any
			json.Unmarshal(vault.Sync, &sync)
			obj := sync["ciphers"].([]any)[0].(map[string]any)
			switch scenario {
			case "history":
				h := obj["passwordHistory"].([]any)[0]
				obj["passwordHistory"] = []any{h, h, h, h, h, h}
			case "extension":
				obj["future"] = nil
			case "attachment":
				obj["attachments"] = []any{map[string]any{"id": "a"}}
			case "fido":
				obj["login"].(map[string]any)["fido2Credentials"] = []any{map[string]any{"keyValue": "x"}}
			case "reprompt":
				obj["reprompt"] = 1
			case "permission":
				obj["viewPassword"] = false
			case "organization":
				obj["organizationId"] = "org"
			case "checksum":
				encoded, _ := EncryptString([]byte("not-derived"), session.key)
				obj["login"].(map[string]any)["uris"].([]any)[0].(map[string]any)["uriChecksum"] = encoded
			case "alias":
				encoded, _ := EncryptString([]byte("different"), session.key)
				obj["login"].(map[string]any)["uri"] = encoded
			case "settings":
				obj["login"].(map[string]any)["autofillOnPageLoad"] = false
			}
			vault.Sync, _ = json.Marshal(sync)
			if data, err := session.ExportPersonalBackup(context.Background(), vault, selected, BitwardenJSON); err == nil || data != nil {
				t.Fatal("lossy export")
			}
		})
	}
}
func TestImportPreflightRejectsBeforeAnyWrite(t *testing.T) {
	calls := 0
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	s, v, ids := backupFixture(t, MyGoBackup, 1)
	defer s.Close()
	data, err := s.ExportPersonalBackup(context.Background(), v, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	remote, _ := resumableFixture(t, server.URL)
	defer remote.Close()
	remote.key = s.key
	scope := Scope{Server: server.URL, Account: "account-a"}
	for _, scenario := range []string{"version", "mixed", "unknown", "missing-folder", "malformed", "duplicate", "encrypted", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			var object map[string]any
			json.Unmarshal(data, &object)
			switch scenario {
			case "version":
				object["version"] = 2
			case "mixed":
				object["collections"] = []any{}
			case "unknown":
				object["items"].([]any)[0].(map[string]any)["future"] = nil
			case "missing-folder":
				object["folders"] = []any{}
			case "malformed":
				object["items"].([]any)[0].(map[string]any)["name"] = false
			case "encrypted":
				object["encrypted"] = true
			}
			raw, _ := json.Marshal(object)
			if scenario == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"encrypted":false`), []byte(`"encrypted":true,"encrypted":false`), 1)
			}
			if scenario == "trailing" {
				raw = append(raw, []byte(`{}`)...)
			}
			if _, err := ParseImport(raw, MyGoBackup); err == nil {
				t.Fatal("invalid preview")
			}
			if _, err := remote.ImportPersonalBackup(context.Background(), scope, &ImportPlan{data: raw, Format: MyGoBackup}, nil); err == nil {
				t.Fatal("invalid import")
			}
		})
	}
	if calls != 0 {
		t.Fatal("preflight wrote to server")
	}
}
func TestImportFolderMappingAndPartialUnknown(t *testing.T) {
	source, v, ids := backupFixture(t, MyGoBackup, 1, 8)
	defer source.Close()
	data, err := source.ExportPersonalBackup(context.Background(), v, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParseImport(data, MyGoBackup)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	calls := []string{}
	created := 0
	var first CipherDocument
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/api/folders" {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			body["id"] = fmt.Sprintf("new-folder-%d", len(calls))
			json.NewEncoder(w).Encode(body)
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(204)
			return
		}
		created++
		if created == 2 {
			w.WriteHeader(500)
			return
		}
		first.JSON, _ = io.ReadAll(r.Body)
		object, _ := documentObject(first)
		if object["folderId"] != "new-folder-1" || object["encryptedFor"] != "account-a" {
			t.Error("bad mapping")
		}
		object["id"] = "new-item"
		json.NewEncoder(w).Encode(object)
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = source.key
	scope := Scope{Server: server.URL, Account: "account-a"}
	s.checkpointPending = true
	if _, err = s.ImportPersonalBackup(context.Background(), scope, plan, nil); !errors.Is(err, ErrCheckpoint) {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatal("checkpoint bypass")
	}
	s.checkpointPending = false
	result, err := s.ImportPersonalBackup(context.Background(), scope, plan, nil)
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) {
		t.Fatal(err)
	}
	if len(calls) != 5 || created != 2 || len(result.Entries) != 4 || result.Entries[2].ID != "new-item" || result.Entries[3].ID != "" {
		t.Fatalf("partial result %+v calls %v", result, calls)
	}
	if calls[3] != "PUT /api/ciphers/new-item/delete" {
		t.Fatal("not soft delete", calls)
	}
	got, err := DecryptCipherDocument(first, s.key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PasswordHistory) != 1 || got.ArchivedDate == nil {
		t.Fatal("history/archive dropped")
	}
}
