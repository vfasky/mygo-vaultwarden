// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOrgBackupOfficialRoutesRoundtripAndNoFalseImportSuccess(t *testing.T) {
	var doc CipherDocument
	var encryptedCollection string
	var calls atomic.Int32
	var targetKey []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/api/sync":
			data := organizationPolicySyncFixture()
			data["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)["type"] = 0
			data["ciphers"] = []json.RawMessage{doc.JSON}
			_ = json.NewEncoder(w).Encode(data)
		case "/api/organizations/org-1/export":
			if r.Method != "GET" {
				t.Error("export must GET")
			}
			object, _ := documentObject(doc)
			for _, name := range []string{"edit", "viewPassword", "favorite", "folderId", "archivedDate", "permissions"} {
				delete(object, name)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"collections": []any{map[string]any{"id": "collection-1", "organizationId": "org-1", "name": encryptedCollection, "externalId": "external-1", "type": 0, "defaultUserCollectionEmail": nil, "object": "collection"}}, "ciphers": []any{object}})
		case "/api/ciphers/import-organization":
			if r.Method != "POST" || r.URL.Query().Get("organizationId") != "org-1" {
				t.Error("wrong import route")
			}
			var body struct {
				Ciphers                 []json.RawMessage
				Collections             []struct{ ID, Name string }
				CollectionRelationships []struct{ Key, Value int }
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Ciphers) != 1 || len(body.Collections) != 1 || len(body.CollectionRelationships) != 1 {
				t.Error("import body")
				return
			}
			fields, err := DecryptCipherDocument(CipherDocument{JSON: body.Ciphers[0]}, targetKey)
			if err != nil || fields.Name != "组织项目" || fields.Login["password"] != "secret" || fields.OrganizationID == nil || *fields.OrganizationID != "org-1" {
				t.Error("import crypto", err)
			}
			if body.Collections[0].ID != "collection-1" || body.CollectionRelationships[0].Key != 0 || body.CollectionRelationships[0].Value != 0 {
				t.Error("collection mapping")
			}
			// 200 can still hide per-cipher failures in the official implementation.
		default:
			t.Error("unexpected route", r.URL)
		}
	}))
	defer server.Close()
	s, v, key, source := organizationFixture(t, server.URL)
	defer s.Close()
	doc = source
	targetKey = key
	encryptedCollection, _ = EncryptString([]byte("共享集合"), key)
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = 0
		}
	})
	installFixtureSnapshot(t, s, v, "revision-1")
	var backup []byte
	if err := s.WithOrganizationBackup(context.Background(), v, "org-1", nil, false, func([]byte) error { return nil }, nil); err != ErrValidation || calls.Load() != 0 {
		t.Fatal("unconfirmed export", err)
	}
	var borrowed []byte
	err := s.WithOrganizationBackup(context.Background(), v, "org-1", nil, true, func(data []byte) error { borrowed = data; backup = append([]byte(nil), data...); return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("borrowed plaintext retained")
		}
	}
	plan, err := ParseOrganizationImport(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	defer clear(backup)
	if len(plan.PreviewItems()) != 1 || plan.Collections()[0].Name != "共享集合" {
		t.Fatal("preview lost")
	}
	collections := plan.Collections()
	*collections[0].ExternalID = "changed"
	if *plan.Collections()[0].ExternalID != "external-1" {
		t.Fatal("preview mutated plan")
	}
	result, err := s.ImportOrganizationBackup(context.Background(), v, "org-1", plan, map[string]string{"collection-1": "collection-1"}, true, nil)
	if err != nil || result.Applied || !result.ReconcileRequired {
		t.Fatal("200 incorrectly treated as item success", result, err)
	}
	if result.ImportReconciliation == nil || !result.ImportReconciliation.ReadCompleted || len(result.ImportReconciliation.AddedIDs) != 0 || len(result.ImportReconciliation.Items) != 1 || result.ImportReconciliation.Items[0].Verified {
		t.Fatal("missing fresh read / false per-item success", result.ImportReconciliation)
	}
}

func TestOrgBackupRejectsOpaquePlaintext(t *testing.T) {
	source, key := copyFixture(t, 1)
	object, _ := documentObject(source)
	itemKey, _ := cipherItemKey(object, key)
	if err := transformCipher(object, itemKey, false); err != nil {
		t.Fatal(err)
	}
	clear(itemKey)
	for _, name := range []string{"object", "key", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedFor", "encryptedByKeyId", "lastKnownRevisionDate", "attachments"} {
		delete(object, name)
	}
	object["organizationId"] = "org-1"
	object["collectionIds"] = []string{}
	object["opaque"] = json.Number("9007199254740993")
	raw, _ := json.Marshal(organizationBackup{Format: organizationBackupFormat, Version: 1, OrganizationID: "org-1", Collections: []OrganizationBackupCollection{}, Items: []map[string]any{object}})
	if _, err := ParseOrganizationImport(raw); err != ErrUnsupportedEdit {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("9007199254740993")) {
		t.Fatal("large field changed")
	}
}
