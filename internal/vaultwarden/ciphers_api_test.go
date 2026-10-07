// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCipherStateRouteMethodsAndScope(t *testing.T) {
	for _, tc := range []struct {
		action       CipherAction
		method, path string
	}{{CipherTrash, "PUT", "/delete"}, {CipherRestore, "PUT", "/restore"}, {CipherArchive, "PUT", "/archive"}, {CipherUnarchive, "PUT", "/unarchive"}, {CipherDeletePermanently, "DELETE", ""}} {
		t.Run(string(tc.action), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != tc.method || r.URL.Path != "/api/ciphers/item-1"+tc.path || r.Header.Get("Authorization") != "Bearer access-not-persisted" {
					t.Error("wrong authenticated mutation")
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			session, _ := resumableFixture(t, server.URL)
			defer session.Close()
			scope := Scope{Server: server.URL, Account: "account-a"}
			if err := session.ChangeCipherState(context.Background(), Scope{Server: server.URL, Account: "other"}, "item-1", tc.action, nil); err != ErrIdentity {
				t.Fatal("scope mismatch accepted")
			}
			if err := session.ChangeCipherState(context.Background(), scope, "item/1", tc.action, nil); err != ErrValidation {
				t.Fatal("path injection accepted")
			}
			if requests.Load() != 0 {
				t.Fatal("rejected mutation reached server")
			}
			if err := session.ChangeCipherState(context.Background(), scope, "item-1", tc.action, nil); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 {
				t.Fatal("mutation duplicated")
			}
		})
	}
}
func TestCipherPartialDoesNotOverwriteEncryptedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/ciphers/item-1/partial" {
			t.Fatal("wrong route")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Fatal("invalid JSON")
		}
		if len(body) != 2 || body["favorite"] != true || body["folderId"] != "folder-1" {
			t.Fatal("partial request changed other fields")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	folder := "folder-1"
	if err := session.SetCipherPersonalMetadata(context.Background(), Scope{Server: server.URL, Account: "account-a"}, "item-1", &folder, true, nil); err != nil {
		t.Fatal(err)
	}
}
func TestUpdateCipherEncryptedAndRevisionBound(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 3)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "Changed title"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/ciphers/item-1" {
			t.Fatal("wrong route")
		}
		var raw json.RawMessage
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			t.Fatal("invalid JSON")
		}
		document := CipherDocument{JSON: raw}
		object, _ := documentObject(document)
		if object["lastKnownRevisionDate"] != fields.RevisionDate || object["encryptedFor"] != "account-a" {
			t.Fatal("unbound update")
		}
		received, err := DecryptCipherDocument(document, key)
		if err != nil || received.Name != fields.Name {
			t.Fatal("invalid encrypted update")
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	clear(session.key)
	session.key = key
	defer session.Close()
	if _, err := session.UpdatePersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, doc, fields, nil); err != nil {
		t.Fatal(err)
	}
}
