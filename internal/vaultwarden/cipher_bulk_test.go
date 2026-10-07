// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bulkFixture(scope Scope, deleted bool) *VaultData {
	var date any
	if deleted {
		date = "2026-01-01T00:00:00Z"
	}
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account}, "ciphers": []any{map[string]any{"id": "item-1", "deletedDate": date}, map[string]any{"id": "item-2", "deletedDate": date}, map[string]any{"id": "org-item", "organizationId": "org"}, map[string]any{"id": "restricted", "edit": false}}})
	return &VaultData{Version: 1, Scope: scope, Sync: raw}
}
func TestBulkRoutesAndPartialFailure(t *testing.T) {
	for _, tc := range []struct {
		op           CipherAction
		method, path string
	}{{CipherMove, "PUT", "/move"}, {CipherTrash, "PUT", "/delete"}, {CipherRestore, "PUT", "/restore"}, {CipherArchive, "PUT", "/archive"}, {CipherUnarchive, "PUT", "/unarchive"}, {CipherDeletePermanently, "DELETE", ""}} {
		t.Run(string(tc.op), func(t *testing.T) {
			requests := 0
			server := newPersonalStatePolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != tc.method || r.URL.Path != "/api/ciphers"+tc.path {
					t.Error("wrong route")
				}
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("body")
				}
				var ids []string
				json.Unmarshal(body["ids"], &ids)
				if len(ids) != 2 || ids[0] != "item-1" || ids[1] != "item-2" {
					t.Error("wrong ids")
				}
				if tc.op == CipherMove && string(body["folderId"]) != "null" {
					t.Error("unfiled move")
				}
				w.WriteHeader(400) // server may already have mutated item-1
			}))
			defer server.Close()
			session, _ := resumableFixture(t, server.URL)
			defer session.Close()
			scope := Scope{Server: server.URL, Account: "account-a"}
			err := session.ChangePersonalCiphers(context.Background(), scope, bulkFixture(scope, true), []string{"item-1", "item-2"}, tc.op, nil, nil)
			var unknown *MutationUncertainError
			if !errors.As(err, &unknown) || requests != 1 {
				t.Fatal("partial error lost or retried", err)
			}
		})
	}
}
func TestBulkRejectsRepromptAndHiddenPasswordBeforeRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("restricted batch reached server") }))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	scope := Scope{Server: server.URL, Account: "account-a"}
	for _, field := range []string{"reprompt", "viewPassword"} {
		vault := bulkFixture(scope, true)
		var object map[string]any
		_ = json.Unmarshal(vault.Sync, &object)
		entry := object["ciphers"].([]any)[0].(map[string]any)
		if field == "reprompt" {
			entry[field] = 1
		} else {
			entry[field] = false
		}
		vault.Sync, _ = json.Marshal(object)
		for _, op := range []CipherAction{CipherMove, CipherTrash, CipherRestore, CipherArchive, CipherUnarchive, CipherDeletePermanently} {
			if err := session.ChangePersonalCiphers(context.Background(), scope, vault, []string{"item-1", "item-2"}, op, nil, nil); err != ErrPermission {
				t.Fatal("restricted batch accepted", field, op, err)
			}
		}
	}
}

func TestBulkRejectsActivePermanentDeleteAndUnauthorizedIDs(t *testing.T) {
	session, _ := resumableFixture(t, "https://example.invalid")
	defer session.Close()
	scope := Scope{Server: "https://example.invalid", Account: "account-a"}
	vault := bulkFixture(scope, false)
	for _, tc := range []struct {
		ids  []string
		op   CipherAction
		want error
	}{
		{[]string{"item-1"}, CipherDeletePermanently, ErrPermission},
		{[]string{"org-item"}, CipherTrash, ErrPermission},
		{[]string{"restricted"}, CipherTrash, ErrPermission},
		{[]string{"missing"}, CipherTrash, ErrPermission},
		{[]string{"item-1", "item-1"}, CipherTrash, ErrValidation},
		{[]string{"../purge"}, CipherTrash, ErrValidation},
	} {
		if err := session.ChangePersonalCiphers(context.Background(), scope, vault, tc.ids, tc.op, nil, nil); err != tc.want {
			t.Fatal(err)
		}
	}
}
