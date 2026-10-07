// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPolicyImportPreflightsAllTypesAndReusesOneAuthority(t *testing.T) {
	source, vault, ids := backupFixture(t, MyGoBackup, 1, 3)
	defer source.Close()
	backup, err := source.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(backup)
	plan, err := ParseImport(backup, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			var reads, writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/api/sync" {
					reads.Add(1)
					if denied {
						_ = json.NewEncoder(w).Encode(policySyncFixture(0, 15, []int{3}))
					} else {
						_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
					}
					return
				}
				n := writes.Add(1)
				if r.Method == "PUT" {
					w.WriteHeader(204)
					return
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid request")
					w.WriteHeader(400)
					return
				}
				body["id"] = fmt.Sprintf("created-%d", n)
				body["revisionDate"] = "2026-01-01T00:00:00Z"
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			result, err := s.ImportPersonalBackup(context.Background(), Scope{Server: server.URL, Account: "account-a"}, plan, nil)
			if denied {
				if !errors.Is(err, ErrPermission) || writes.Load() != 0 || len(result.Entries) != 0 {
					t.Fatal("restricted later item caused partial import", err, writes.Load(), result)
				}
			} else if err != nil || writes.Load() != 6 || len(result.Entries) != 4 {
				t.Fatal("import failed", err, writes.Load(), result)
			}
			if reads.Load() != 1 || s.writePolicies != nil {
				t.Fatal("authority was not operation-scoped", reads.Load())
			}
		})
	}
}

func TestPolicyUpdateRejectsOwnershipButPreservesExistingRead(t *testing.T) {
	document, key := cipherDocumentFixture(t, 2)
	fields, err := DecryptCipherDocument(document, key)
	if err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/sync" {
			_ = json.NewEncoder(w).Encode(policySyncFixture(2, 5, nil))
			return
		}
		writes.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = key
	scope := Scope{Server: server.URL, Account: "account-a"}
	data := policySyncFixture(2, 5, nil)
	data["ciphers"] = []json.RawMessage{document.JSON}
	encoded, _ := json.Marshal(data)
	vault := &VaultData{Version: 1, Scope: scope, Sync: encoded, QuarantinedOrganizations: []string{"org-a"}}
	// Local quarantine is not a policy exemption. This authenticated snapshot
	// remains valid for reading personal records under PersonalOwnership.
	if _, _, err := s.ReadPersonalCipher(vault, fields.ID); err != nil {
		t.Fatal("ownership blocked existing personal read", err)
	}
	if _, err := s.UpdatePersonalCipher(context.Background(), scope, document, fields, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("ownership bypass", err)
	}
	if writes.Load() != 0 {
		t.Fatal("denied update reached server")
	}
}
