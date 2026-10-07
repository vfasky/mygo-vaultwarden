// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPolicyPersonalStateUsesServerTypeAndPermissions(t *testing.T) {
	for _, action := range []CipherAction{CipherTrash, CipherRestore, CipherArchive, CipherUnarchive, CipherDeletePermanently, CipherMove} {
		for _, scenario := range []string{"ownership-allowed", "type-restricted", "forged-organization", "forged-reprompt", "forged-edit", "forged-view", "missing-record", "missing-type", "missing-permission", "duplicate-record"} {
			t.Run(string(action)+"/"+scenario, func(t *testing.T) {
				policyType, value := 5, any(nil)
				if scenario == "type-restricted" {
					policyType, value = 15, []int{3}
				}
				data := policySyncFixture(2, policyType, value)
				row := map[string]any{"id": "item-1", "type": 3, "organizationId": nil, "edit": true, "viewPassword": true, "reprompt": 0}
				data["ciphers"] = []any{row}
				switch scenario {
				case "forged-organization":
					row["organizationId"] = "org-a"
				case "forged-reprompt":
					row["reprompt"] = 1
				case "forged-edit":
					row["edit"] = false
				case "forged-view":
					row["viewPassword"] = false
				case "missing-record":
					data["ciphers"] = []any{}
				case "missing-type":
					delete(row, "type")
				case "missing-permission":
					delete(row, "edit")
				case "duplicate-record":
					data["ciphers"] = []any{row, row}
				}
				var reads, writes atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" && r.URL.Path == "/api/sync" {
						reads.Add(1)
						_ = json.NewEncoder(w).Encode(data)
						return
					}
					writes.Add(1)
					w.WriteHeader(204)
				}))
				defer server.Close()
				s, _ := resumableFixture(t, server.URL)
				defer s.Close()
				scope := Scope{Server: server.URL, Account: "account-a"}
				// Intentionally misleading caller metadata: server type is Card (3).
				doc := CipherDocument{JSON: []byte(`{"id":"item-1","type":1,"edit":true,"viewPassword":true,"reprompt":0}`)}
				calls := []func() error{
					func() error {
						return s.ChangePersonalCiphers(context.Background(), scope, bulkFixture(scope, true), []string{"item-1"}, action, nil, nil)
					},
				}
				if action != CipherMove {
					calls = append(calls, func() error {
						return s.ChangePersonalCipherStateAuthorized(context.Background(), scope, doc, action, nil, nil)
					})
				} else {
					calls = append(calls, func() error {
						return s.setCipherPersonalMetadataUnchecked(context.Background(), scope, "item-1", nil, true, nil)
					})
				}
				for _, call := range calls {
					before := writes.Load()
					err := call()
					if scenario == "ownership-allowed" {
						if err != nil || writes.Load() != before+1 {
							t.Fatalf("type5 banned allowed state action: %v", err)
						}
					} else {
						if err == nil || writes.Load() != before {
							t.Fatalf("forged caller bypass: %v writes=%d", err, writes.Load())
						}
						if scenario == "type-restricted" && !errors.Is(err, ErrPermission) {
							t.Fatal(err)
						}
					}
				}
				if reads.Load() != int32(len(calls)) {
					t.Fatal("operation reused stale policy", reads.Load())
				}
			})
		}
	}
}
