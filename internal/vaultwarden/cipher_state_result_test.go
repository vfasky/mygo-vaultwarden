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

func TestCipherStateResultRecordsMutationBoundary(t *testing.T) {
	for _, scenario := range []string{"permission", "policy", "cancel-before-dispatch", "acknowledged", "disconnected", "rejected"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			data := policySyncFixture(2, 5, nil)
			row := map[string]any{"id": "item-1", "type": 3, "organizationId": nil, "edit": true, "viewPassword": true, "reprompt": 0}
			data["ciphers"] = []any{row}
			if scenario == "policy" {
				row["edit"] = false
			}
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/api/sync" {
					if scenario == "cancel-before-dispatch" {
						cancel()
					}
					json.NewEncoder(w).Encode(data)
					return
				}
				writes.Add(1)
				if scenario == "disconnected" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				if scenario == "rejected" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			doc := CipherDocument{JSON: []byte(`{"id":"item-1","edit":true,"viewPassword":true,"reprompt":0}`)}
			if scenario == "permission" {
				doc.JSON = []byte(`{"id":"item-1","edit":false,"viewPassword":true}`)
			}
			result, err := s.ChangePersonalCipherStateAuthorizedResult(ctx, Scope{Server: server.URL, Account: "account-a"}, doc, CipherTrash, nil, nil)
			dispatched := scenario == "acknowledged" || scenario == "disconnected" || scenario == "rejected"
			if result.Dispatched != dispatched || writes.Load() != boolWriteCount(dispatched) {
				t.Fatalf("incorrect dispatch evidence: %+v writes=%d err=%v", result, writes.Load(), err)
			}
			if (err == nil) != (scenario == "acknowledged") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
func boolWriteCount(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
