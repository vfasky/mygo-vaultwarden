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

func TestOrganizationCipherPolicyScopeAndIdentity(t *testing.T) {
	for _, operation := range []string{"create", "update", "share"} {
		for _, scenario := range []string{"allow", "ownership", "restricted", "other-org", "missing-member", "changed-member", "changed-role", "disabled", "accepted", "missing-policy"} {
			t.Run(operation+"/"+scenario, func(t *testing.T) {
				data := organizationPolicySyncFixture()
				profile := data["profile"].(map[string]any)
				member := profile["organizations"].([]any)[0].(map[string]any)
				switch scenario {
				case "ownership", "restricted", "other-org":
					kind, org := 15, "org-1"
					var value any = []int{1}
					if scenario == "ownership" {
						kind, value = 5, nil
					}
					if scenario == "other-org" {
						org = "org-other"
						profile["organizations"] = append(profile["organizations"].([]any), map[string]any{"id": org, "organizationUserId": "member-other", "userId": "account-a", "type": 2, "status": 2, "enabled": true, "usePolicies": true, "permissions": map[string]any{"managePolicies": false}})
					}
					policy := map[string]any{"id": "policy-1", "organizationId": org, "type": kind, "enabled": true, "data": value}
					data["policies"], data["policiesNew"] = []any{policy}, []any{policy}
				case "missing-member":
					profile["organizations"] = []any{}
				case "changed-member":
					member["organizationUserId"] = "member-new"
				case "changed-role":
					member["type"] = 4
				case "disabled":
					member["enabled"] = false
				case "accepted":
					member["status"] = 1
				case "missing-policy":
					delete(data, "policies")
				}
				var writes, reads atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && r.URL.Path == "/api/sync" {
						reads.Add(1)
						_ = json.NewEncoder(w).Encode(data)
						return
					}
					writes.Add(1)
					var body map[string]json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("write body")
					}
					if operation != "update" {
						_ = json.Unmarshal(body["cipher"], &body)
					}
					body["id"] = json.RawMessage(`"item-org"`)
					if operation == "share" {
						body["id"] = json.RawMessage(`"share-me"`)
					}
					_ = json.NewEncoder(w).Encode(body)
				}))
				defer server.Close()
				s, vault, _, _ := organizationFixture(t, server.URL)
				defer s.Close()
				var err error
				switch operation {
				case "create":
					_, err = s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", CipherFields{Type: 1, Name: "created", Login: map[string]any{"password": "secret"}}, nil)
				case "update":
					doc, fields, e := s.ReadOrganizationCipher(vault, "item-org", nil)
					if e != nil {
						t.Fatal(e)
					}
					fields.Name = "edited"
					_, err = s.UpdateOrganizationCipher(context.Background(), vault, doc, fields, nil, nil)
				case "share":
					doc, e := NewPersonalCipher(CipherFields{Type: 1, Name: "shared", Login: map[string]any{"password": "secret"}}, s.key, s.account)
					if e != nil {
						t.Fatal(e)
					}
					object, _ := documentObject(doc)
					object["id"], object["revisionDate"], object["edit"], object["viewPassword"] = "share-me", "2026-06-01T00:00:00Z", true, true
					doc.JSON, _ = json.Marshal(object)
					var raw map[string]json.RawMessage
					_ = json.Unmarshal(vault.Sync, &raw)
					raw["ciphers"], _ = json.Marshal([]json.RawMessage{doc.JSON})
					vault.Sync, _ = json.Marshal(raw)
					installFixtureSnapshot(t, s, vault, "revision-1")
					fields, e := DecryptCipherDocument(doc, s.key)
					if e != nil {
						t.Fatal(e)
					}
					_, err = s.SharePersonalCipher(context.Background(), vault, "org-1", "collection-1", doc, fields, nil, nil)
				}
				allowed := scenario == "allow" || scenario == "ownership" || scenario == "other-org"
				if reads.Load() != 1 {
					t.Fatalf("policy reads %d, error %v", reads.Load(), err)
				}
				if allowed {
					if err != nil || writes.Load() != 1 {
						t.Fatalf("allowed write: %v, requests %d", err, writes.Load())
					}
				} else {
					if err == nil || writes.Load() != 0 {
						t.Fatalf("blocked write: %v, requests %d", err, writes.Load())
					}
					if scenario == "restricted" && !errors.Is(err, ErrPermission) {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
