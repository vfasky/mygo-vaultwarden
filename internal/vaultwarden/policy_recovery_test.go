// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPendingPolicySharedScopeVectors(t *testing.T) {
	encoded, err := os.ReadFile("testdata/pending-policy-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name                               string
		Version                            int
		Pending                            []PendingPolicyMutation
		Valid, PersonalRead, PersonalWrite bool
	}
	if json.Unmarshal(encoded, &vectors) != nil {
		t.Fatal("invalid vectors")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			vault := &VaultData{Version: vector.Version, Scope: Scope{Server: "https://example.invalid", Account: "account"}, Sync: []byte(`{"profile":{"id":"account"},"ciphers":[]}`), PendingPolicyMutations: vector.Pending}
			_, err := vault.Documents(vault.Scope)
			if (err == nil) != vector.Valid {
				t.Fatal(err)
			}
			if err != nil {
				return
			}
			policies := &operationPolicies{restrictedPersonal: map[int]bool{}, restrictedOrganizations: map[string]map[int]bool{}}
			applyPendingPolicies(policies, vector.Pending)
			if (!policies.restrictedPersonal[1]) != vector.PersonalRead || (!policies.personalOwnership && !policies.restrictedPersonal[1]) != vector.PersonalWrite {
				t.Fatal("scope mismatch")
			}
		})
	}
}

func TestPolicyRecoveryBindsPreviewRevisionMutationAndFreshCandidate(t *testing.T) {
	for _, mode := range []string{"success", "stale-revision", "wrong-id", "changed-policy", "revoked-member", "ordinary-sync", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var serverSync []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/sync" {
					t.Error(r.URL.Path)
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write(serverSync)
			}))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = acceptedGroupsVault(t, s, ownerVault(t, v))
			serverSync = append([]byte(nil), v.Sync...)
			record := PendingPolicyMutation{"org-1", 15, "mutation-1"}
			v.Version = 2
			v.PendingPolicyMutations = []PendingPolicyMutation{record}
			v.QuarantinedOrganizations = []string{"org-1"}
			if err := s.AcceptAuthenticatedSnapshot(v, "pending"); err != nil {
				t.Fatal(err)
			}
			initial, err := s.Sync(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			review, err := s.ReviewPendingPolicy(initial, record)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			preview := *initial.Vault
			preview.Version = 2
			preview.PendingPolicyMutations = []PendingPolicyMutation{record}
			preview.QuarantinedOrganizations = []string{"org-1"}
			if _, err = s.SyncForPolicyRecovery(context.Background(), &preview, review, nil); err == nil {
				t.Fatal("unbound review accepted")
			}
			if err = s.AcceptAuthenticatedSnapshot(&preview, "preview"); err != nil {
				t.Fatal(err)
			}
			if err = s.BindPolicyRecoveryReview(review, &preview, "preview"); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "stale-revision":
				if err = s.AcceptAuthenticatedSnapshot(&preview, "next"); err != nil {
					t.Fatal(err)
				}
			case "wrong-id":
				review.record.MutationID = "foreign"
			case "changed-policy", "revoked-member":
				var obj map[string]any
				_ = json.Unmarshal(serverSync, &obj)
				if mode == "changed-policy" {
					row := map[string]any{"id": "policy-1", "organizationId": "org-1", "type": 15, "enabled": true, "data": []int{1}}
					obj["policies"] = []any{row}
					obj["policiesNew"] = []any{row}
				} else {
					profile := obj["profile"].(map[string]any)
					newer := profile["organizationsNew"].([]any)
					newer[0].(map[string]any)["status"] = -1
					profile["organizations"] = []any{}
					obj["policies"] = []any{}
					obj["policiesNew"] = []any{}
				}
				serverSync, _ = json.Marshal(obj)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			var fresh SyncResult
			if mode == "ordinary-sync" {
				fresh, err = s.Sync(ctx)
			} else {
				fresh, err = s.SyncForPolicyRecovery(ctx, &preview, review, nil)
			}
			if mode == "stale-revision" || mode == "wrong-id" || mode == "cancel" {
				if err == nil {
					t.Fatal("invalid preview used")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			err = s.ValidatePolicyRecovery(fresh, review)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if s.ValidatePolicyRecovery(fresh, review) == nil {
					t.Fatal("replayed recovery")
				}
				return
			}
			if err == nil {
				t.Fatal("changed/stale evidence accepted")
			}
			if mode == "revoked-member" {
				if !errors.Is(err, ErrConflict) {
					t.Fatal(err)
				}
				// Re-review the now authoritative revoked state. Only the personal barrier
				// may be released; the organization must remain quarantined.
				current, e := s.ReviewPendingPolicy(fresh, record)
				if e != nil {
					t.Fatal(e)
				}
				defer current.Close()
				if current.CanRestoreOrganization() {
					t.Fatal("revoked org restored")
				}
				revoked := *fresh.Vault
				revoked.Version = 2
				revoked.PendingPolicyMutations = []PendingPolicyMutation{record}
				revoked.QuarantinedOrganizations = []string{"org-1"}
				if e = s.AcceptAuthenticatedSnapshot(&revoked, "revoked-preview"); e != nil {
					t.Fatal(e)
				}
				if e = s.BindPolicyRecoveryReview(current, &revoked, "revoked-preview"); e != nil {
					t.Fatal(e)
				}
				final, e := s.SyncForPolicyRecovery(ctx, &revoked, current, nil)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.ValidatePolicyRecovery(final, current); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
