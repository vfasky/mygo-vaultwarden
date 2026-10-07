// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPolicyComparisonIgnoresJSONFormattingButPreservesLargeIntegers(t *testing.T) {
	kind, enabled := 1, false
	a := []policyRecord{{OrganizationID: "org-1", Type: &kind, Enabled: &enabled, Data: json.RawMessage(`{ "opaque": 9007199254740993, "minimum": null }`)}}
	b := []policyRecord{{OrganizationID: "org-1", Type: &kind, Enabled: &enabled, Data: json.RawMessage(`{"minimum":null,"opaque":9007199254740993}`)}}
	if !equalPolicyRecords(a, b) {
		t.Fatal("formatting caused conflict")
	}
	b[0].Data = json.RawMessage(`{"minimum":null,"opaque":9007199254740992}`)
	if equalPolicyRecords(a, b) {
		t.Fatal("rounded unknown integer")
	}
}

func TestPolicyManagementProtocolConfirmationAndFailure(t *testing.T) {
	for _, mode := range []string{"success", "changed", "checkpoint", "unknown", "consent", "expired", "member", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			writes, isolations, reads := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/api/organizations/org-1")
				if path == "/users" {
					writeMembers(w, memberRows())
					return
				}
				raw := `{"id":"policy-1","organizationId":"org-1","type":1,"enabled":false,"data":{"minLength":14,"opaque":9007199254740993,"nullable":null}}`
				if mode == "changed" && reads > 1 {
					raw = strings.Replace(raw, `"minLength":14`, `"minLength":16`, 1)
				}
				if r.Method == "GET" {
					reads++
					if path == "/policies" {
						_, _ = w.Write([]byte(`{"data":[` + raw + `],"continuationToken":null}`))
					} else {
						_, _ = w.Write([]byte(raw))
					}
					return
				}
				writes++
				if isolations != 1 {
					t.Error("write before checkpoint")
				}
				if mode == "unknown" {
					w.WriteHeader(503)
					return
				}
				var body struct {
					Policy struct {
						Enabled bool
						Data    map[string]json.RawMessage
					}
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil || !body.Policy.Enabled || string(body.Policy.Data["opaque"]) != "9007199254740993" || string(body.Policy.Data["nullable"]) != "null" || string(body.Policy.Data["minLength"]) != "18" {
					t.Error("lost policy data")
				}
				raw = strings.Replace(raw, `"enabled":false`, `"enabled":true`, 1)
				raw = strings.Replace(raw, `"minLength":14`, `"minLength":18`, 1)
				_, _ = w.Write([]byte(raw))
			}))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = acceptedGroupsVault(t, s, ownerVault(t, v))
			d, err := s.OrganizationPolicy(context.Background(), v, "org-1", 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.Enabled = true
			for i := range d.Fields {
				if d.Fields[i].Key == "minLength" {
					d.Fields[i].Value = "18"
				}
			}
			consent := d.Confirm()
			defer consent.Close()
			if mode == "consent" {
				d.Enabled = false
			}
			if mode == "expired" {
				s.BindSnapshotRevision(v.Scope, "other")
			}
			if mode == "member" {
				s.Close()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			isolate := func(SessionCheckpoint) error {
				isolations++
				if mode == "checkpoint" {
					return errors.New("disk")
				}
				return nil
			}
			err = s.SaveOrganizationPolicy(ctx, v, d, consent, isolate, nil)
			if mode == "success" {
				if err != nil || writes != 1 || len(s.pendingPolicyMutations) != 1 {
					t.Fatal(err, writes)
				}
				if err = s.SaveOrganizationPolicy(ctx, v, d, consent, isolate, nil); err != ErrValidation {
					t.Fatal("replayed consent", err)
				}
			} else if mode == "unknown" {
				var uncertain *MutationUncertainError
				if !errors.As(err, &uncertain) || writes != 1 {
					t.Fatal(err, writes)
				}
			} else if err == nil || writes != 0 {
				t.Fatal("unsafe mutation", err, writes)
			}
		})
	}
}
func TestAllPolicyTypesRoundTripAndRoles(t *testing.T) {
	for _, def := range OrganizationPolicyDefinitions() {
		t.Run(strconv.Itoa(def.Type), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw := map[string]any{"id": "policy-1", "organizationId": "org-1", "type": def.Type, "enabled": false, "data": nil}
				if strings.HasSuffix(r.URL.Path, "/policies") {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{raw}})
				} else {
					_ = json.NewEncoder(w).Encode(raw)
				}
			}))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			if _, err := s.OrganizationPolicies(context.Background(), v, "org-1", nil); err == nil {
				t.Fatal("non administrator allowed")
			}
			v = acceptedGroupsVault(t, s, ownerVault(t, v))
			rows, err := s.OrganizationPolicies(context.Background(), v, "org-1", nil)
			if err != nil || len(rows) != 12 {
				t.Fatal(err, len(rows))
			}
			d, err := s.OrganizationPolicy(context.Background(), v, "org-1", def.Type, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			body, err := d.body()
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(body)
			if string(encoded) != `{"policy":{"data":null,"enabled":false}}` {
				t.Fatal(string(encoded))
			}
			if d.Confirm() == nil {
				t.Fatal("cannot confirm unchanged default")
			}
		})
	}
}
func TestPendingPolicySnapshotReadWriteIsolation(t *testing.T) {
	s, v, _, _ := organizationFixture(t, "http://127.0.0.1:9999")
	defer s.Close()
	v = acceptedGroupsVault(t, s, ownerVault(t, v))
	record := PendingPolicyMutation{"org-1", 15, "mutation-1"}
	v.PendingPolicyMutations = []PendingPolicyMutation{record}
	if err := s.AcceptAuthenticatedSnapshot(v, "pending-1"); err == nil {
		t.Fatal("v1 downgraded barrier")
	}
	v.Version = 2
	if err := s.AcceptAuthenticatedSnapshot(v, "pending-2"); err != nil {
		t.Fatal(err)
	}
	if !s.offlinePolicies.policies.restrictedPersonal[1] || !s.offlinePolicies.policies.restrictedPersonal[8] {
		t.Fatal("not blocked")
	}
	if s.offlinePolicies.policies.restrictedOrganizations["org-other"][1] {
		t.Fatal("other org blocked")
	}
	v.PendingPolicyMutations = nil
	if err := s.ValidateAuthenticatedSnapshot(v, "pending-2"); err == nil {
		t.Fatal("caller cleared barrier")
	}
	v.PendingPolicyMutations = []PendingPolicyMutation{record, record}
	if err := s.AcceptAuthenticatedSnapshot(v, "duplicate"); err == nil {
		t.Fatal("duplicate")
	}
	record.PolicyType = 5
	v.PendingPolicyMutations = []PendingPolicyMutation{record}
	if err := s.AcceptAuthenticatedSnapshot(v, "write-only"); err != nil {
		t.Fatal(err)
	}
	if !s.offlinePolicies.policies.personalOwnership || s.offlinePolicies.policies.restrictedPersonal[1] {
		t.Fatal("write-only policy blocked reads")
	}
}
