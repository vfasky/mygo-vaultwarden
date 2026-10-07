// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestURIDefaultPolicySharedVectorsAndEncryptedProjection(t *testing.T) {
	raw, err := os.ReadFile("testdata/uri-default-policy-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name                                              string
		Roles                                             []int
		Values                                            []json.RawMessage
		Expected                                          int
		DisabledFirst, OrganizationDisabled, AcceptedOnly bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{8}, 64)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			data := emptyPolicySyncFixture()
			orgs, policies := []any{}, []any{}
			for i, role := range tc.Roles {
				status := 2
				if tc.AcceptedOnly {
					status = 1
				}
				id := fmt.Sprintf("org-%d", i)
				orgs = append(orgs, map[string]any{"id": id, "organizationUserId": fmt.Sprintf("member-%d", i), "userId": "account-a", "type": role, "status": status, "enabled": !tc.OrganizationDisabled, "usePolicies": true, "permissions": map[string]any{"managePolicies": false}})
				policies = append(policies, map[string]any{"id": fmt.Sprintf("policy-%d", i), "organizationId": id, "type": 16, "enabled": !(i == 0 && tc.DisabledFirst), "data": map[string]any{"uriMatchDetection": tc.Values[i]}})
			}
			data["profile"].(map[string]any)["organizations"] = orgs
			data["policies"], data["policiesNew"] = policies, policies
			if tc.AcceptedOnly {
				data["policies"] = []any{}
			}
			p, err := parsePolicyFixture(data)
			if err != nil || p.defaultURIMatch != tc.Expected {
				t.Fatalf("default got %+v error %v want %d", p, err, tc.Expected)
			}
			// Real cipher encryption covers both inherited null and explicit rules,
			// including skip behavior for prefix/regex/never without domain fallback.
			doc, err := NewPersonalCipher(CipherFields{Type: 1, Name: "fixture", Login: map[string]any{"username": "u", "password": "secret", "uris": []any{map[string]any{"uri": "https://login.example.invalid/path", "match": nil}, map[string]any{"uri": "https://explicit.example.invalid/path", "match": 0}}}}, key, "account-a")
			if err != nil {
				t.Fatal(err)
			}
			var cipher encryptedCipher
			if json.Unmarshal(doc.JSON, &cipher) != nil {
				t.Fatal("cipher")
			}
			cipher.ID = "cipher-1"
			result, err := decryptSyncWithPolicies(syncReply{Ciphers: []encryptedCipher{cipher}}, key, p)
			if err != nil || len(result.Credentials) != 1 {
				t.Fatal(err)
			}
			c := result.Credentials[0]
			supported := tc.Expected == 0 || tc.Expected == 1 || tc.Expected == 3
			want := 1
			if supported {
				want = 2
			}
			if len(c.URIs) != want || c.Password != "secret" {
				t.Fatal("projection", c.URIs)
			}
			explicit := c.URIs[len(c.URIs)-1]
			if explicit.Match != 0 || explicit.SourceIndex == nil || *explicit.SourceIndex != 1 {
				t.Fatal("explicit rule overwritten")
			}
			if supported && (c.URIs[0].Match != tc.Expected || c.URIs[0].SourceIndex == nil || *c.URIs[0].SourceIndex != 0) {
				t.Fatal("inherited rule")
			}
			pending := *p
			applyPendingPolicies(&pending, []PendingPolicyMutation{{OrganizationID: "org-0", PolicyType: 16, MutationID: "pending-uri"}})
			blocked, e := decryptSyncWithPolicies(syncReply{Ciphers: []encryptedCipher{cipher}}, key, &pending)
			if e != nil || len(blocked.Credentials) != 1 || len(blocked.Credentials[0].URIs) != 1 || *blocked.Credentials[0].URIs[0].SourceIndex != 1 {
				t.Fatal("pending URI mutation retained inherited fill or lost explicit rule", e)
			}
			encoded, err := json.Marshal(c)
			if err != nil || !bytes.Contains(encoded, []byte(`"sourceIndex":1`)) {
				t.Fatal("bridge provenance", err)
			}
		})
	}
}

func TestDefaultURIMatchRequiresAuthenticatedCurrentSnapshot(t *testing.T) {
	s, v, _, _ := organizationFixture(t, "https://example.invalid")
	defer s.Close()
	s.RevokeItemAuthorizations()
	if _, err := s.DefaultURIMatch(v); err == nil {
		t.Fatal("untrusted snapshot")
	}
	v = acceptedGroupsVault(t, s, ownerVault(t, v))
	if _, err := s.DefaultURIMatch(v); err != nil {
		t.Fatal(err)
	}
	s.RevokeItemAuthorizations()
	if _, err := s.DefaultURIMatch(v); err == nil {
		t.Fatal("revoked snapshot")
	}
}
