// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"testing"
)

func TestOrganizationDefaultURIProjectionAndCheckpoint(t *testing.T) {
	s, v, key, doc := organizationFixture(t, "https://example.invalid")
	defer s.Close()
	defer clear(key)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.Login["uris"] = []any{map[string]any{"uri": "https://login.example.invalid/path", "match": nil}, map[string]any{"uri": "https://explicit.example.invalid/", "match": 0}}
	doc, err = EncryptCipherDocument(doc, fields, key, s.account)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range []int{0, 1, 2, 3, 4, 5} {
		current := changeOrganizationFixture(t, v, func(d map[string]any) {
			d["ciphers"] = []json.RawMessage{doc.JSON}
			policies := []any{map[string]any{"id": "uri-policy", "organizationId": "org-1", "type": 16, "enabled": true, "data": map[string]any{"uriMatchDetection": match}}}
			d["policies"], d["policiesNew"] = policies, policies
		})
		if err := s.AcceptAuthenticatedSnapshot(current, "uri-revision"); err != nil {
			t.Fatal(err)
		}
		p, err := s.snapshotPoliciesLocked(current)
		if err != nil {
			t.Fatal(err)
		}
		result := SyncResult{Vault: current}
		if err := s.appendOrganizationCredentialsLocked(&result, p); err != nil {
			t.Fatal(err)
		}
		if len(result.Credentials) != 1 {
			t.Fatal("missing org credential")
		}
		rules := result.Credentials[0].URIs
		want := 1
		if match == 0 || match == 1 || match == 3 {
			want = 2
		}
		if len(rules) != want || rules[want-1].Match != 0 {
			t.Fatal("org default/explicit", match, rules)
		}
		if want == 2 && rules[0].Match != match {
			t.Fatal("org inheritance")
		}
		// A real same-content checkpoint receipt retains the parsed default; it must
		// not reset it to domain while moving the revision or revoke other policy.
		receipt := &checkpointPolicyReceipt{prior: s.offlinePolicies}
		cp := SessionCheckpoint{Scope: current.Scope, receipt: receipt}
		if err := cp.AcceptAuthenticatedReceipt(current, "uri-revision", "checkpoint"); err != nil {
			t.Fatal(err)
		}
		if receipt.revision != "checkpoint" || receipt.prior.policies.defaultURIMatch != match {
			t.Fatal("checkpoint lost default")
		}
	}
}
