// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"testing"
)

// installFixtureSnapshot models an authenticated bridge receipt for an explicit
// test snapshot. Never use it for tamper/legacy negative cases.
func installFixtureSnapshot(t *testing.T, s *Session, v *VaultData, revision string) {
	t.Helper()
	var body map[string]any
	decoder := json.NewDecoder(bytes.NewReader(v.Sync))
	decoder.UseNumber()
	if decoder.Decode(&body) != nil {
		t.Fatal("fixture sync")
	}
	profile := body["profile"].(map[string]any)
	profile["email"], profile["key"] = s.email, s.wrapped
	if profile["organizations"] == nil {
		profile["organizations"] = []any{}
	}
	if profile["organizationsNew"] == nil {
		profile["organizationsNew"] = profile["organizations"]
	}
	for _, org := range profile["organizations"].([]any) {
		o := org.(map[string]any)
		if o["usePolicies"] == nil {
			o["usePolicies"] = true
		}
		if o["permissions"] == nil {
			o["permissions"] = map[string]any{"managePolicies": false}
		}
	}
	// Fixture mutations of membership must model both fixed-server arrays.
	profile["organizationsNew"] = profile["organizations"]
	if body["policies"] == nil {
		body["policies"] = []any{}
	}
	if body["policiesNew"] == nil {
		body["policiesNew"] = body["policies"]
	}
	v.Sync, _ = json.Marshal(body)
	if err := s.AcceptAuthenticatedSnapshot(v, revision); err != nil {
		t.Fatal("fixture receipt:", err)
	}
}
