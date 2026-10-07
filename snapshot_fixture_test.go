// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

// prepareUIReceipt supplies the complete policy fields of a fictional server
// receipt. Call explicitly after fixture edits, never in tamper-negative tests.
func prepareUIReceipt(t *testing.T, a *app, v *vaultwarden.VaultData) {
	t.Helper()
	var body map[string]any
	if json.Unmarshal(v.Sync, &body) != nil {
		t.Fatal("fixture sync")
	}
	profile := body["profile"].(map[string]any)
	profile["email"], profile["key"] = a.snapshot.PasswordUnlock.Email, "fixture-wrapped-key"
	if profile["organizations"] == nil {
		profile["organizations"] = []any{}
	}
	for _, raw := range profile["organizations"].([]any) {
		org := raw.(map[string]any)
		org["usePolicies"] = true
		org["permissions"] = map[string]any{"managePolicies": false}
	}
	profile["organizationsNew"] = profile["organizations"]
	if body["policies"] == nil {
		body["policies"] = []any{}
	}
	if body["policiesNew"] == nil {
		body["policiesNew"] = body["policies"]
	}
	v.Sync, _ = json.Marshal(body)
}
func acceptUIReceipt(t *testing.T, a *app, v *vaultwarden.VaultData) {
	t.Helper()
	prepareUIReceipt(t, a, v)
	if err := a.session.(*vaultwarden.Session).AcceptAuthenticatedSnapshot(v, a.sessionRevision); err != nil {
		t.Fatal("fixture receipt", err)
	}
}
