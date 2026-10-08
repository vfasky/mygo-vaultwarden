// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func runtimeFixture(t *testing.T, reprompt bool) (*deviceLoginFixture, *DeviceLogin, DeviceLoginResult) {
	t.Helper()
	f, c, scope := newDeviceLoginFixture(t)
	doc, err := NewPersonalCipher(CipherFields{Type: 1, Name: "runtime item", Login: map[string]any{"username": "runtime-user", "password": "runtime-secret"}}, f.key, scope.Account)
	if err != nil {
		t.Fatal(err)
	}
	var item map[string]any
	json.Unmarshal(doc.JSON, &item)
	item["id"] = "runtime-item"
	item["revisionDate"] = "2026-01-01T00:00:00Z"
	item["edit"] = true
	item["viewPassword"] = true
	if reprompt {
		item["reprompt"] = 1
	}
	var body map[string]any
	json.Unmarshal(f.raw, &body)
	body["ciphers"] = []any{item}
	body["sends"] = []any{}
	f.raw, _ = json.Marshal(body)
	flow, err := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flow.Close)
	result, err := flow.Run(nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, flow, result
}
func TestRuntimeAuthorityRequiresActualSyncAndRevokes(t *testing.T) {
	_, flow, result := runtimeFixture(t, false)
	forged := *result.Sync.Vault
	forged.Sync = append([]byte(nil), forged.Sync...)
	forged.Sync = append(forged.Sync, ' ')
	if _, err := result.Session.AcceptRuntimeSnapshot(&forged); !errors.Is(err, ErrIdentity) {
		t.Fatal("forged result accepted", err)
	}
	authority, err := result.Session.AcceptRuntimeSnapshot(result.Sync.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Check(result.Sync.Vault); err != nil {
		t.Fatal(err)
	}
	if _, err = result.Session.AcceptRuntimeSnapshot(result.Sync.Vault); !errors.Is(err, ErrIdentity) {
		t.Fatal("receipt reused", err)
	}
	// Native callback may check the opaque lease without reentering Session.mu.
	called := false
	err = result.Session.WithPersonalSecret(result.Sync.Vault, authority.Revision(), "runtime-item", "password", nil, func(secret string, key []byte, deadline time.Time) error {
		called = true
		if secret != "runtime-secret" || len(key) != 0 || deadline.After(authority.Expires()) {
			t.Error("runtime secret used durable key or wrong expiry")
		}
		return authority.CheckLease()
	})
	if err != nil || !called {
		t.Fatal("runtime secret unavailable", err)
	}
	fresh, err := result.Session.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(authority.CheckLease(), ErrExpired) {
		t.Fatal("old runtime survived sync")
	}
	next, err := result.Session.AcceptRuntimeSnapshot(fresh.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision() == authority.Revision() {
		t.Fatal("reused revision")
	}
	flow.Close()
	if !errors.Is(next.CheckLease(), ErrExpired) {
		t.Fatal("flow close retained authority")
	}
}
func TestRuntimeAuthorityRepromptDoesNotBindPassword(t *testing.T) {
	_, _, result := runtimeFixture(t, true)
	authority, err := result.Session.AcceptRuntimeSnapshot(result.Sync.Vault)
	if err != nil {
		t.Fatal(err)
	}
	use := func(string, []byte, time.Time) error { return nil }
	if err = result.Session.WithPersonalSecret(result.Sync.Vault, authority.Revision(), "runtime-item", "password", nil, use); !errors.Is(err, ErrPermission) {
		t.Fatal("reprompt bypass", err)
	}
	if _, err = result.Session.AuthorizePersonalItem(context.Background(), result.Sync.Vault, authority.Revision(), "runtime-item", []byte("wrong-password")); err == nil {
		t.Fatal("wrong password accepted")
	}
	grant, err := result.Session.AuthorizePersonalItem(context.Background(), result.Sync.Vault, authority.Revision(), "runtime-item", []byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err = result.Session.WithPersonalSecret(result.Sync.Vault, authority.Revision(), "runtime-item", "password", grant, use); err != nil {
		t.Fatal(err)
	}
	if result.Session.passwordUnlock != nil {
		t.Fatal("reprompt silently bound persistent password")
	}
}
func TestRuntimeAuthorityExpiryCannotRefresh(t *testing.T) {
	f, _, result := runtimeFixture(t, false)
	result.Session.mu.Lock()
	result.Session.expires = time.Now().Add(-time.Second)
	result.Session.mu.Unlock()
	if _, err := result.Session.Sync(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatal("expired runtime continued", err)
	}
	f.mu.Lock()
	grants := f.grants
	f.mu.Unlock()
	if grants != 1 {
		t.Fatal("runtime attempted refresh", grants)
	}
}
func TestRuntimeAuthorityPreservesLocalProtection(t *testing.T) {
	_, _, result := runtimeFixture(t, false)
	local := &VaultData{Version: 2, Scope: result.Sync.Scope, PendingPolicyMutations: []PendingPolicyMutation{{OrganizationID: "11111111-1111-4111-8111-111111111111", MutationID: "22222222-2222-4222-8222-222222222222", PolicyType: 15}}}
	// DeviceLoginResult embeds scope in Sync, never trusts an email as identity.
	local.Scope = result.Sync.Scope
	authority, accepted, err := result.Session.AcceptRuntimeSnapshotWithProtection(result.Sync.Vault, local)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted.PreservesPendingPolicies(local) || !accepted.PreservesPendingPolicies(result.Sync.Vault) {
		t.Fatal("protection dropped")
	}
	if err = authority.Check(accepted); err != nil {
		t.Fatal(err)
	}
	if _, _, err = result.Session.ReadPersonalCipher(accepted, "runtime-item"); err == nil {
		t.Fatal("pending policy bypass")
	}
}
