// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestAuthManagementUnknownRequiresRead(t *testing.T) {
	calls := 0
	var request authManagementRequest
	scope := vaultwarden.Scope{Server: "https://vault.example", Account: "account"}
	f := newAuthManagementForm(scope, 3, func(r authManagementRequest) { calls++; request = r })
	f.operation = "disable"
	f.password = "password"
	f.values["type"] = "0"
	f.dispatch()
	if calls != 0 || !f.confirming {
		t.Fatal("missing confirmation")
	}
	f.dispatch()
	request.Close()
	if calls != 1 || f.password != "" {
		t.Fatal("dispatch cleanup")
	}
	f.complete(scope, 3, f.sequence, "", context.Canceled)
	f.dispatch()
	if calls != 1 {
		t.Fatal("unknown mutation retried")
	}
	f.operation = vaultwarden.MFAList
	f.dispatch()
	request.Close()
	if calls != 2 {
		t.Fatal("read verification blocked")
	}
	f.Close()
}

func TestAuthRecoveryConfirmationAndLease(t *testing.T) {
	calls := 0
	var emitted authRequest
	f := newAuthForm(vaultwarden.Scope{Server: "https://vault.example", Account: "account"}, 10, func(r authRequest) { calls++; emitted = r })
	f.provider = 8
	f.token = "recovery-secret"
	f.dispatch()
	if calls != 0 || !f.confirming {
		t.Fatal("missing destructive confirmation")
	}
	f.dispatch()
	defer emitted.Close()
	if calls != 1 || !emitted.Response.ConfirmRemoveAllMFA || f.token != "" {
		t.Fatal("dispatch")
	}
	if f.complete(f.scope, 11, emitted.Sequence, nil) {
		t.Fatal("stale epoch")
	}
	f.Close()
	if emitted.Context.Err() != context.Canceled {
		t.Fatal("request not cancelled")
	}
	if f.complete(f.scope, 10, emitted.Sequence, nil) {
		t.Fatal("late result")
	}
}
