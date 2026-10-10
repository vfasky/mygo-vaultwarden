// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestAuthManagementUnknownRequiresRead(t *testing.T) {
	calls := 0
	var request AuthManagementRequest
	scope := vaultwarden.Scope{Server: "https://vault.example", Account: "account"}
	f := NewAuthManagementForm(scope, 3, func(r AuthManagementRequest) { calls++; request = r })
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
	f.Complete(scope, 3, f.sequence, "", context.Canceled)
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
	var emitted AuthRequest
	f := NewAuthForm(vaultwarden.Scope{Server: "https://vault.example", Account: "account"}, 10, func(r AuthRequest) { calls++; emitted = r })
	f.Provider = 8
	f.Token = "recovery-secret"
	f.Dispatch()
	if calls != 0 || !f.Confirming {
		t.Fatal("missing destructive confirmation")
	}
	f.Dispatch()
	defer emitted.Close()
	if calls != 1 || !emitted.Response.ConfirmRemoveAllMFA || f.Token != "" {
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
