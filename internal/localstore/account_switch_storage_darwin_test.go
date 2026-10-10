// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package localstore

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestNativeBoundAccountSwitchConfirmedAndUnknownReceipts(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "lost-reply"}[unknown], func(t *testing.T) {
			call := recoveryNativeCall(t)
			oldScope := vaultwarden.Scope{Server: "https://old.example.invalid", Account: "old"}
			target := vaultwarden.Scope{Server: "https://new.example.invalid", Account: "new"}
			old := targetFixture(oldScope)
			fresh := targetFixture(target)
			fresh.PasswordUnlock.Key = bytes.Repeat([]byte{62}, 32)
			initial := call(Request{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &oldScope, PasswordUnlock: old.PasswordUnlock, Session: old.Session, Vault: old.Vault})
			if !initial.OK {
				t.Fatal(initial.Code)
			}
			binding, err := NewAccountSwitchBinding(initial.State, target)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			transport := func(r Request) Reply {
				reply := call(r)
				if r.Operation == "publishBoundAccount" {
					writes++
					if unknown && reply.OK {
						return Reply{Code: "lost_reply", Message: "fixture dropped committed reply"}
					}
				}
				return reply
			}
			reply, err := PublishBoundAccount(context.Background(), initial.State, fresh, binding, transport)
			defer clear(reply.Session)
			if unknown {
				if err == nil {
					t.Fatal("unknown adopted")
				}
				state := call(Request{Operation: "status"}).State
				if state == nil || !state.AccountSwitchPending || *state.Scope != target {
					t.Fatal("committed uncertainty lost")
				}
				query := call(Request{Operation: "inspectAccountSwitch", ExpectedRevision: state.Revision, SwitchOperationID: binding.OperationID})
				if !query.OK || query.AccountSwitch == nil || query.AccountSwitch.Binding != binding {
					t.Fatal("same-operation inspection", query.Code)
				}
				reply = call(Request{Operation: "confirmAccountSwitch", ExpectedRevision: query.State.Revision, SwitchOperationID: binding.OperationID, UnlockKey: fresh.PasswordUnlock.Key})
				defer clear(reply.Session)
			} else if err != nil {
				t.Fatal(err)
			}
			if writes != 1 || !reply.OK || reply.State == nil || reply.State.AccountSwitchPending || reply.State.CleanupPending || reply.AccountSwitch == nil || reply.AccountSwitch.Phase != "confirmed" || *reply.State.Scope != target || reply.Vault == nil {
				t.Fatal("invalid final switch receipt", reply.Code)
			}
			denied := call(Request{Operation: "listPassword", ExpectedRevision: reply.State.Revision, Scope: &oldScope, UnlockKey: old.PasswordUnlock.Key})
			if denied.OK {
				t.Fatal("old account key retained ordinary authority")
			}
			accepted := call(Request{Operation: "listPassword", ExpectedRevision: reply.State.Revision, Scope: &target, UnlockKey: fresh.PasswordUnlock.Key})
			defer clear(accepted.Session)
			if !accepted.OK {
				t.Fatal(accepted.Code)
			}
			disk, err := os.ReadFile(os.Getenv("SNAPSHOT_TEST_DIRECTORY") + "/snapshot-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(disk, []byte(binding.OperationID)) || bytes.Contains(disk, old.Session) {
				t.Fatal("switch recovery material plaintext")
			}
		})
	}
}
