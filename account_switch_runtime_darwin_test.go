// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func runtimeHarnessFrame(t *testing.T) func([]byte) ([]byte, error) {
	t.Helper()
	library := os.Getenv("SNAPSHOT_TEST_HARNESS")
	if library == "" {
		t.Skip("isolated Swift runtime harness required")
	}
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := purego.Dlsym(handle, "mygo_runtime_secret_execute")
	if err != nil {
		t.Fatal(err)
	}
	var call func([]byte, int, []byte, int) int32
	purego.RegisterFunc(&call, symbol)
	return func(input []byte) ([]byte, error) {
		out := make([]byte, 96*1024)
		defer clear(out)
		n := call(input, len(input), out, len(out))
		runtime.KeepAlive(input)
		runtime.KeepAlive(out)
		if n <= 0 || int(n) > len(out) {
			return nil, errRuntimeSecretUnavailable
		}
		return append([]byte(nil), out[:n]...), nil
	}
}
func TestNativeRuntimeBootstrapForeignTargetCannotBeMissed(t *testing.T) {
	frame := runtimeHarnessFrame(t)
	f := newRuntimeResourceControllerFixture(t)
	cap := f.a.runtimeVault.authority
	call := recoveryNativeCall(t)
	actor := vaultwarden.Scope{Server: cap.Scope().Server, Account: "foreign-actor"}
	initial := targetFixture(actor)
	published := call(storageRequest{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &actor, PasswordUnlock: initial.PasswordUnlock, Session: initial.Session, Vault: initial.Vault})
	if !published.OK {
		t.Fatal(published.Code)
	}
	var epoch atomic.Uint64
	epoch.Store(3)
	adapter, err := newTargetRecoveryStorage(published.State, 3, epoch.Load, initial.PasswordUnlock.Key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	dispatch := vaultwarden.RecoveryDispatch{OperationID: strings.Repeat("e", 32), Actor: actor, Target: cap.Scope(), Kind: "reset-password", PreviousRevision: "actor-revision", AuthorizationEpoch: 7, RequireTargetLogin: true}
	if err = adapter.Begin(dispatch); err != nil {
		t.Fatal(err)
	}
	state := call(storageRequest{Operation: "status"}).State
	before, err := os.ReadFile(os.Getenv("SNAPSHOT_TEST_DIRECTORY") + "/snapshot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	err = checkRuntimeTargetProtection(cap, f.a.runtimeVault.vault, state, f.a.epoch, &f.a.workerEpoch, call, &nativeRuntimeSecrets{call: frame})
	if !errors.Is(err, errRuntimeTargetBlocked) {
		t.Fatal("foreign target bypassed bootstrap", err)
	}
	after, err := os.ReadFile(os.Getenv("SNAPSHOT_TEST_DIRECTORY") + "/snapshot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only runtime query changed persistent state")
	}
}
func TestNativeBoundAccountSwitchConfirmedAndUnknownReceipts(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "lost-reply"}[unknown], func(t *testing.T) {
			call := recoveryNativeCall(t)
			oldScope := vaultwarden.Scope{Server: "https://old.example.invalid", Account: "old"}
			target := vaultwarden.Scope{Server: "https://new.example.invalid", Account: "new"}
			old := targetFixture(oldScope)
			fresh := targetFixture(target)
			fresh.PasswordUnlock.Key = bytes.Repeat([]byte{62}, 32)
			initial := call(storageRequest{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &oldScope, PasswordUnlock: old.PasswordUnlock, Session: old.Session, Vault: old.Vault})
			if !initial.OK {
				t.Fatal(initial.Code)
			}
			binding, err := newAccountSwitchBinding(initial.State, target)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			transport := func(r storageRequest) storageReply {
				reply := call(r)
				if r.Operation == "publishBoundAccount" {
					writes++
					if unknown && reply.OK {
						return storageReply{Code: "lost_reply", Message: "fixture dropped committed reply"}
					}
				}
				return reply
			}
			reply, err := publishBoundAccount(context.Background(), initial.State, fresh, binding, transport)
			defer clear(reply.Session)
			if unknown {
				if err == nil {
					t.Fatal("unknown adopted")
				}
				state := call(storageRequest{Operation: "status"}).State
				if state == nil || !state.AccountSwitchPending || *state.Scope != target {
					t.Fatal("committed uncertainty lost")
				}
				query := call(storageRequest{Operation: "inspectAccountSwitch", ExpectedRevision: state.Revision, SwitchOperationID: binding.OperationID})
				if !query.OK || query.AccountSwitch == nil || query.AccountSwitch.Binding != binding {
					t.Fatal("same-operation inspection", query.Code)
				}
				reply = call(storageRequest{Operation: "confirmAccountSwitch", ExpectedRevision: query.State.Revision, SwitchOperationID: binding.OperationID, UnlockKey: fresh.PasswordUnlock.Key})
				defer clear(reply.Session)
			} else if err != nil {
				t.Fatal(err)
			}
			if writes != 1 || !reply.OK || reply.State == nil || reply.State.AccountSwitchPending || reply.State.CleanupPending || reply.AccountSwitch == nil || reply.AccountSwitch.Phase != "confirmed" || *reply.State.Scope != target || reply.Vault == nil {
				t.Fatal("invalid final switch receipt", reply.Code)
			}
			denied := call(storageRequest{Operation: "listPassword", ExpectedRevision: reply.State.Revision, Scope: &oldScope, UnlockKey: old.PasswordUnlock.Key})
			if denied.OK {
				t.Fatal("old account key retained ordinary authority")
			}
			accepted := call(storageRequest{Operation: "listPassword", ExpectedRevision: reply.State.Revision, Scope: &target, UnlockKey: fresh.PasswordUnlock.Key})
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
