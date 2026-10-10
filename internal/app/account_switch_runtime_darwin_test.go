// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
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
			return nil, localstore.ErrRuntimeSecretUnavailable
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
	published := call(localstore.Request{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &actor, PasswordUnlock: initial.PasswordUnlock, Session: initial.Session, Vault: initial.Vault})
	if !published.OK {
		t.Fatal(published.Code)
	}
	var epoch atomic.Uint64
	epoch.Store(3)
	adapter, err := localstore.NewTargetRecoveryStorage(published.State, 3, epoch.Load, initial.PasswordUnlock.Key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	dispatch := vaultwarden.RecoveryDispatch{OperationID: strings.Repeat("e", 32), Actor: actor, Target: cap.Scope(), Kind: "reset-password", PreviousRevision: "actor-revision", AuthorizationEpoch: 7, RequireTargetLogin: true}
	if err = adapter.Begin(dispatch); err != nil {
		t.Fatal(err)
	}
	state := call(localstore.Request{Operation: "status"}).State
	before, err := os.ReadFile(os.Getenv("SNAPSHOT_TEST_DIRECTORY") + "/snapshot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	err = localstore.CheckRuntimeTargetProtection(cap, f.a.runtimeVault.vault, state, f.a.epoch, &f.a.workerEpoch, call, &localstore.NativeRuntimeSecrets{Call: frame})
	if !errors.Is(err, localstore.ErrRuntimeTargetBlocked) {
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
