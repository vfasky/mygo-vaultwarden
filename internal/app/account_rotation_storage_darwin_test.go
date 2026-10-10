// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func recoveryNativeCall(t *testing.T) func(storageRequest) storageReply {
	t.Helper()
	library := os.Getenv("SNAPSHOT_TEST_HARNESS")
	if library == "" {
		t.Skip("requires isolated MemoryKeys Swift C ABI harness")
	}
	t.Setenv("SNAPSHOT_TEST_DIRECTORY", t.TempDir())
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := purego.Dlsym(handle, "mygo_snapshot_execute")
	if err != nil {
		t.Fatal(err)
	}
	var native func([]byte, int, []byte, int) int32
	purego.RegisterFunc(&native, symbol)
	return func(request storageRequest) storageReply {
		t.Helper()
		input, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(input)
		output, err := boundedStorageCall(input, func(frame []byte) ([]byte, error) {
			buffer := make([]byte, 512*1024)
			n := native(frame, len(frame), buffer, len(buffer))
			runtime.KeepAlive(frame)
			runtime.KeepAlive(buffer)
			if n <= 0 || int(n) > len(buffer) {
				t.Fatalf("ABI length %d", n)
			}
			return buffer[:n], nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(output)
		var reply storageReply
		if json.Unmarshal(output, &reply) != nil {
			t.Fatal("invalid bridge JSON")
		}
		return reply
	}
}
func TestNativeAccountRecoveryLifecycle(t *testing.T) {
	call := recoveryNativeCall(t)
	scope := vaultwarden.Scope{Server: "https://rotation.example.invalid", Account: "rotation-account"}
	key := bytes.Repeat([]byte{37}, 32)
	unlock := &vaultwarden.PasswordUnlock{Config: vaultwarden.PasswordUnlockConfig{Email: "rotation@example.invalid", KDF: vaultwarden.KDF{Iterations: 5000}}, Key: key}
	vault := &vaultwarden.VaultData{Version: 1, Scope: scope, Sync: []byte(`{"profile":{"id":"rotation-account","organizations":[]},"policies":[],"policiesNew":[],"ciphers":[],"opaque":9007199254740993}`)}
	session := []byte("old-session-secret")
	first := call(storageRequest{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &scope, PasswordUnlock: unlock, Session: session, Vault: vault})
	if !first.OK {
		t.Fatal(first.Code)
	}
	var epoch atomic.Uint64
	epoch.Store(19)
	adapter, err := newAccountRecoveryStorage(first.State, 19, epoch.Load, key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	oldVault, _ := json.Marshal(first.Vault)
	record := vaultwarden.AccountRecovery{Version: 1, OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Scope: scope, Kind: vaultwarden.AccountRotateKey, OldRevision: first.State.Revision, OldSession: session, OldUnlock: unlock, OldVault: oldVault, NewUserKey: bytes.Repeat([]byte{71}, 64), NewWrappedKey: "new-wrapper", Request: []byte(`{"hash":"secret-proof"}`)}
	// The exact typed function is accepted by the account Commit API.
	var persist vaultwarden.AccountRecoveryPersistence = adapter.Begin
	if err := persist(record); err != nil {
		t.Fatal(err)
	}
	pending, err := adapter.Query()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(record)
	if !bytes.Equal(pending.Recovery.Record, raw) || pending.Recovery.Phase != "prepared" || pending.Vault != nil || len(pending.Session) != 0 {
		t.Fatal("recovery receipt mismatch")
	}
	pending.Recovery.Close()
	blocked := call(storageRequest{Operation: "saveSession", ExpectedRevision: pending.State.Revision, Scope: &scope, UnlockKey: key, Session: []byte("interleaved")})
	if blocked.OK {
		t.Fatal("ordinary checkpoint bypassed barrier")
	}
	bad := vaultwarden.AccountChangeResult{OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Scope: scope, Kind: record.Kind, PreviousRevision: record.OldRevision, Dispatched: true, Unknown: true}
	if adapter.Result(bad) == nil {
		t.Fatal("foreign operation accepted")
	}
	bad.OperationID = record.OperationID
	if err := adapter.Result(bad); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Checkpoint(vaultwarden.SessionCheckpoint{Scope: scope, Session: []byte("new-login-checkpoint")}); err != nil {
		t.Fatal(err)
	}
	saved, err := adapter.Query()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Recovery.Phase != "unknown" || !bytes.Equal(saved.Recovery.Record, raw) || string(saved.Recovery.Checkpoint) != "new-login-checkpoint" {
		t.Fatal("unknown materials lost")
	}
	saved.Recovery.Close()
	locked := call(storageRequest{Operation: "lock"})
	if !locked.OK {
		t.Fatal(locked.Code)
	}
	epoch.Add(1)
	if _, err := adapter.Query(); err == nil {
		t.Fatal("late lifecycle accepted")
	}
	// Re-open with an explicitly authenticated recovery UI lifecycle. Binding epoch
	// stays the original operation's; current UI epoch is independently checked.
	reopened, err := newAccountRecoveryStorage(locked.State, epoch.Load(), epoch.Load, key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Query()
	if err != nil {
		t.Fatal(err)
	}
	after.Recovery.Close()
	fresh := vaultwarden.SyncResult{Scope: scope, Credentials: []vaultwarden.Credential{}, Vault: vault, Session: []byte("new-session-secret"), PasswordUnlock: &vaultwarden.PasswordUnlock{Config: unlock.Config, Key: bytes.Repeat([]byte{81}, 32)}}
	if _, err := reopened.ResolveVerified(fresh, true, true, false); err == nil {
		t.Fatal("missing full resource verification accepted")
	}
	complete, err := reopened.ResolveVerified(fresh, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Recovery != nil || complete.Vault == nil || !bytes.Equal(complete.Vault.Sync, vault.Sync) {
		t.Fatal("invalid completed snapshot receipt")
	}
	wrong := call(storageRequest{Operation: "listPassword", ExpectedRevision: complete.State.Revision, Scope: &scope, UnlockKey: key})
	if wrong.OK {
		t.Fatal("old unlock survived")
	}
	restored := call(storageRequest{Operation: "listPassword", ExpectedRevision: complete.State.Revision, Scope: &scope, UnlockKey: fresh.PasswordUnlock.Key})
	if !restored.OK || string(restored.Session) != "new-session-secret" {
		t.Fatal("fresh snapshot unavailable")
	}
	if _, err := reopened.ResolveVerified(fresh, true, true, true); err == nil {
		t.Fatal("duplicate clear accepted")
	}
}

func TestAccountRecoveryAdapterRejectsMissingReceiptAndLateEpoch(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://rotation.example.invalid", Account: "rotation-account"}
	state := &snapshotStatus{Available: true, Scope: &scope, Revision: "old", SnapshotID: "old-id"}
	unlock := &vaultwarden.PasswordUnlock{Key: bytes.Repeat([]byte{11}, 32)}
	record := vaultwarden.AccountRecovery{Version: 1, Scope: scope, OldRevision: "old", OldUnlock: unlock}
	var epoch atomic.Uint64
	epoch.Store(1)
	calls := 0
	adapter, err := newAccountRecoveryStorage(state, 1, epoch.Load, unlock.Key, func(storageRequest) storageReply {
		calls++
		return storageReply{OK: true, State: &snapshotStatus{Available: true, Scope: &scope, Revision: "next", SnapshotID: "new-id"}}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if adapter.Begin(record) == nil {
		t.Fatal("missing journal receipt accepted")
	}
	epoch.Store(2)
	if adapter.Begin(record) == nil || calls != 1 {
		t.Fatal("stale epoch dispatched storage write")
	}
}
