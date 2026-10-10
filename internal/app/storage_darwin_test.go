// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestNativeStorageTransferABI(t *testing.T) {
	library := os.Getenv("SNAPSHOT_TEST_BRIDGE")
	if library == "" {
		t.Skip("set SNAPSHOT_TEST_BRIDGE to the test-built production dylib")
	}
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	// Keep loaded: Swift expiry timers can outlive this test, as in production.
	symbol, err := purego.Dlsym(handle, "mygo_snapshot_execute")
	if err != nil {
		t.Fatal(err)
	}
	var call func([]byte, int, []byte, int) int32
	purego.RegisterFunc(&call, symbol)
	frames := 0
	// Unsupported operation is rejected before sharedContainer/Keychain access.
	// More than 4 MiB still traverses the real C ABI in bounded pages.
	input := []byte(`{"operation":"unsupported-test-operation","padding":"` + strings.Repeat("x", 5*1024*1024) + `"}`)
	_, err = boundedStorageCall(input, func(raw []byte) ([]byte, error) {
		frames++
		output := make([]byte, 512*1024)
		n := call(raw, len(raw), output, len(output))
		runtime.KeepAlive(raw)
		runtime.KeepAlive(output)
		if n <= 0 || int(n) > len(output) {
			t.Fatalf("invalid native reply: %d", n)
		}
		return output[:n], nil
	})
	if err == nil || frames < 23 {
		t.Fatalf("expected post-upload rejection, frames=%d err=%v", frames, err)
	}
}

func TestNativeLargeAuthenticatedSnapshot(t *testing.T) {
	library := os.Getenv("SNAPSHOT_TEST_HARNESS")
	if library == "" {
		t.Skip("set SNAPSHOT_TEST_HARNESS to the isolated test-configured bridge")
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
	call := func(request storageRequest) storageReply {
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
				t.Fatalf("invalid ABI length %d", n)
			}
			return buffer[:n], nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(output)
		var reply storageReply
		if err := json.Unmarshal(output, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	scope := vaultwarden.Scope{Server: "https://vault.example.invalid", Account: "large-account"}
	key := bytes.Repeat([]byte{37}, 32)
	material := &vaultwarden.PasswordUnlock{Config: vaultwarden.PasswordUnlockConfig{Email: "large@example.invalid", KDF: vaultwarden.KDF{Iterations: 5000}}, Key: key}
	raw := []byte(`{"profile":{"id":"large-account","organizations":[]},"policies":[],"policiesNew":[],"ciphers":[],"largeUnknownField":"` + strings.Repeat("x", 5*1024*1024) + `"}`)
	vault := &vaultwarden.VaultData{Version: 1, Scope: scope, Sync: raw}
	first := call(storageRequest{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &scope, PasswordUnlock: material, Session: []byte("test-session"), Vault: vault})
	if !first.OK || first.State == nil || first.Vault == nil || !bytes.Equal(first.Vault.Sync, raw) {
		t.Fatalf("large publish failed: %s", first.Code)
	}
	unlocked := call(storageRequest{Operation: "listPassword", ExpectedRevision: first.State.Revision, Scope: &scope, UnlockKey: key})
	if !unlocked.OK || unlocked.Vault == nil || !bytes.Equal(unlocked.Vault.Sync, raw) || string(unlocked.Session) != "test-session" {
		t.Fatalf("large authenticated restore failed: %s", unlocked.Code)
	}
	wrong := call(storageRequest{Operation: "listPassword", ExpectedRevision: first.State.Revision, Scope: &scope, UnlockKey: bytes.Repeat([]byte{99}, 32)})
	if wrong.OK || wrong.Code != "invalid_password" || wrong.Vault != nil || len(wrong.Session) != 0 {
		t.Fatal("wrong key released payload")
	}
	checkpoint := call(storageRequest{Operation: "saveSession", ExpectedRevision: first.State.Revision, Scope: &scope, UnlockKey: key, Session: []byte("new-token")})
	if !checkpoint.OK || checkpoint.Vault == nil || !bytes.Equal(checkpoint.Vault.Sync, raw) {
		t.Fatalf("large checkpoint failed: %s", checkpoint.Code)
	}
	locked := call(storageRequest{Operation: "lock"})
	if !locked.OK {
		t.Fatal("lock failed")
	}
	stale := call(storageRequest{Operation: "listPassword", ExpectedRevision: checkpoint.State.Revision, Scope: &scope, UnlockKey: key})
	if stale.OK || stale.Code != "stale_revision" || stale.Vault != nil {
		t.Fatal("stale request released payload")
	}
}
