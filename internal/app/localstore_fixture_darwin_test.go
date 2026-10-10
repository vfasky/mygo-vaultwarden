// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Keep this helper consistent with recoveryNativeCall in internal/localstore tests.
func recoveryNativeCall(t *testing.T) func(localstore.Request) localstore.Reply {
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
	return func(request localstore.Request) localstore.Reply {
		t.Helper()
		input, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(input)
		output, err := localstore.BoundedStorageCall(input, func(frame []byte) ([]byte, error) {
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
		var reply localstore.Reply
		if json.Unmarshal(output, &reply) != nil {
			t.Fatal("invalid bridge JSON")
		}
		return reply
	}
}

// Keep this helper consistent with targetFixture in internal/localstore tests.
func targetFixture(scope vaultwarden.Scope) vaultwarden.SyncResult {
	return vaultwarden.SyncResult{Scope: scope, Vault: &vaultwarden.VaultData{Version: 1, Scope: scope, Sync: []byte(`{"profile":{"id":"` + scope.Account + `","organizations":[]},"policies":[],"policiesNew":[],"ciphers":[]}`)}, Session: []byte("isolated-fresh-session"), PasswordUnlock: &vaultwarden.PasswordUnlock{Config: vaultwarden.PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultwarden.KDF{Iterations: 5000}}, Key: bytes.Repeat([]byte{41}, 32)}}
}
