// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package testfixture

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/ebitengine/purego"
)

// RecoveryNativeCall uses only an explicitly supplied isolated MemoryKeys harness.
// The caller supplies its bounded protocol framing to avoid importing localstore.
func RecoveryNativeCall[Request, Reply any](t *testing.T, bounded func([]byte, func([]byte) ([]byte, error)) ([]byte, error)) func(Request) Reply {
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
	t.Cleanup(func() {
		if err := purego.Dlclose(handle); err != nil {
			t.Error(err)
		}
	})
	symbol, err := purego.Dlsym(handle, "mygo_snapshot_execute")
	if err != nil {
		t.Fatal(err)
	}
	var native func([]byte, int, []byte, int) int32
	purego.RegisterFunc(&native, symbol)
	return func(request Request) Reply {
		t.Helper()
		input, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(input)
		output, err := bounded(input, func(frame []byte) ([]byte, error) {
			buffer := make([]byte, 512*1024)
			n := native(frame, len(frame), buffer, len(buffer))
			runtime.KeepAlive(frame)
			runtime.KeepAlive(buffer)
			if n <= 0 || int(n) > len(buffer) {
				clear(buffer)
				t.Fatalf("ABI length %d", n)
			}
			return buffer[:n], nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clear(output)
		var reply Reply
		if err := json.Unmarshal(output, &reply); err != nil {
			t.Fatal("invalid bridge JSON", err)
		}
		return reply
	}
}
