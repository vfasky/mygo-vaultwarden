// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package localstore

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/ebitengine/purego"
)

func TestNativeUnknownOperationFailsClosed(t *testing.T) {
	library := os.Getenv("SNAPSHOT_TEST_BRIDGE")
	if library == "" {
		t.Skip("set SNAPSHOT_TEST_BRIDGE to the production bridge")
	}
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
	for _, operation := range []Operation{"", "STATUS", "unsupported-test-operation", "activate"} {
		input, err := json.Marshal(Request{Operation: operation})
		if err != nil {
			t.Fatal(err)
		}
		output := make([]byte, 4096)
		n := native(input, len(input), output, len(output))
		runtime.KeepAlive(input)
		runtime.KeepAlive(output)
		if n <= 0 || int(n) > len(output) {
			t.Fatalf("invalid response length: %d", n)
		}
		var reply Reply
		if err := json.Unmarshal(output[:n], &reply); err != nil {
			t.Fatal(err)
		}
		if reply.OK || reply.Code != "invalid_input" || reply.State != nil || reply.Vault != nil || reply.Session != nil {
			t.Fatalf("unknown operation did not fail closed: %+v", reply)
		}
	}
}
