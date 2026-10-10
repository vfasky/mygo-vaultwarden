// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"testing"
)

func TestSendNativeSaveName(t *testing.T) {
	for _, name := range []string{"../private.txt", "C:\\secrets\\private.txt"} {
		if sendSaveName(name) != "private.txt" {
			t.Fatal("path in suggested filename")
		}
	}
	for _, name := range []string{"..", "secret\nfile"} {
		if sendSaveName(name) != "Send 文件" {
			t.Fatal("unsafe suggested filename")
		}
	}
}
