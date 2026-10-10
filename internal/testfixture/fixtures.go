// SPDX-License-Identifier: GPL-3.0-only
// Package testfixture contains shared fixtures imported only by tests.
package testfixture

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
)

func BackupDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TargetSnapshot is a structural storage fixture, not remote recovery evidence.
// Its legacy KDF intentionally exercises offline snapshot compatibility.
func TargetSnapshot(scope vaultwarden.Scope) vaultwarden.SyncResult {
	sync, err := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account, "organizations": []any{}}, "policies": []any{}, "policiesNew": []any{}, "ciphers": []any{}})
	if err != nil {
		panic(err)
	}
	return vaultwarden.SyncResult{Scope: scope, Vault: &vaultwarden.VaultData{Version: 1, Scope: scope, Sync: sync}, Session: []byte("isolated-fresh-session"), PasswordUnlock: &vaultwarden.PasswordUnlock{Config: vaultwarden.PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultcrypto.KDF{Iterations: 5000}}, Key: bytes.Repeat([]byte{41}, 32)}}
}
