// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/hex"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"testing"
)

func TestSnapshotUnlockKeyVectorAndPasswordBinding(t *testing.T) {
	config := PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultcrypto.KDF{Type: 0, Iterations: 5000}}
	key, err := DeriveSnapshotUnlockKey([]byte("fixture-master-password"), config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	// Independently derived using Node's PBKDF2 and HMAC (HKDF-Expand block 1).
	if hex.EncodeToString(key) != "7d9e27e111537223b56246a8b4d9a75f6bef2ff0c9f3a42894ebb542a4f4ded4" {
		t.Fatal("snapshot unlock KDF no longer matches the stored format")
	}
	wrong, err := DeriveSnapshotUnlockKey([]byte("wrong-password"), config)
	if err != nil || bytes.Equal(key, wrong) {
		t.Fatal("wrong password produced the same wrapping key")
	}
	clear(wrong)
	config.KDF.Iterations = 4999
	if _, err := DeriveSnapshotUnlockKey([]byte("fixture-master-password"), config); err != ErrKDF {
		t.Fatal("offline unlock accepted unsafe KDF parameters")
	}
}

func TestArgonSnapshotUnlockKey(t *testing.T) {
	config := PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultcrypto.KDF{Type: 1, Iterations: 2, Memory: 16, Parallelism: 1}}
	first, err := DeriveSnapshotUnlockKey([]byte("fixture-master-password"), config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first)
	second, err := DeriveSnapshotUnlockKey([]byte("fixture-master-password"), config)
	defer clear(second)
	if err != nil || len(first) != 32 || !bytes.Equal(first, second) {
		t.Fatal("Argon2id unlock could not reproduce the wrapping key")
	}
}
