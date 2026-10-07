// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// PasswordUnlockConfig is public KDF metadata, never a password verifier.
// The snapshot header and this configuration are authenticated by the wrapper.
type PasswordUnlockConfig struct {
	Email string `json:"email"`
	KDF   KDF    `json:"kdf"`
}

// PasswordUnlock carries a domain-separated wrapping key only while publishing.
// Callers must clear Key after passing it to secure storage.
type PasswordUnlock struct {
	Config PasswordUnlockConfig `json:"config"`
	Key    []byte               `json:"key"`
}

func snapshotUnlockKey(master []byte) ([]byte, error) {
	return hkdf.Expand(sha256.New, master, "mygo-vaultwarden/snapshot-unlock/v1", 32)
}

func DeriveSnapshotUnlockKey(password []byte, config PasswordUnlockConfig) ([]byte, error) {
	master, err := DeriveMaster(password, config.Email, config.KDF)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	return snapshotUnlockKey(master)
}
