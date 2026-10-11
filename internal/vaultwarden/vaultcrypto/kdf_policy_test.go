// SPDX-License-Identifier: GPL-3.0-only
package vaultcrypto

import (
	"errors"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

func TestOnlineKDFPolicyAndOfflineCompatibility(t *testing.T) {
	for _, iterations := range []int{0, 4999, 5000, 99999} {
		key, err := DeriveOnlineMaster([]byte("fixture-password"), "a@example.invalid", KDF{Iterations: iterations})
		if !errors.Is(err, vaulterr.ErrWeakKDF) || len(key) != 0 {
			t.Fatalf("iterations %d: %v", iterations, err)
		}
	}
	key, err := DeriveMaster([]byte("fixture-password"), "a@example.invalid", KDF{Iterations: 5000})
	defer clear(key)
	if err != nil || len(key) != 32 {
		t.Fatalf("legacy offline derivation: %v", err)
	}
	key, err = DeriveOnlineMaster([]byte("fixture-password"), "a@example.invalid", KDF{Iterations: 100000})
	defer clear(key)
	if err != nil || len(key) != 32 {
		t.Fatalf("online floor: %v", err)
	}
}

func TestArgonMemoryValidationBounds(t *testing.T) {
	// Test the validator directly: the maximum must not allocate a GiB in tests.
	for _, memory := range []int{15, 16, 256, 257, 1024, 1025} {
		err := ValidateKDF(KDF{Type: 1, Iterations: 2, Memory: memory, Parallelism: 1})
		valid := memory >= 16 && memory <= 1024
		if (err == nil) != valid {
			t.Fatalf("memory %d: %v", memory, err)
		}
	}
}
