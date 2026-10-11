// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
)

func TestAccountProofAndRecoveryRejectWeakKDF(t *testing.T) {
	kdf := vaultcrypto.KDF{Iterations: 5000}
	s := &Session{email: "a@example.invalid", passwordUnlock: &PasswordUnlock{Config: PasswordUnlockConfig{KDF: kdf}}}
	proof, err := s.accountProofLocked(AccountSensitiveInput{Password: []byte("fixture-password")})
	if !errors.Is(err, ErrWeakKDF) || proof.Hash != "" {
		t.Fatalf("account proof: %+v, %v", proof, err)
	}
	hash, wrapped, err := recoveryPasswordPayload(context.Background(), []byte("Fixture-Password-92!"), s.email, kdf, make([]byte, 64), AccountPasswordPolicy{})
	if !errors.Is(err, ErrWeakKDF) || hash != "" || wrapped != "" {
		t.Fatalf("recovery produced weak proof: %v", err)
	}
}
