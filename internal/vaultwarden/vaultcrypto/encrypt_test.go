// SPDX-License-Identifier: GPL-3.0-only
package vaultcrypto

import (
	"bytes"
	"encoding/base64"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"strings"
	"testing"
)

func TestEncryptStringRoundTripAndIndependentIV(t *testing.T) {
	key := bytes.Repeat([]byte{31}, 64)
	for _, plain := range [][]byte{nil, []byte("秘密🔑"), bytes.Repeat([]byte{255}, 16), bytes.Repeat([]byte{0}, 1024*1024)} {
		first, err := EncryptString(plain, key)
		if err != nil {
			t.Fatal(err)
		}
		second, err := EncryptString(plain, key)
		if err != nil || first == second {
			t.Fatal("encryption reused IV")
		}
		decoded, err := DecryptString(first, key)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatal("encryption roundtrip failed")
		}
		clear(decoded)
	}
	if _, err := EncryptString([]byte("secret"), key[:32]); err != vaulterr.ErrEncryption {
		t.Fatal("invalid key accepted")
	}
	if _, err := EncryptString(make([]byte, 1024*1024+1), key); err != vaulterr.ErrEncryption {
		t.Fatal("unbounded input accepted")
	}
}

func TestEncryptStringRejectsTamperingEveryComponent(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 64)
	encrypted, err := EncryptString([]byte("sensitive field"), key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		parts := strings.Split(encrypted[2:], "|")
		component, err := base64.StdEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		component[0] ^= 1
		parts[i] = base64.StdEncoding.EncodeToString(component)
		if plain, err := DecryptString("2."+strings.Join(parts, "|"), key); err != vaulterr.ErrEncryption || plain != nil {
			t.Fatal("tampering accepted")
		}
	}
	wrong := bytes.Repeat([]byte{4}, 64)
	if plain, err := DecryptString(encrypted, wrong); err != vaulterr.ErrEncryption || plain != nil {
		t.Fatal("wrong key accepted")
	}
}
