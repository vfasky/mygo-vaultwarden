// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"strings"
	"testing"
)

// Test-only fixture encryption. No vault writes/encryption endpoints are shipped.
func encryptFixture(data, key []byte) string {
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	padding := 16 - len(data)%16
	plain := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, _ := aes.NewCipher(key[:32])
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	mac := hmac.New(sha256.New, key[32:])
	mac.Write(iv)
	mac.Write(plain)
	return "2." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(plain) + "|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestDecryptIntegrityAndEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x4a}, 64)
	encoded := encryptFixture([]byte("你好 / password"), key)
	got, err := vaultcrypto.DecryptString(encoded, key)
	if err != nil || string(got) != "你好 / password" {
		t.Fatal("cipher roundtrip failed")
	}
	parts := strings.Split(encoded, "|")
	parts[2] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, bad := range []string{strings.Join(parts, "|"), "0." + encoded[2:], "7.AAAA", "2.AA==|AA==|AA==", "", encoded + "|extra"} {
		if _, err := vaultcrypto.DecryptString(bad, key); err != vaulterr.ErrEncryption {
			t.Fatal("invalid cipher was accepted")
		}
	}
}
