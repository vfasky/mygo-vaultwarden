// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"os"
	"testing"
)

func TestOrganizationOpenSSLFixedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/organization-rsa.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ PKCS8, SHA256, SHA1 string }
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("vector")
	}
	der, err := base64.StdEncoding.DecodeString(vector.PKCS8)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(*rsa.PrivateKey)
	expected := make([]byte, 64)
	for i := range expected {
		expected[i] = byte(i)
	}
	for _, wrapped := range []string{vector.SHA256, vector.SHA1} {
		key, err := unwrapOrganizationKey(wrapped, private)
		if err != nil || !bytes.Equal(key, expected) {
			t.Fatal("OpenSSL OAEP vector", err)
		}
		wrong := "3." + wrapped[2:]
		if wrapped[0] == '3' {
			wrong = "4." + wrapped[2:]
		}
		if _, err := unwrapOrganizationKey(wrong, private); err == nil {
			t.Fatal("cross-hash OAEP accepted")
		}
	}
	owner := bytes.Repeat([]byte{3}, 64)
	wrapped, _ := vaultcrypto.EncryptString(der, owner)
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	profile, _ := json.Marshal(map[string]any{"privateKey": wrapped, "accountKeys": map[string]any{"publicKeyEncryptionKeyPair": map[string]string{"wrappedPrivateKey": wrapped, "publicKey": base64.StdEncoding.EncodeToString(public)}}})
	if _, err := accountPrivateKey(profile, owner); err != nil {
		t.Fatal("PKCS8/SPKI", err)
	}
	for _, badDER := range [][]byte{der[:len(der)-1], x509.MarshalPKCS1PrivateKey(private), append(append([]byte(nil), der...), 0), bytes.Repeat([]byte{0}, 8193)} {
		wrapped, _ := vaultcrypto.EncryptString(badDER, owner)
		profile, _ := json.Marshal(map[string]any{"privateKey": wrapped})
		if _, err := accountPrivateKey(profile, owner); err == nil {
			t.Fatal("invalid PKCS8 accepted")
		}
	}
}

func TestOrganizationAutoFillExclusions(t *testing.T) {
	session, vault, _, _ := organizationFixture(t, "http://127.0.0.1:1")
	defer session.Close()
	for _, tc := range []struct {
		name, field string
		value       any
		expected    int
	}{
		{"allowed", "reprompt", 0, 1}, {"reprompt", "reprompt", 1, 0}, {"hidden", "viewPassword", false, 0}, {"deleted", "deletedDate", "2026-06-01T00:00:00Z", 0}, {"archived", "archivedDate", "2026-06-01T00:00:00Z", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := changeOrganizationFixture(t, vault, func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)[tc.field] = tc.value })
			result := SyncResult{Vault: v}
			session.mu.Lock()
			err := session.appendOrganizationCredentialsLocked(&result, &operationPolicies{})
			session.mu.Unlock()
			if err != nil || len(result.Credentials) != tc.expected {
				t.Fatal("AutoFill exclusion", err, len(result.Credentials))
			}
		})
	}
	revoked := changeOrganizationFixture(t, vault, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		p["organizations"], p["organizationsNew"] = []any{}, []any{}
	})
	result := SyncResult{Vault: revoked}
	session.mu.Lock()
	err := session.appendOrganizationCredentialsLocked(&result, &operationPolicies{})
	session.mu.Unlock()
	if err != nil || len(result.Credentials) != 0 {
		t.Fatal("revoked projection", err)
	}
}
