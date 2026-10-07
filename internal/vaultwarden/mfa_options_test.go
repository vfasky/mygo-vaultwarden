// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/base64"
	"testing"
)

func TestWebAuthnOptionsPreserveBinaryAndRP(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	raw := mfaJSON(map[string]any{"challenge": challenge, "rp": map[string]string{"id": "vault.example"}, "user": map[string]string{"id": "AP_-", "name": "test@example.invalid"}, "excludeCredentials": []map[string]string{{"type": "public-key", "id": "AQI"}}})
	options, e := ParseWebAuthnOptions("https://vault.example/base", raw, true, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer options.Binding.Close()
	if len(options.Challenge) != 32 || len(options.UserID) != 3 || options.UserID[1] != 255 || len(options.Excluded) != 1 {
		t.Fatal("binary corruption")
	}
	if _, e = ParseWebAuthnOptions("https://evil.example", raw, true, 1); e == nil {
		t.Fatal("unbound RP")
	}
	if _, e = ParseWebAuthnOptions("https://vault.example", []byte(`{"challenge":"a","challenge":"b"}`), false, 1); e == nil {
		t.Fatal("duplicate keys")
	}
}
