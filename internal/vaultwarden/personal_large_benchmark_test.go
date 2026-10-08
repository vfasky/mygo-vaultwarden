// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Measures real authenticated-snapshot acceptance and personal metadata
// decryption; setup encryption is excluded from per-operation timing. Process RSS
// measured externally still includes fixture construction and Go runtime memory.
func BenchmarkPersonalVault10000(b *testing.B) {
	userKey := bytes.Repeat([]byte{42}, 64)
	defer clear(userKey)
	client, err := NewClient("https://large-fixture.example.invalid", "large-fixture-device")
	if err != nil {
		b.Fatal(err)
	}
	scope := Scope{Server: "https://large-fixture.example.invalid", Account: "large-account"}
	session := &Session{client: client, email: "large@example.invalid", account: scope.Account, key: userKey, wrapped: "fixture-wrapped", access: "fixture-access", refresh: "fixture-refresh", expires: time.Now().Add(time.Hour)}
	defer session.Close()
	rows := make([]json.RawMessage, 10000)
	for i := range rows {
		document, e := NewPersonalCipher(CipherFields{Type: 1, Name: fmt.Sprintf("Large fixture %05d", i), Login: map[string]any{"username": "fixture-user", "password": "fixture-password", "uris": []any{map[string]any{"uri": "https://example.invalid", "match": 0}}}}, userKey, scope.Account)
		if e != nil {
			b.Fatal(e)
		}
		var object map[string]any
		json.Unmarshal(document.JSON, &object)
		object["id"] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		object["edit"], object["viewPassword"] = true, true
		rows[i], _ = json.Marshal(object)
	}
	raw, err := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account, "email": session.email, "key": session.wrapped, "organizations": []any{}, "organizationsNew": []any{}}, "ciphers": rows, "folders": []any{}, "sends": []any{}, "policies": []any{}, "policiesNew": []any{}})
	if err != nil {
		b.Fatal(err)
	}
	vault := &VaultData{Version: 1, Scope: scope, Sync: raw}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := session.AcceptAuthenticatedSnapshot(vault, "large-revision"); err != nil {
			b.Fatal(err)
		}
		entries, err := session.PersonalEntries(vault)
		if err != nil || len(entries) != 10000 {
			b.Fatalf("large vault entries=%d err=%v", len(entries), err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(raw)), "vault-bytes")
}
