// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServerValidationAndRedirectBoundary(t *testing.T) {
	for _, raw := range []string{"http://vault.example.com", "https://user:secret@example.com", "https://example.com/?x=1", "https://example.com/#x", "file:///secret", "https://example.com/a/../b", "https://example.com/%2fapi"} {
		if _, err := CanonicalServer(raw); err == nil {
			t.Fatalf("unsafe server accepted: %s", raw)
		}
	}
	if got, err := CanonicalServer(" https://Vault.Example.com/bitwarden/ "); err != nil || got != "https://vault.example.com/bitwarden" {
		t.Fatal("subpath normalization failed")
	}
	forwarded := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) }))
	defer first.Close()
	client, _ := NewClient(first.URL, fixtureUUID())
	if _, _, err := client.request(context.Background(), "POST", "/identity/connect/token", "application/x-www-form-urlencoded", "password=fixture", "token"); err == nil || forwarded {
		t.Fatal("redirect leaked a request")
	}
}
func TestSessionRefreshAndIdentityBinding(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 64)
	wrapped := "fixture-wrapped-key"
	refreshes := 0
	account := "account-a"
	profileKey := wrapped
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sub/identity/connect/token" {
			refreshes++
			_ = r.ParseForm()
			if r.Form.Get("refresh_token") != "refresh-old" {
				t.Error("wrong refresh token")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh", "refresh_token": "refresh-new", "expires_in": 3600, "token_type": "Bearer"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]any{"id": account, "email": "a@example.invalid", "key": profileKey, "organizations": []any{}, "organizationsNew": []any{}}, "ciphers": []any{}, "policies": []any{}, "policiesNew": []any{}})
	}))
	defer server.Close()
	client, _ := NewClient(server.URL+"/sub", fixtureUUID())
	s := &Session{client: client, email: "a@example.invalid", key: key, wrapped: wrapped, access: "expired", refresh: "refresh-old", expires: time.Now().Add(time.Hour)}
	if result, err := s.Sync(context.Background()); err != nil || result.Scope.Account != "account-a" || refreshes != 1 {
		t.Fatalf("refresh failed: %v", err)
	}
	account = "account-b"
	if _, err := s.Sync(context.Background()); err != ErrIdentity {
		t.Fatal("account substitution accepted")
	}
	account = "account-a"
	profileKey = "rotated"
	if _, err := s.Sync(context.Background()); err != ErrExpired {
		t.Fatal("key rotation was ignored")
	}
	s.Close()
	if _, err := s.Sync(context.Background()); err != ErrExpired {
		t.Fatal("closed session remained usable")
	}
}
func TestTLSRequiresValidTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	client, _ := NewClient(server.URL, fixtureUUID())
	if _, _, err := client.request(context.Background(), "GET", "/api/sync", "", "", ""); err != ErrNetwork {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client.http.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if status, _, err := client.request(context.Background(), "GET", "/api/sync", "", "", ""); err != nil || status != 200 {
		t.Fatal("properly trusted local TLS failed")
	}
}

func TestCancellationStopsNetwork(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer server.Close()
	client, _ := NewClient(server.URL, fixtureUUID())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Login(ctx, "a@example.invalid", []byte("password"), nil); err != ErrCancelled || called {
		t.Fatal("cancelled operation contacted server")
	}
}
func TestSyncFilteringAndFailureIsAtomic(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 64)
	enc := func(s string) *string { v := encryptFixture([]byte(s), key); return &v }
	var body syncReply
	// JSON fixture tests null fields and case-insensitive server property names too.
	payload := map[string]any{"profile": map[string]string{"id": "a", "email": "a@example.invalid", "key": "key"}, "ciphers": []any{
		map[string]any{"id": "good", "type": 1, "name": enc("personal"), "login": map[string]any{"username": enc("user"), "password": enc("password"), "uris": []any{map[string]any{"uri": enc("https://login.example.co.uk/"), "match": 0}}}},
		map[string]any{"id": "org", "type": 1, "organizationId": "org"}, map[string]any{"id": "reprompt", "type": 1, "reprompt": 1}, map[string]any{"id": "note", "type": 2}, map[string]any{"id": "deleted", "type": 1, "deletedDate": "now"},
	}}
	encoded, _ := json.Marshal(payload)
	_ = json.Unmarshal(encoded, &body)
	result, err := decryptSync(body, key)
	if err != nil || len(result.Credentials) != 1 || result.Summary.Organizations != 1 || result.Summary.Reprompt != 1 || result.Summary.Deleted != 1 {
		t.Fatalf("filtering failed: %v", err)
	}
	if result.Credentials[0].URIs[0].BaseDomain != "example.co.uk" {
		t.Fatal("public suffix handling failed")
	}
	bad := "2.invalid|cipher|tag"
	body.Ciphers[0].Login.Password = &bad
	if result, err := decryptSync(body, key); err != ErrEncryption || len(result.Credentials) != 0 {
		t.Fatal("corrupt data produced a partial success")
	}
}
func TestURIRulesDoNotExpandPublicSuffixOrUnsupportedModes(t *testing.T) {
	for _, mode := range []int{4, 5, 99} {
		if _, _, err := NormalizeURI("https://example.com", mode); err == nil {
			t.Fatal("unsupported rule accepted")
		}
	}
	for _, raw := range []string{"https://com", "https://co.uk", "http://127.0.0.1:18472/", "http://localhost:18472/"} {
		rule, _, err := NormalizeURI(raw, 0)
		if err != nil || rule.IncludeSubdomains {
			t.Fatalf("unsafe subdomain rule: %s", raw)
		}
	}
	rule, _, err := NormalizeURI("https://accounts.example.com/path", 0)
	if err != nil || rule.BaseDomain != "example.com" || !rule.IncludeSubdomains {
		t.Fatal("base-domain rule missing")
	}
	if _, _, err := NormalizeURI("https://username:password@example.com/", 0); err == nil {
		t.Fatal("userinfo URI accepted")
	}
	if _, _, err := NormalizeURI("javascript:alert(1)", 0); err == nil {
		t.Fatal("non-web URI accepted")
	}
	if !strings.HasPrefix(rule.URI, "https://") {
		t.Fatal("scheme changed")
	}
}

func TestLiteralURIPrefixSharedVectorsAndByteLimits(t *testing.T) {
	data, err := os.ReadFile("testdata/uri-prefix-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Prefix string
		Valid        bool
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			rule, host, err := NormalizeURI(vector.Prefix, 2)
			if (err == nil) != vector.Valid {
				t.Fatal("prefix eligibility", err)
			}
			if err == nil && (rule.URI != vector.Prefix || rule.Match != 2 || host != "" || rule.BaseDomain != "" || rule.IncludeSubdomains) {
				t.Fatal("prefix normalized or granted host fallback")
			}
		})
	}
	exact := "https://x/" + strings.Repeat("é", 4091)
	if len(exact) != 8192 {
		t.Fatal("fixture length")
	}
	if rule, _, err := NormalizeURI(exact, 2); err != nil || rule.URI != exact {
		t.Fatal("8192-byte prefix", err)
	}
	for _, prefix := range []string{exact + "a", exact + "é", "\xff", "https://x/\x00"} {
		if _, _, err := NormalizeURI(prefix, 2); err == nil {
			t.Fatal("invalid/oversized prefix accepted")
		}
	}
}
