// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLoginChallengeProtocol(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prompts  int
		requests int32
		wantErr  error
	}{
		{"without-mfa", 0, 1, nil},
		{"retry-success", 2, 3, nil},
		{"exhausted", 2, 3, ErrCredentials},
		{"cancelled", 1, 1, ErrCancelled},
		{"wrong-password", 0, 1, ErrCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := "fixture@example.invalid"
			password := []byte("fixture-master-password")
			defer clear(password)
			kdf := vaultcrypto.KDF{Type: 0, Iterations: 5000}
			master, err := vaultcrypto.DeriveMaster(password, email, kdf)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(master)
			stretched, err := vaultcrypto.StretchMaster(master)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(stretched)
			authHash := vaultcrypto.AuthorizationHash(master, password)
			wrapped := encryptFixture(bytes.Repeat([]byte{42}, 64), stretched)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/identity/accounts/prelogin" {
					_ = json.NewEncoder(w).Encode(kdf)
					return
				}
				if r.URL.Path == "/api/sync" {
					_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]any{"id": "account-a", "email": email, "key": wrapped, "organizations": []any{}, "organizationsNew": []any{}}, "ciphers": []any{}, "policies": []any{}, "policiesNew": []any{}})
					return
				}
				if r.URL.Path != "/identity/connect/token" {
					t.Error("unexpected request")
					w.WriteHeader(404)
					return
				}
				n := requests.Add(1)
				_ = r.ParseForm()
				if r.Form.Get("password") != authHash {
					t.Error("authorization hash changed across the challenge")
				}
				if n == 1 && tc.name != "without-mfa" && tc.name != "wrong-password" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"twoFactorProviders":[0]}`))
					return
				}
				if n > 1 && (r.Form.Get("twoFactorToken") != "123456" || r.Form.Get("twoFactorProvider") != "0" || r.Form.Get("twoFactorRemember") != "0") {
					t.Error("wrong MFA submission")
				}
				if tc.name == "wrong-password" || tc.name == "exhausted" || (tc.name == "retry-success" && n == 2) {
					w.WriteHeader(400)
					// Invalid codes may not repeat the provider metadata.
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-refresh", "token_type": "Bearer", "expires_in": 3600, "key": wrapped})
			}))
			defer server.Close()
			client, err := NewClient(server.URL, fixtureUUID())
			if err != nil {
				t.Fatal(err)
			}
			prompts := 0
			session, err := client.Login(context.Background(), email, password, func() ([]byte, error) {
				prompts++
				// The UI flow releases the raw password at the first challenge.
				clear(password)
				if tc.name == "cancelled" {
					return nil, ErrCancelled
				}
				return []byte("123456"), nil
			})
			if session != nil {
				defer session.Close()
				// MFA clears the raw password; its original KDF material must still
				// produce the same offline key as a later password-only unlock.
				config := PasswordUnlockConfig{Email: email, KDF: kdf}
				key, err := DeriveSnapshotUnlockKey([]byte("fixture-master-password"), config)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key)
				result, err := session.Sync(context.Background())
				if err != nil || result.PasswordUnlock == nil || !bytes.Equal(key, result.PasswordUnlock.Key) {
					t.Fatal("successful login did not publish the password unlock key")
				}
				clear(result.PasswordUnlock.Key)
				result, err = session.Sync(context.Background())
				if err != nil || !bytes.Equal(key, result.PasswordUnlock.Key) {
					t.Fatal("publication cleanup changed the session wrapping key")
				}
				clear(result.PasswordUnlock.Key)
				retained := session.passwordUnlock.Key
				session.Close()
				if session.passwordUnlock != nil || !bytes.Equal(retained, make([]byte, len(retained))) {
					t.Fatal("closing the session retained the wrapping key")
				}
			}
			if !errors.Is(err, tc.wantErr) || prompts != tc.prompts || requests.Load() != tc.requests {
				t.Fatalf("unexpected result: err=%v prompts=%d requests=%d", err, prompts, requests.Load())
			}
		})
	}
}
