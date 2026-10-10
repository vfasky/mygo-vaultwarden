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
	"time"
)

var accountTestPassword = []byte("Fixture-old-Passphrase-582!")

func accountFixture(t *testing.T, handle func(http.ResponseWriter, *http.Request, *Session, *VaultData)) (*Session, *VaultData) {
	t.Helper()
	var s *Session
	var v *VaultData
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == "/api/accounts/profile" || r.URL.Path == "/api/accounts/keys") && r.Method == "GET" {
			var o map[string]json.RawMessage
			_ = json.Unmarshal(v.Sync, &o)
			_, _ = w.Write(o["profile"])
			return
		}
		if r.URL.Path == "/api/accounts/verify-password" {
			_, _ = w.Write([]byte(`{"Object":"masterPasswordPolicy","minLength":12,"requireNumbers":true,"requireSpecial":true}`))
			return
		}
		if r.URL.Path == "/api/sync" {
			_, _ = w.Write(v.Sync)
			return
		}
		handle(w, r, s, v)
	}))
	t.Cleanup(server.Close)
	client, _ := NewClient(server.URL, "account-test-device-1234")
	kdf := vaultcrypto.KDF{Type: 0, Iterations: 100000}
	master, _ := vaultcrypto.DeriveMaster(accountTestPassword, "old@example.invalid", kdf)
	defer clear(master)
	stretched, _ := vaultcrypto.StretchMaster(master)
	defer clear(stretched)
	key := bytes.Repeat([]byte{23}, 64)
	wrapped, _ := vaultcrypto.EncryptString(key, stretched)
	unlock, _ := snapshotUnlockKey(master)
	s = &Session{client: client, account: "account-a", email: "old@example.invalid", access: "token", refresh: "refresh", expires: time.Now().Add(time.Hour), wrapped: wrapped, key: key, passwordUnlock: &PasswordUnlock{Config: PasswordUnlockConfig{Email: "old@example.invalid", KDF: kdf}, Key: unlock}}
	keys, err := makeOrganizationKeyPair(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": s.account, "email": s.email, "key": wrapped, "name": "fixture", "organizations": []any{}, "organizationsNew": []any{}, "privateKey": keys.EncryptedPrivateKey, "publicKey": keys.PublicKey}, "ciphers": []any{}, "folders": []any{}, "sends": []any{}, "policies": []any{}, "policiesNew": []any{}})
	v = &VaultData{Version: 1, Scope: Scope{Server: server.URL, Account: s.account}, Sync: raw}
	if err = s.AcceptAuthenticatedSnapshot(v, "account-revision"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, v
}
func TestAccountCredentialsRewrapAndRecoveryBeforeDispatch(t *testing.T) {
	for _, kind := range []AccountChangeKind{AccountChangePassword, AccountChangeEmail, AccountChangeKDF} {
		t.Run(string(kind), func(t *testing.T) {
			stored := []byte(nil)
			writes := 0
			s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
				if stored == nil {
					t.Error("dispatch before durable recovery")
				}
				writes++
				w.WriteHeader(200)
			})
			oldKey := append([]byte(nil), s.key...)
			defer clear(oldKey)
			password := []byte("Fixture-new-Passphrase-927!")
			kdf := vaultcrypto.KDF{Type: 1, Iterations: 2, Memory: 16, Parallelism: 1}
			email := "new@example.invalid"
			plan, err := s.PrepareAccountCredentials(context.Background(), v, kind, accountTestPassword, password, email, kdf, "hint", "123456", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			result, err := s.CommitAccountChange(context.Background(), plan, string(kind), nil, func(r AccountRecovery) error { stored, _ = json.Marshal(r); return nil })
			defer clear(stored)
			if err != nil || !result.Confirmed || !result.RequireLogin || writes != 1 || !s.closed {
				t.Fatalf("change not finalized: %+v %v", result, err)
			}
			var recovery AccountRecovery
			if json.Unmarshal(stored, &recovery) != nil {
				t.Fatal("bad recovery")
			}
			defer recovery.Close()
			newPassword := password
			if kind != AccountChangePassword {
				newPassword = accountTestPassword
			}
			master, err := vaultcrypto.DeriveMaster(newPassword, recovery.NewUnlock.Config.Email, recovery.NewUnlock.Config.KDF)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(master)
			stretched, _ := vaultcrypto.StretchMaster(master)
			defer clear(stretched)
			unwrapped, err := vaultcrypto.DecryptString(recovery.NewWrappedKey, stretched)
			defer clear(unwrapped)
			if err != nil || !bytes.Equal(unwrapped, oldKey) {
				t.Fatal("lost original user key")
			}
			old, err := RestoreSession(recovery.OldSession, recovery.Scope, &recovery.OldUnlock.Config)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			if !bytes.Equal(old.key, oldKey) || !bytes.Equal(recovery.OldVault, mustAccountJSON(t, v)) {
				t.Fatal("old recovery lost")
			}
			if _, err = s.CommitAccountChange(context.Background(), plan, string(kind), nil, func(AccountRecovery) error { return nil }); err == nil || writes != 1 {
				t.Fatal("replayed change")
			}
		})
	}
}
func mustAccountJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestAccountChangeFailClosedAndUnknown(t *testing.T) {
	for _, scenario := range []string{"wrong-password", "cancel", "old-revision", "old-epoch", "storage-fail", "confirmation", "refresh-fail", "checkpoint-fail", "server-key", "partial-400", "partial-500", "transport"} {
		t.Run(scenario, func(t *testing.T) {
			var writes atomic.Int32
			s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
				if r.URL.Path == "/identity/connect/token" {
					if scenario == "checkpoint-fail" {
						_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "rotated-refresh", "expires_in": 3600, "token_type": "bearer", "key": s.wrapped})
					} else if scenario == "server-key" {
						_, _ = w.Write([]byte(`{"access_token":"a","refresh_token":"b","expires_in":3600,"token_type":"bearer","key":"changed"}`))
					} else {
						w.WriteHeader(500)
					}
					return
				}
				writes.Add(1)
				switch scenario {
				case "partial-400":
					w.WriteHeader(400)
				case "partial-500":
					w.WriteHeader(500)
				case "transport":
					h, _, _ := w.(http.Hijacker).Hijack()
					_ = h.Close()
				default:
					w.WriteHeader(200)
				}
			})
			password := accountTestPassword
			if scenario == "wrong-password" {
				password = []byte("wrong")
			}
			plan, err := s.PrepareAccountDestructive(context.Background(), v, AccountPurge, AccountSensitiveInput{Password: password}, nil)
			if scenario == "wrong-password" {
				if err == nil || writes.Load() != 0 {
					t.Fatal("wrong password accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			confirm := "purge"
			switch scenario {
			case "cancel":
				cancel()
			case "old-revision":
				s.authorizationRevision = "other"
			case "old-epoch":
				s.authorizationEpoch++
			case "confirmation":
				confirm = ""
			case "refresh-fail", "server-key", "checkpoint-fail":
				s.expires = time.Time{}
			}
			saved := false
			result, err := s.CommitAccountChange(ctx, plan, confirm, func(SessionCheckpoint) error {
				if scenario == "checkpoint-fail" {
					return ErrCheckpoint
				}
				return nil
			}, func(r AccountRecovery) error {
				if scenario == "storage-fail" {
					return ErrCheckpoint
				}
				saved = true
				return nil
			})
			partial := scenario == "partial-400" || scenario == "partial-500" || scenario == "transport"
			if err == nil {
				t.Fatal("failure hidden")
			}
			if partial {
				if !result.Unknown || !result.Dispatched || !saved || writes.Load() != 1 || !s.closed {
					t.Fatal("partial failure not quarantined")
				}
				var uncertain *MutationUncertainError
				if !errors.As(err, &uncertain) {
					t.Fatal("retryable error")
				}
			} else if writes.Load() != 0 || result.Dispatched {
				t.Fatal("unsafe write")
			}
		})
	}
}
func TestAccountPolicyAndSensitiveInput(t *testing.T) {
	policy := AccountPasswordPolicy{MinLength: 12, MinComplexity: 3, RequireLower: true, RequireUpper: true, RequireNumbers: true, RequireSpecial: true, EnforceOnLogin: true}
	for _, bad := range []string{"password", "AAAAAAAAAAAA1!", "aaaaaaaaaaaa1!", "LongPasswordWithoutNumber!", "LongPassword123?"} {
		if policy.Check(context.Background(), []byte(bad), "user@example.invalid", false) == nil {
			t.Fatal("weak password passed")
		}
	}
	if err := policy.Check(context.Background(), []byte("Orchid!Paper762-Volcano"), "user@example.invalid", true); err != nil {
		t.Fatal(err)
	}
	// Exact clients policy: Unicode case mappings count; '?' does not satisfy its
	// explicit !@#$%^&* set; length is JavaScript UTF-16 length.
	if err := (AccountPasswordPolicy{RequireUpper: true, RequireLower: true, MinLength: 4}).Check(context.Background(), []byte("Éß😀"), "x", false); err != nil {
		t.Fatal(err)
	}
	p := policy
	p.EnforceOnLogin = false
	if p.Check(context.Background(), []byte("short"), "x", true) != nil {
		t.Fatal("enforceOnLogin ignored")
	}
	s, _ := accountFixture(t, func(w http.ResponseWriter, r *http.Request, _ *Session, _ *VaultData) { w.WriteHeader(400) })
	for _, in := range []AccountSensitiveInput{{}, {Password: accountTestPassword, OTP: "123456"}, {Password: []byte("bad")}} {
		if _, err := s.accountProofLocked(in); err == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	if _, err := s.accountProofLocked(AccountSensitiveInput{OTP: "123456"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []vaultcrypto.KDF{{Type: 0, Iterations: 99999}, {Type: 2, Iterations: 100000}, {Type: 1, Iterations: 2, Memory: 257, Parallelism: 1}, {Type: 1, Iterations: 100000, Memory: 16, Parallelism: 1}} {
		if accountNewKDF(k) == nil {
			t.Fatal("unbounded KDF accepted")
		}
	}
}
