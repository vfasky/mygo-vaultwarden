// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func authenticatedSnapshotFixture(t *testing.T) (*Session, *VaultData, []byte, PasswordUnlockConfig) {
	t.Helper()
	s, config := resumableFixture(t, "https://snapshot.example.invalid")
	raw, err := json.Marshal(emptyPolicySyncFixture())
	if err != nil {
		t.Fatal(err)
	}
	v := &VaultData{Version: 1, Scope: Scope{Server: s.client.base.String(), Account: s.account}, Sync: raw}
	saved, err := s.savedLocked()
	if err != nil {
		t.Fatal(err)
	}
	return s, v, saved, config
}

func TestAuthenticatedSnapshotConstructorAndPublicBinder(t *testing.T) {
	s, v, saved, config := authenticatedSnapshotFixture(t)
	defer s.Close()
	defer clear(saved)
	network, err := RestoreSession(saved, v.Scope, &config)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	if err = network.BindSnapshotRevision(v.Scope, "revision-1"); err != nil {
		t.Fatal(err)
	}
	if err = network.ValidateAuthenticatedSnapshot(v, "revision-1"); !errors.Is(err, ErrExpired) {
		t.Fatal("public revision created offline authority", err)
	}
	restored, err := RestoreSessionFromAuthenticatedSnapshot(saved, v.Scope, &config, v, "revision-1")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	clear(saved)
	if err = restored.ValidateAuthenticatedSnapshot(v, "revision-1"); err != nil {
		t.Fatal(err)
	}
	if err = restored.BindSnapshotRevision(v.Scope, "revision-1"); err != nil {
		t.Fatal(err)
	}
	if err = restored.ValidateAuthenticatedSnapshot(v, "revision-1"); err != nil {
		t.Fatal("same revision revoked current authority", err)
	}
	if err = restored.BindSnapshotRevision(v.Scope, "revision-2"); err != nil {
		t.Fatal(err)
	}
	if err = restored.ValidateAuthenticatedSnapshot(v, "revision-2"); !errors.Is(err, ErrExpired) {
		t.Fatal("new revision inherited policy", err)
	}
	_ = restored.BindSnapshotRevision(v.Scope, "revision-1")
	if err = restored.ValidateAuthenticatedSnapshot(v, "revision-1"); !errors.Is(err, ErrExpired) {
		t.Fatal("revision rollback resurrected policy", err)
	}
}

func TestAuthenticatedSnapshotRejectsIncompleteIdentityAndMutation(t *testing.T) {
	for _, scenario := range []string{"missing-policy", "wrong-email", "wrong-key", "wrong-account", "wrong-server", "missing-revision", "invalid-version", "duplicate-quarantine", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			s, v, saved, config := authenticatedSnapshotFixture(t)
			defer s.Close()
			defer clear(saved)
			var body map[string]any
			_ = json.Unmarshal(v.Sync, &body)
			revision := "revision-1"
			scope := v.Scope
			switch scenario {
			case "missing-policy":
				delete(body, "policiesNew")
			case "wrong-email":
				body["profile"].(map[string]any)["email"] = "other@example.invalid"
			case "wrong-key":
				body["profile"].(map[string]any)["key"] = "rotated"
			case "wrong-account":
				body["profile"].(map[string]any)["id"] = "other"
			case "wrong-server":
				v.Scope.Server = "https://other.example.invalid"
			case "missing-revision":
				revision = ""
			case "invalid-version":
				v.Version = 2
			case "duplicate-quarantine":
				v.QuarantinedOrganizations = []string{"org-a", "org-a"}
			}
			v.Sync, _ = json.Marshal(body)
			if scenario == "malformed" {
				v.Sync = []byte(`{"profile":`)
			}
			result, err := RestoreSessionFromAuthenticatedSnapshot(saved, scope, &config, v, revision)
			if err == nil || result != nil {
				t.Fatal("invalid receipt installed partial authority", err)
			}
		})
	}
	s, v, saved, _ := authenticatedSnapshotFixture(t)
	defer s.Close()
	defer clear(saved)
	if err := s.AcceptAuthenticatedSnapshot(v, "r"); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), v.Sync...)
	v.Sync[0] = '['
	if err := s.ValidateAuthenticatedSnapshot(v, "r"); err == nil {
		t.Fatal("mutated bytes retained permission")
	}
	v.Sync = original
	if err := s.ValidateAuthenticatedSnapshot(v, "r"); err != nil {
		t.Fatal("authority aliased caller bytes", err)
	}
	v.QuarantinedOrganizations = []string{"org-a"}
	if err := s.ValidateAuthenticatedSnapshot(v, "r"); err == nil {
		t.Fatal("quarantine change retained permission")
	}
	v.QuarantinedOrganizations = nil
	if err := s.AcceptAuthenticatedSnapshot(v, "new"); err != nil {
		t.Fatal(err)
	}
	s.RevokeItemAuthorizations()
	if err := s.ValidateAuthenticatedSnapshot(v, "new"); !errors.Is(err, ErrExpired) {
		t.Fatal("revocation ignored", err)
	}
	if err := s.AcceptAuthenticatedSnapshot(v, "next"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.ValidateAuthenticatedSnapshot(v, "next"); !errors.Is(err, ErrExpired) {
		t.Fatal("closed session usable", err)
	}
}

func TestSyncPoliciesPrecedeCredentialDecryption(t *testing.T) {
	for _, scenario := range []string{"restricted", "missing-policy", "permitted-corrupt", "type5-corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			body := policySyncFixture(2, 15, []int{1})
			profile := body["profile"].(map[string]any)
			profile["organizationsNew"] = profile["organizations"]
			// The organization is server-disabled: its confirmed policy still
			// restricts personal data, without requiring any organization key.
			body["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)["enabled"] = false
			body["ciphers"] = []any{map[string]any{"id": "login-a", "type": 1, "name": "invalid-ciphertext", "viewPassword": true,
				"login": map[string]any{"username": "invalid-ciphertext", "password": "invalid-ciphertext"}}}
			switch scenario {
			case "missing-policy":
				delete(body, "policiesNew")
			case "permitted-corrupt":
				body["policies"].([]any)[0].(map[string]any)["data"] = []int{3}
			case "type5-corrupt":
				body["policies"].([]any)[0].(map[string]any)["type"] = 5
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/sync" || r.Header.Get("Authorization") != "Bearer access-not-persisted" {
					t.Error("unauthenticated sync")
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			result, err := s.Sync(context.Background())
			defer clear(result.Session)
			if result.PasswordUnlock != nil {
				defer clear(result.PasswordUnlock.Key)
			}
			switch scenario {
			case "restricted":
				if err != nil || len(result.Credentials) != 0 || result.Summary.Restricted != 1 {
					t.Fatal("restricted ciphertext was decrypted", err)
				}
				if err := s.ValidateAuthenticatedSnapshot(result.Vault, "public-result"); !errors.Is(err, ErrExpired) {
					t.Fatal("unpublished sync result created authority", err)
				}
			case "missing-policy":
				if !errors.Is(err, ErrProtocol) {
					t.Fatal("legacy sync did not require policy migration", err)
				}
			default:
				if !errors.Is(err, ErrEncryption) {
					t.Fatal("permitted data did not reach cryptographic validation", err)
				}
			}
		})
	}
}

func TestAuthenticatedSnapshotBoundsAndAmbiguousSession(t *testing.T) {
	s, v, saved, config := authenticatedSnapshotFixture(t)
	defer s.Close()
	defer clear(saved)
	duplicate := append(append([]byte(nil), saved[:len(saved)-1]...), []byte(`,"version":1}`)...)
	defer clear(duplicate)
	if restored, err := RestoreSessionFromAuthenticatedSnapshot(duplicate, v.Scope, &config, v, "r"); !errors.Is(err, ErrProtocol) || restored != nil {
		t.Fatal("ambiguous saved identity accepted", err)
	}
	if err := s.AcceptAuthenticatedSnapshot(v, string(bytes.Repeat([]byte{'r'}, 1025))); !errors.Is(err, ErrExpired) {
		t.Fatal("unbounded revision", err)
	}
	v.QuarantinedOrganizations = make([]string, 1025)
	if err := s.AcceptAuthenticatedSnapshot(v, "r"); !errors.Is(err, ErrProtocol) {
		t.Fatal("unbounded quarantine", err)
	}
	v.QuarantinedOrganizations = nil
	v.Sync = make([]byte, maxResponse+1)
	if err := s.AcceptAuthenticatedSnapshot(v, "r"); !errors.Is(err, ErrProtocol) {
		t.Fatal("unbounded snapshot", err)
	}
}

func TestSyncReplacementRevokesInstalledSnapshot(t *testing.T) {
	for _, scenario := range []string{"success", "missing-policy", "network-failure", "wrong-identity"} {
		t.Run(scenario, func(t *testing.T) {
			body := emptyPolicySyncFixture()
			raw, _ := json.Marshal(body)
			switch scenario {
			case "missing-policy":
				delete(body, "policies")
			case "wrong-identity":
				body["profile"].(map[string]any)["id"] = "other-account"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "network-failure" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			v := &VaultData{Version: 1, Scope: Scope{Server: server.URL, Account: s.account}, Sync: raw}
			if err := s.AcceptAuthenticatedSnapshot(v, "r"); err != nil {
				t.Fatal(err)
			}
			result, err := s.Sync(context.Background())
			defer clear(result.Session)
			if result.PasswordUnlock != nil {
				defer clear(result.PasswordUnlock.Key)
			}
			if (scenario == "success") != (err == nil) {
				t.Fatal("unexpected sync result", err)
			}
			if err := s.ValidateAuthenticatedSnapshot(v, "r"); !errors.Is(err, ErrExpired) {
				t.Fatal("sync retained old capability", err)
			}
		})
	}
}
