// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func resumableFixture(t *testing.T, server string) (*Session, PasswordUnlockConfig) {
	t.Helper()
	client, err := NewClient(server, fixtureUUID())
	if err != nil {
		t.Fatal(err)
	}
	config := PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: KDF{Type: 0, Iterations: 5000}}
	return &Session{client: client, email: config.Email, account: "account-a", key: bytes.Repeat([]byte{42}, 64),
		wrapped: "fixture-wrapped-user-key", refresh: "refresh-old", access: "access-not-persisted", expires: time.Now().Add(time.Hour),
		passwordUnlock: &PasswordUnlock{Config: config, Key: bytes.Repeat([]byte{7}, 32)}}, config
}

func TestSavedSessionRoundTripBindsScopeAndClearsSource(t *testing.T) {
	original, config := resumableFixture(t, "https://vault.example.invalid")
	data, err := original.savedLocked()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if bytes.Contains(data, []byte(original.access)) || bytes.Contains(data, []byte("fixture-master-password")) {
		t.Fatal("unnecessary secret persisted")
	}
	scope := Scope{Server: original.client.base.String(), Account: original.account}
	original.Close()
	restored, err := RestoreSession(data, scope, &config)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	clear(data)
	if restored.refresh != "refresh-old" || restored.account != scope.Account || restored.access != "" || !restored.expires.IsZero() || len(restored.key) != 64 || restored.passwordUnlock.Key[0] != 7 {
		t.Fatal("saved session did not restore independently of its input buffer")
	}
}

func TestSavedSessionRejectsSubstitutionAndMalformedMaterial(t *testing.T) {
	for _, scenario := range []string{"server", "account", "email", "config", "version", "key", "wrapper", "missing-refresh", "device", "malformed", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			session, config := resumableFixture(t, "https://vault.example.invalid")
			defer session.Close()
			data, _ := session.savedLocked()
			defer clear(data)
			var state savedSession
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			scope := state.Scope
			switch scenario {
			case "server":
				state.Scope.Server = "https://other.example.invalid"
			case "account":
				state.Scope.Account = "account-b"
			case "email":
				state.Email = "other@example.invalid"
			case "config":
				config.KDF.Iterations++
			case "version":
				state.Version++
			case "key":
				state.UserKey = []byte{1}
			case "wrapper":
				state.PasswordUnlock = nil
			case "missing-refresh":
				state.RefreshToken = ""
			case "device":
				state.DeviceID = "short"
			}
			encoded, _ := json.Marshal(state)
			defer clear(encoded)
			if scenario == "malformed" {
				encoded = []byte("not-json")
			}
			if scenario == "oversized" {
				encoded = bytes.Repeat([]byte{1}, 64*1024+1)
			}
			if restored, err := RestoreSession(encoded, scope, &config); err == nil || restored != nil {
				t.Fatal("invalid saved session accepted")
			}
		})
	}
}

func TestRestoredSessionRefreshesAndPersistsBeforeSyncIncludingNetworkFailure(t *testing.T) {
	var refreshes, syncs atomic.Int32
	var persisted atomic.Bool
	var failSync atomic.Bool
	failSync.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			n := refreshes.Add(1)
			_ = r.ParseForm()
			want := "refresh-old"
			if n > 1 {
				want = "refresh-new"
			}
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != want {
				t.Error("wrong restored refresh token")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/sync":
			syncs.Add(1)
			if !persisted.Load() || r.Header.Get("Authorization") != "Bearer access-new" {
				t.Error("sync preceded durable refresh checkpoint")
			}
			if failSync.Load() {
				w.WriteHeader(503)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]string{"id": "account-a", "email": "fixture@example.invalid", "key": "fixture-wrapped-user-key"}, "ciphers": []any{}})
		default:
			t.Error("restoration attempted a password login")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	original, config := resumableFixture(t, server.URL)
	data, _ := original.savedLocked()
	defer clear(data)
	original.Close()
	scope := Scope{Server: server.URL, Account: "account-a"}
	restored, err := RestoreSession(data, scope, &config)
	if err != nil {
		t.Fatal(err)
	}
	var disk, borrowed, borrowedKey []byte
	persist := func(checkpoint SessionCheckpoint) error {
		if checkpoint.Scope != scope || len(checkpoint.UnlockKey) != 32 {
			t.Fatal("checkpoint lost snapshot identity")
		}
		disk = append(disk[:0], checkpoint.Session...)
		borrowed, borrowedKey = checkpoint.Session, checkpoint.UnlockKey
		persisted.Store(true)
		return nil
	}
	if _, err := restored.SyncWithCheckpoint(context.Background(), persist); err != ErrNetwork {
		t.Fatal("expected transient download failure")
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || !bytes.Equal(borrowedKey, make([]byte, len(borrowedKey))) {
		t.Fatal("checkpoint buffers retained secrets")
	}
	restored.Close()
	failSync.Store(false)
	restored, err = RestoreSession(disk, scope, &config)
	clear(disk)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	result, err := restored.SyncWithCheckpoint(context.Background(), persist)
	defer clear(result.Session)
	defer clear(disk)
	if result.PasswordUnlock != nil {
		defer clear(result.PasswordUnlock.Key)
	}
	if err != nil || result.Scope != scope || len(result.Session) == 0 || refreshes.Load() != 2 || syncs.Load() != 2 {
		t.Fatal("restart after transient failure lost the refreshed session")
	}
}

func TestRefreshCheckpointFailureStopsDownloadAndIsRetried(t *testing.T) {
	var refreshes, syncs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 3600, "token_type": "Bearer"})
			return
		}
		syncs.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"profile": map[string]string{"id": "account-a", "email": "fixture@example.invalid", "key": "fixture-wrapped-user-key"}, "ciphers": []any{}})
	}))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	session.expires = time.Time{}
	blocked := errors.New("checkpoint revoked")
	if _, err := session.SyncWithCheckpoint(context.Background(), func(SessionCheckpoint) error { return blocked }); !errors.Is(err, blocked) || syncs.Load() != 0 {
		t.Fatal("download continued after failed credential persistence")
	}
	called := false
	result, err := session.SyncWithCheckpoint(context.Background(), func(SessionCheckpoint) error { called = true; return nil })
	defer clear(result.Session)
	if result.PasswordUnlock != nil {
		defer clear(result.PasswordUnlock.Key)
	}
	if err != nil || !called || refreshes.Load() != 1 || syncs.Load() != 1 {
		t.Fatal("failed checkpoint was skipped or refresh repeated")
	}
}

func TestExpiredRefreshRequiresLoginWithoutSync(t *testing.T) {
	var syncs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			syncs.Add(1)
		}
		w.WriteHeader(401)
	}))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	session.expires = time.Time{}
	if _, err := session.SyncWithCheckpoint(context.Background(), func(SessionCheckpoint) error { t.Fatal("invalid refresh persisted"); return nil }); err != ErrExpired || syncs.Load() != 0 {
		t.Fatal("expired login remained usable")
	}
}
