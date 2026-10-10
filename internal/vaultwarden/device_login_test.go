// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type deviceLoginFixture struct {
	mu                  sync.Mutex
	row                 authRequestWire
	code                string
	key                 []byte
	raw                 []byte
	wrapped             string
	known, approve, mfa bool
	recoveryChallenge   bool
	tokenHook           func()
	syncHook            func()
	preloginHook        func()
	responseStatus      int
	tokenStatus         int
	grants              int
	epoch               atomic.Uint64
}

func newDeviceLoginFixture(t *testing.T) (*deviceLoginFixture, *Client, Scope) {
	t.Helper()
	key := bytes.Repeat([]byte{19}, 64)
	master, _ := vaultcrypto.DeriveMaster([]byte("fixture-password"), "fixture@example.invalid", vaultcrypto.KDF{Iterations: 5000})
	defer clear(master)
	stretched, _ := vaultcrypto.StretchMaster(master)
	defer clear(stretched)
	wrapped := encryptFixture(key, stretched)
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": "account-a", "email": "fixture@example.invalid", "key": wrapped, "privateKey": encryptFixture(der, key), "organizations": []any{}, "organizationsNew": []any{}}, "ciphers": []any{}, "folders": []any{}, "collections": []any{}, "policies": []any{}, "policiesNew": []any{}})
	f := &deviceLoginFixture{key: key, raw: raw, wrapped: wrapped, known: true, approve: true, tokenStatus: 200}
	f.epoch.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/api/devices/knowndevice":
			if r.Header.Get("X-Request-Email") != base64.RawURLEncoding.EncodeToString([]byte("fixture@example.invalid")) || r.Header.Get("X-Device-Identifier") == "" {
				t.Error("known device headers")
			}
			json.NewEncoder(w).Encode(f.known)
		case "/api/auth-requests":
			var body struct{ PublicKey, AccessCode string }
			json.NewDecoder(r.Body).Decode(&body)
			f.code = body.AccessCode
			f.row = authRequestWire{AuthRequest: AuthRequest{ID: "b6d98b09-e6b1-42b0-93f1-d7f77aab9543", PublicKey: body.PublicKey}}
			json.NewEncoder(w).Encode(f.row)
		case "/api/auth-requests/b6d98b09-e6b1-42b0-93f1-d7f77aab9543/response":
			if f.responseStatus != 0 {
				w.WriteHeader(f.responseStatus)
				return
			}
			if r.URL.Query().Get("code") != f.code {
				t.Error("code mismatch")
			}
			if f.approve && f.row.Key == nil {
				public, e := parseMemberPublicKey(f.row.PublicKey)
				if e != nil {
					t.Error(e)
					return
				}
				encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, f.key, nil)
				wrapped := "3." + base64.StdEncoding.EncodeToString(encrypted)
				date := "2026-01-01T00:00:00Z"
				approved := true
				f.row.Key = &wrapped
				f.row.ResponseDate = &date
				f.row.RequestApproved = &approved
			}
			json.NewEncoder(w).Encode(f.row)
		case "/identity/connect/token":
			f.grants++
			if f.tokenHook != nil {
				f.tokenHook()
			}
			r.ParseForm()
			if r.Header.Get("Authorization") != "" || r.Form.Get("grant_type") != "password" || r.Form.Get("password") != f.code || r.Form.Get("authrequest") != f.row.ID {
				t.Error("real authrequest grant contract")
			}
			if f.mfa && (r.Form.Get("twoFactorToken") == "" || (f.recoveryChallenge && r.Form.Get("twoFactorProvider") == "8")) {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"twoFactorProviders2":{"0":{}}}`)
				return
			}
			w.WriteHeader(f.tokenStatus)
			if f.tokenStatus != 200 {
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "refresh_token": "refresh", "expires_in": 3600, "token_type": "Bearer", "key": f.wrapped})
		case "/api/sync":
			if f.syncHook != nil {
				f.syncHook()
			}
			if r.Header.Get("Authorization") != "Bearer access" {
				t.Error("wrong bearer")
			}
			w.Write(f.raw)
		case "/identity/accounts/prelogin":
			if f.preloginHook != nil {
				f.preloginHook()
			}
			fmt.Fprint(w, `{"kdf":0,"kdfIterations":5000}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(srv.URL, "fixture-device-id")
	return f, c, Scope{Server: srv.URL, Account: "account-a"}
}
func (f *deviceLoginFixture) check(_ Scope, epoch uint64) error {
	if f.epoch.Load() != epoch {
		return ErrExpired
	}
	return nil
}
func TestDeviceLoginGrantMFAKeyAndPasswordBinding(t *testing.T) {
	f, c, scope := newDeviceLoginFixture(t)
	f.mfa = true
	flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	result, e := flow.Run(func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
		if ch.SendEmail != nil || ch.Providers["0"] == nil {
			t.Error("MFA metadata")
		}
		return MFAResponse{Provider: 0, Token: []byte("123456")}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if result.Sync.Scope != scope || result.Sync.PasswordUnlock != nil || len(result.Sync.Session) != 0 || !result.RequiresPasswordForSessionPersistence {
		t.Fatal("fabricated persistent wrapper")
	}
	if _, e = flow.Run(nil); e != ErrConflict {
		t.Fatal("replayed")
	}
	if e = flow.BindPassword(context.Background(), []byte("incorrect")); e == nil {
		t.Fatal("wrong password bound")
	}
	if e = flow.BindPassword(context.Background(), []byte("fixture-password")); e != nil {
		t.Fatal(e)
	}
	synced, e := result.Session.Sync(context.Background())
	if e != nil || synced.PasswordUnlock == nil || len(synced.Session) == 0 {
		t.Fatal("bound snapshot", e)
	}
	restored, e := RestoreSession(synced.Session, scope, &synced.PasswordUnlock.Config)
	if e != nil {
		t.Fatal(e)
	}
	restored.Close()
	clear(synced.Session)
	clear(synced.PasswordUnlock.Key)
	flow.Close()
	if _, e = result.Session.Sync(context.Background()); e == nil {
		t.Fatal("closed login resurrected")
	}
	if f.grants != 2 {
		t.Fatal("expected challenge plus one grant", f.grants)
	}
}
func TestDeviceLoginIdentityUnknownAndUncertain(t *testing.T) {
	for _, mode := range []string{"unknown", "account", "key", "uncertain", "epoch", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f, c, scope := newDeviceLoginFixture(t)
			if mode == "unknown" {
				f.known = false
			}
			if mode == "account" {
				scope.Account = "other"
			}
			if mode == "key" {
				f.key = bytes.Repeat([]byte{20}, 64)
			}
			if mode == "uncertain" {
				f.tokenStatus = 500
			}
			flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
			if mode == "unknown" {
				if e != ErrDeviceUnknown {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer flow.Close()
			if mode == "epoch" {
				f.epoch.Store(2)
			}
			if mode == "cancel" {
				flow.Close()
			}
			_, e = flow.Run(nil)
			if e == nil {
				t.Fatal("accepted unsafe result")
			}
			if mode == "uncertain" {
				var uncertain *MutationUncertainError
				if !errors.As(e, &uncertain) {
					t.Fatal("unknown source lost", e)
				}
				if f.grants != 1 {
					t.Fatal("retried uncertain grant")
				}
			}
		})
	}
}
func TestDeviceLoginRecoverySurvivesFailure(t *testing.T) {
	for _, mode := range []string{"unconfirmed", "invalid", "cancel-before", "http", "disconnect", "cancel-dispatched", "identity", "private-key", "sync", "lifecycle", "provider-switch"} {
		t.Run(mode, func(t *testing.T) {
			f, c, scope := newDeviceLoginFixture(t)
			f.mfa = true
			f.recoveryChallenge = mode == "provider-switch"
			flow, err := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			want := DeviceLoginRecoveryConfirmed
			if mode == "unconfirmed" || mode == "invalid" || mode == "cancel-before" {
				want = DeviceLoginRecoveryNotSubmitted
			}
			if mode == "http" || mode == "disconnect" || mode == "cancel-dispatched" || mode == "provider-switch" {
				want = DeviceLoginRecoverySubmitted
			}
			f.tokenHook = func() {
				if f.grants != 2 {
					return
				}
				switch mode {
				case "http":
					f.tokenStatus = 500
				case "cancel-dispatched":
					flow.Close()
				}
			}
			if mode == "disconnect" {
				base := c.http.Transport
				c.http.Transport = deviceLoginRecoveryTransport{base: base}
			}
			f.syncHook = func() {
				switch mode {
				case "identity", "provider-switch":
					f.raw = bytes.Replace(f.raw, []byte("account-a"), []byte("account-b"), 1)
				case "private-key":
					f.raw = bytes.Replace(f.raw, []byte("privateKey"), []byte("absentKey"), 1)
				case "sync":
					f.raw = []byte(`{}`)
				case "lifecycle":
					f.epoch.Store(2)
				}
			}
			prompts := 0
			result, err := flow.Run(func(context.Context, MFAChallenge) (MFAResponse, error) {
				prompts++
				if mode == "provider-switch" && prompts == 2 {
					return MFAResponse{Provider: 0, Token: []byte("123456")}, nil
				}
				if mode == "cancel-before" {
					flow.Close()
				}
				r := MFAResponse{Provider: 8, Token: []byte("fixture-recovery"), ConfirmRemoveAllMFA: mode != "unconfirmed"}
				if mode == "invalid" {
					r.Token = nil
				}
				return r, nil
			})
			if err == nil {
				t.Fatal("unsafe login accepted")
			}
			if mode == "identity" && !errors.Is(err, ErrIdentity) {
				t.Fatal("identity error lost", err)
			}
			if result.Recovery.State != want || result.RemovedAllMFA != (want == DeviceLoginRecoveryConfirmed) {
				t.Fatalf("side effect lost: %+v, err %v", result.Recovery, err)
			}
			if result.Recovery.Scope != scope || result.Recovery.Epoch != 1 || result.Recovery.RequestID != flow.Metadata().ID || result.Recovery.DeviceID != c.deviceID {
				t.Fatal("attempt binding lost")
			}
			if result.Session != nil || result.Sync.Vault != nil || result.RememberToken != "" {
				t.Fatal("failed result contains session/secrets")
			}
			if flow.session != nil {
				if _, e := flow.session.Sync(context.Background()); e == nil {
					t.Fatal("failed session remains live")
				}
			}
			again, e := flow.Run(nil)
			if !errors.Is(e, ErrConflict) || again.Recovery.State != want {
				t.Fatal("replay or metadata regression")
			}
		})
	}
}

type deviceLoginRecoveryTransport struct{ base http.RoundTripper }

func (tr deviceLoginRecoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/identity/connect/token" {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte("twoFactorProvider=8")) {
			return nil, errors.New("fixture disconnect")
		}
	}
	if tr.base == nil {
		return http.DefaultTransport.RoundTrip(r)
	}
	return tr.base.RoundTrip(r)
}

func TestDeviceLoginRecoveryMonotonicAcrossProviders(t *testing.T) {
	f, c, scope := newDeviceLoginFixture(t)
	flow, err := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	// A later provider or failure cannot demote a recorded side effect.
	flow.recordRecovery(DeviceLoginRecoveryConfirmed)
	flow.recordRecovery(DeviceLoginRecoverySubmitted)
	flow.Close()
	r, _ := flow.Run(nil)
	if !r.RemovedAllMFA || r.Recovery.State != DeviceLoginRecoveryConfirmed {
		t.Fatal("recovery regressed")
	}
}

func TestDeviceLoginPollingCancellationRace(t *testing.T) {
	f, c, scope := newDeviceLoginFixture(t)
	f.approve = false
	flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := flow.Run(nil); done <- e }()
	flow.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled flow accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel did not terminate polling")
	}
}
