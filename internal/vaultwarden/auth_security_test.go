// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

func TestOnlinePreloginRejectsWeakKDF(t *testing.T) {
	for _, iterations := range []int{5000, 99999} {
		t.Run(fmt.Sprint(iterations), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path != "/identity/accounts/prelogin" {
					t.Errorf("password proof request reached %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(vaultcrypto.KDF{Iterations: iterations})
			}))
			defer server.Close()
			c, _ := NewClient(server.URL, fixtureUUID())
			ctx := context.Background()
			for name, run := range map[string]func() error{
				"login": func() error { _, err := c.Login(ctx, "a@example.invalid", []byte("fixture-password"), nil); return err },
				"mfa": func() error {
					_, err := c.LoginMFA(ctx, "a@example.invalid", []byte("fixture-password"), "", nil)
					return err
				},
				"device-bind": func() error {
					scope := Scope{Server: server.URL, Account: "fixture-account"}
					flow := &DeviceLogin{ctx: ctx, client: c, scope: scope, email: "a@example.invalid", ready: true,
						check:   func(Scope, uint64) error { return nil },
						session: &Session{account: scope.Account}}
					return flow.BindPassword(ctx, []byte("fixture-password"))
				},
				"runtime": func() error {
					_, err := runtimePasswordKey(ctx, c, "a@example.invalid", "wrapped", []byte("fixture-password"))
					return err
				},
				"sso": func() error {
					_, err := c.UnlockSSOVault(ctx, json.RawMessage(`{"access_token":"access","refresh_token":"refresh","expires_in":3600,"token_type":"Bearer","key":"wrapped"}`), "a@example.invalid", []byte("fixture-password"))
					return err
				},
			} {
				before := requests
				if err := run(); !errors.Is(err, ErrWeakKDF) || requests != before+1 {
					t.Fatalf("%s: %v; requests %d", name, err, requests-before)
				}
			}
		})
	}
}

func TestLoginHTTPStatusClassification(t *testing.T) {
	for _, phase := range []string{"prelogin", "token"} {
		for _, status := range []int{403, 429, 500, 503} {
			t.Run(fmt.Sprintf("%s/%d", phase, status), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if phase == "token" && strings.HasSuffix(r.URL.Path, "prelogin") {
						_ = json.NewEncoder(w).Encode(vaultcrypto.KDF{Iterations: 100000})
						return
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte("secret response body"))
				}))
				defer server.Close()
				c, _ := NewClient(server.URL, fixtureUUID())
				_, err := c.Login(context.Background(), "a@example.invalid", []byte("fixture-password"), nil)
				if !errors.Is(err, statusError(status)) {
					t.Fatalf("Login: %v", err)
				}
				_, err = c.LoginMFA(context.Background(), "a@example.invalid", []byte("fixture-password"), "", nil)
				if !errors.Is(err, statusError(status)) {
					t.Fatalf("LoginMFA: %v", err)
				}
			})
		}
	}
}

func TestNewAccountArgonMemoryBounds(t *testing.T) {
	for _, memory := range []int{15, 16, 256, 257, 1024, 1025} {
		err := accountNewKDF(vaultcrypto.KDF{Type: 1, Iterations: 2, Memory: memory, Parallelism: 1})
		if (err == nil) != (memory >= 16 && memory <= 1024) {
			t.Fatalf("memory %d: %v", memory, err)
		}
	}
}

func TestErrorMessageIdentityLocalizationAndSafety(t *testing.T) {
	defer i18n.Set(i18n.Current())
	identity := ErrWeakKDF.Error()
	if ErrWeakKDF != vaulterr.ErrWeakKDF || errors.Is(ErrWeakKDF, ErrKDF) {
		t.Fatal("weak KDF must be a distinct shared sentinel")
	}
	for _, lang := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(lang)
		wrapped := fmt.Errorf("secret wrapper: %w", ErrWeakKDF)
		message := ErrorMessage(wrapped)
		if !errors.Is(wrapped, ErrWeakKDF) || ErrWeakKDF.Error() != identity || strings.Contains(message, "secret") || !strings.Contains(message, "100000") {
			t.Fatalf("identity or display: %q", message)
		}
		if lang == i18n.English && !strings.Contains(message, "trusted official client") {
			t.Fatalf("untranslated: %s", message)
		}
		if got := ErrorMessage(errors.New("secret URL/token")); strings.Contains(got, "secret") || got == "" {
			t.Fatal("unsafe fallback")
		}
		uncertain := &MutationUncertainError{Cause: ErrNetwork}
		if ErrorMessage(fmt.Errorf("private: %w", uncertain)) != uncertain.Error() {
			t.Fatal("lost uncertain-write warning")
		}
		upload := &SendUploadError{Cause: ErrNetwork}
		if ErrorMessage(upload) != upload.Error() {
			t.Fatal("lost upload warning")
		}
	}
	if ErrorMessage(nil) != "" {
		t.Fatal("nil error has a message")
	}
}
