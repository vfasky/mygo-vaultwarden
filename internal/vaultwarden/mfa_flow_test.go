// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMFAProviderWireAndCancellation(t *testing.T) {
	for _, provider := range []int{0, 1, 2, 3, 7, 8} {
		t.Run(strconv.Itoa(provider), func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "prelogin") {
					w.Write([]byte(`{"kdf":0,"kdfIterations":100000}`))
					return
				}
				r.ParseForm()
				posts++
				if r.Form.Get("password") == "raw-password" {
					t.Error("raw password sent")
				}
				if posts > 1 {
					if r.Form.Get("twoFactorProvider") != strconv.Itoa(provider) || r.Form.Get("twoFactorToken") != "response" {
						t.Error("provider response mismatch")
					}
				}
				w.WriteHeader(400)
				fmt.Fprintf(w, `{"twoFactorProviders2":{"%d":{}}}`, provider)
			}))
			defer server.Close()
			c, _ := NewClient(server.URL, "test-device-identifier")
			prompts := 0
			_, e := c.LoginMFA(context.Background(), "test@example.invalid", []byte("raw-password"), "", func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
				prompts++
				if prompts > 1 {
					return MFAResponse{}, context.Canceled
				}
				return MFAResponse{Provider: provider, Token: []byte("response"), ConfirmRemoveAllMFA: provider == 8}, nil
			})
			if !errors.Is(e, ErrCancelled) || posts != 2 {
				t.Fatal("wire/cancel", e, posts)
			}
		})
	}
}
func TestDuoCorrelation(t *testing.T) {
	state := "server-issued-state-123456789"
	payload := base64.RawURLEncoding.EncodeToString(mfaJSON(map[string]string{"state": state, "redirect_uri": "https://vault.example/base/duo-redirect-connector.html?client=desktop"}))
	authURL := "https://api-123.duosecurity.com/oauth/v1/authorize?request=" + "e30." + payload + ".signature"
	f, e := NewDuoFlow("https://vault.example/base", authURL, 7)
	if e != nil {
		t.Fatal(e)
	}
	callback := "bitwarden://duo-callback?" + url.Values{"state": {state}, "code": {"authorization-code"}}.Encode()
	for _, bad := range []string{callback + "&state=duplicate", strings.Replace(callback, "duo-callback", "sso-callback", 1), callback + "#x", strings.Replace(callback, "state=", "state=wrong", 1)} {
		if _, e = f.Complete(bad, 7); e == nil {
			t.Fatal("accepted attack")
		}
	}
	token, e := f.Complete(callback, 7)
	if e != nil || string(token) != "authorization-code|"+state {
		t.Fatal(e)
	}
	clear(token)
	if _, e = f.Complete(callback, 7); e == nil {
		t.Fatal("replay")
	}
	if _, e = NewDuoFlow("https://vault.example/base", strings.Replace(authURL, "api-123.duosecurity.com", "evil.invalid", 1), 7); e == nil {
		t.Fatal("evil origin")
	}
}
func TestSSOCloseCancelsExchange(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "prevalidate") {
			w.Write([]byte(`{"token":"sso"}`))
			return
		}
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	c, _ := NewClient(server.URL, "test-device-identifier")
	f, _, e := c.BeginSSO(context.Background(), "bitwarden://sso-callback", 1)
	if e != nil {
		t.Fatal(e)
	}
	callback := "bitwarden://sso-callback?" + url.Values{"state": {f.state}, "code": {"code"}, "iss": {server.URL}}.Encode()
	result := make(chan error, 1)
	go func() { _, e := f.Exchange(context.Background(), callback, 1); result <- e }()
	<-started
	f.Close()
	select {
	case e := <-result:
		if !errors.Is(e, ErrCancelled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel timeout")
	}
}
func TestMFAManagementUnknownFailure(t *testing.T) {
	s, _ := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) { w.WriteHeader(500) })
	_, e := s.MFAManage(context.Background(), MFADisable, AccountSensitiveInput{OTP: "protected"}, map[string]json.RawMessage{"type": mfaJSON(0)}, true, nil)
	var unknown *MutationUncertainError
	if !errors.As(e, &unknown) {
		t.Fatal("must not imply rollback", e)
	}
}
