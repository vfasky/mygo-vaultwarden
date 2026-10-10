// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func mfaJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func TestMFAManageProofAndEndpoint(t *testing.T) {
	calls := 0
	s, _ := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
		calls++
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["masterPasswordHash"] != nil || body["otp"] != "protected-code" {
			t.Error("incorrect proof")
		}
		if r.URL.Path != "/api/two-factor/get-authenticator" {
			t.Error(r.URL.Path)
		}
		w.Write([]byte(`{"key":"secret"}`))
	})
	ctx := context.Background()
	if _, e := s.MFAManage(ctx, "get-authenticator", AccountSensitiveInput{OTP: "protected-code"}, nil, false, nil); e != nil {
		t.Fatal(e)
	}
	for _, op := range []MFAManageOperation{"../../accounts", "disable", "delete-webauthn"} {
		if _, e := s.MFAManage(ctx, op, AccountSensitiveInput{OTP: "protected-code"}, nil, false, nil); e == nil {
			t.Fatal("accepted", op)
		}
	}
	if _, e := s.MFAManage(ctx, "get-authenticator", AccountSensitiveInput{OTP: "protected-code"}, map[string]json.RawMessage{"masterPasswordHash": mfaJSON("injected")}, false, nil); e == nil {
		t.Fatal("injected proof")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
func TestSSOCallbackBinding(t *testing.T) {
	exchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "prevalidate") {
			w.Write([]byte(`{"token":"discovery"}`))
			return
		}
		exchanges++
		r.ParseForm()
		if len(r.Form.Get("code_verifier")) != 43 {
			t.Error("PKCE")
		}
		w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	c, _ := NewClient(server.URL, "test-device-identifier")
	f, authorize, e := c.BeginSSO(context.Background(), "bitwarden://sso-callback", 7)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(authorize)
	q := u.Query()
	h := sha256.Sum256([]byte(f.verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(h[:]) {
		t.Fatal("challenge")
	}
	callback := "bitwarden://sso-callback?" + url.Values{"state": {q.Get("state")}, "code": {"code"}, "iss": {server.URL}}.Encode()
	for _, bad := range []string{strings.Replace(callback, "sso-callback", "attacker", 1), callback + "&state=evil", strings.Replace(callback, "state=", "state=x", 1), callback + "#fragment", strings.Replace(callback, url.QueryEscape(server.URL), "https%3A%2F%2Fevil.invalid", 1)} {
		if _, e = f.Exchange(context.Background(), bad, 7); e == nil {
			t.Fatal("accepted bad callback")
		}
	}
	if _, e = f.Exchange(context.Background(), callback, 8); e == nil {
		t.Fatal("epoch")
	}
	if _, e = f.Exchange(context.Background(), callback, 7); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Exchange(context.Background(), callback, 7); e == nil {
		t.Fatal("replay")
	}
	if exchanges != 1 {
		t.Fatal(exchanges)
	}
	f, _, _ = c.BeginSSO(context.Background(), "bitwarden://sso-callback", 7)
	f.Close()
	if _, e = f.Exchange(context.Background(), callback, 7); e == nil {
		t.Fatal("cancel")
	}
}
func TestWebAuthnOriginReplay(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	id := base64.RawURLEncoding.EncodeToString([]byte("credential"))
	hash := sha256.Sum256([]byte("vault.example"))
	auth := append(hash[:], 1, 0, 0, 0, 0)
	makeResponse := func(origin string, cross bool) json.RawMessage {
		return mfaJSON(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": map[string]string{"clientDataJSON": base64.RawURLEncoding.EncodeToString(mfaJSON(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": cross})), "authenticatorData": base64.RawURLEncoding.EncodeToString(auth), "signature": "AQ"}})
	}
	b, e := NewWebAuthnBinding("https://vault.example/path", "vault.example", challenge, false, []string{id}, 9)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []json.RawMessage{makeResponse("https://evil.example", false), makeResponse("https://vault.example", true)} {
		if b.Validate(raw, 9) == nil {
			t.Fatal("cross origin")
		}
	}
	good := makeResponse("https://vault.example", false)
	if b.Validate(good, 8) == nil {
		t.Fatal("epoch")
	}
	if e = b.Validate(good, 9); e != nil {
		t.Fatal(e)
	}
	if b.Validate(good, 9) == nil {
		t.Fatal("replay")
	}
}
func mfaTOTP(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
	defer clear(key)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(counter[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func TestLiveMFA(t *testing.T) {
	server := os.Getenv("MYGO_MFA_TEST_URL")
	if server == "" {
		t.Skip("requires isolated 1.37.4 fixture")
	}
	if !strings.HasPrefix(server, "http://127.0.0.1:") {
		t.Fatal("non-loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c, _ := NewClient(server, fixtureUUID())
	email := "mfa-" + fixtureUUID() + "@example.invalid"
	password := []byte("Mfa-test-primary-passphrase-852!")
	defer clear(password)
	verification, e := c.AccountSendRegistrationEmail(ctx, email, "")
	if e != nil {
		t.Fatal(e)
	}
	if verification.EmailSent {
		t.Fatal("registration needs token fixture")
	}
	if e = c.AccountRegister(ctx, email, password, vaultcrypto.KDF{Type: 0, Iterations: 100000}, "", verification.Token); e != nil {
		t.Fatal(e)
	}
	s, e := c.Login(ctx, email, password, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	persist := func(SessionCheckpoint) error { return nil }
	proof := AccountSensitiveInput{Password: password}
	setup, e := s.MFAManage(ctx, "get-authenticator", proof, nil, false, persist)
	if e != nil {
		t.Fatal(e)
	}
	var config struct {
		Key string `json:"key"`
	}
	json.Unmarshal(setup, &config)
	if config.Key == "" {
		t.Fatal("no TOTP key")
	}
	_, e = s.MFAManage(ctx, "authenticator", proof, map[string]json.RawMessage{"key": mfaJSON(config.Key), "token": mfaJSON(mfaTOTP(config.Key))}, true, persist)
	if e != nil {
		t.Fatal("enable", e)
	}
	recovery, e := s.MFAManage(ctx, MFARecovery, proof, nil, true, persist)
	if e != nil {
		t.Fatal(e)
	}
	var recoverData struct {
		Code string `json:"code"`
	}
	json.Unmarshal(recovery, &recoverData)
	if recoverData.Code == "" {
		t.Fatal("no recovery code")
	}
	// Avoid replaying the enrollment timestep; login should reject a bogus OTP.
	attempts := 0
	_, e = c.LoginMFA(ctx, email, password, "", func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
		attempts++
		return MFAResponse{Provider: 0, Token: []byte("000000")}, nil
	})
	if e == nil || attempts == 0 {
		t.Fatal("bad OTP accepted")
	}
	// Enrollment consumes the current TOTP timestep; wait for a fresh one.
	timer := time.NewTimer(time.Duration(31-time.Now().Unix()%30) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	totpResult, e := c.LoginMFA(ctx, email, password, "", func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
		return MFAResponse{Provider: 0, Token: []byte(mfaTOTP(config.Key)), Remember: true}, nil
	})
	if e != nil {
		t.Fatal("TOTP login", e)
	}
	totpResult.Session.Close()
	if totpResult.RememberToken == "" {
		t.Fatal("missing remember token")
	}
	remembered, e := c.LoginMFA(ctx, email, password, totpResult.RememberToken, nil)
	if e != nil {
		t.Fatal("remembered login", e)
	}
	remembered.Session.Close()
	// Recovery is an explicitly destructive login, not an ordinary backup OTP.
	result, e := c.LoginMFA(ctx, email, password, "", func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
		return MFAResponse{Provider: 8, Token: []byte(recoverData.Code), ConfirmRemoveAllMFA: true}, nil
	})
	if e != nil {
		t.Fatal("recovery", e)
	}
	defer result.Session.Close()
	if !result.RemovedAllMFA {
		t.Fatal("missing side effect")
	}
	listed, e := result.Session.MFAManage(ctx, MFAList, AccountSensitiveInput{}, nil, false, persist)
	if e != nil {
		t.Fatal(e)
	}
	var list struct {
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(listed, &list) != nil || len(list.Data) != 0 {
		t.Fatal("recovery did not remove MFA")
	}
	plain, e := c.Login(ctx, email, password, nil)
	if e != nil {
		t.Fatal("plain login after recovery", e)
	}
	plain.Close()
}
