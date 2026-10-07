// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountRegistrationProtocolAndLocalKeys(t *testing.T) {
	password := []byte("Registration-Fixture-726!")
	kdf := KDF{Type: 0, Iterations: 100000}
	email := "register@example.invalid"
	finishes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/accounts/register/send-verification-email":
			if r.Header.Get("Accept") != "application/json" {
				t.Error("JSON Accept missing")
			}
			_, _ = w.Write([]byte(`"verification-token"`))
		case "/identity/accounts/register/finish":
			finishes++
			var body struct {
				Email string
				KDF
				MasterPasswordHash, Key, EmailVerificationToken string
				Keys                                            organizationKeyPair
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Fatal("bad register body")
			}
			master, _ := DeriveMaster(password, email, kdf)
			defer clear(master)
			stretched, _ := StretchMaster(master)
			defer clear(stretched)
			if body.Email != email || body.EmailVerificationToken != "verification-token" || body.MasterPasswordHash != AuthorizationHash(master, password) {
				t.Error("invalid registration DTO")
			}
			key, err := DecryptString(body.Key, stretched)
			if err != nil || len(key) != 64 {
				t.Error("invalid user key")
				return
			}
			defer clear(key)
			private, err := DecryptString(body.Keys.EncryptedPrivateKey, key)
			if err != nil {
				t.Error(err)
				return
			}
			defer clear(private)
			if _, err = x509.ParsePKCS8PrivateKey(private); err != nil {
				t.Error(err)
			}
			public, _ := base64.StdEncoding.DecodeString(body.Keys.PublicKey)
			if _, err = x509.ParsePKIXPublicKey(public); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("old or wrong registration endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "register-device-1234")
	r, err := client.AccountSendRegistrationEmail(context.Background(), " Register@example.invalid ", "Fixture")
	if err != nil || r.Token == "" || r.EmailSent {
		t.Fatal(err)
	}
	if err = client.AccountRegister(context.Background(), email, password, kdf, "hint", r.Token); err != nil || finishes != 1 {
		t.Fatal(err)
	}
	if err = client.AccountRegister(context.Background(), email, password, KDF{Type: 1, Iterations: 2, Memory: 999999, Parallelism: 1}, "", r.Token); err == nil || finishes != 1 {
		t.Fatal("resource limit missing")
	}
}
func TestAccountRegistrationSMTPAndCancellation(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	defer server.Close()
	client, _ := NewClient(server.URL, "register-device-1234")
	r, err := client.AccountSendRegistrationEmail(context.Background(), "a@example.invalid", "Name")
	if err != nil || !r.EmailSent || r.Token != "" {
		t.Fatal("SMTP result ambiguous")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = client.AccountRegister(ctx, "a@example.invalid", bytes.Repeat([]byte("a"), 12), KDF{Type: 0, Iterations: 100000}, "", "token"); err == nil || calls != 1 {
		t.Fatal("cancel sent request")
	}
}
