// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrgAPIKeyOwnerConsentAndSecretLifetime(t *testing.T) {
	var calls atomic.Int32
	var expected string
	rotate := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		path := "/api/organizations/org-1/api-key"
		if rotate {
			path = "/api/organizations/org-1/rotate-api-key"
		}
		if r.Method != "POST" || r.URL.Path != path {
			t.Error("wrong key route")
		}
		var body struct{ MasterPasswordHash string }
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.MasterPasswordHash != expected {
			t.Error("password proof")
		}
		_, _ = w.Write([]byte(`{"object":"apiKey","apiKey":"fixture-secret","revisionDate":"2026-06-02T00:00:00Z"}`))
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	source, _, _ := protectedItemFixture(t, server.URL)
	defer source.Close()
	s.passwordUnlock = &PasswordUnlock{Config: source.passwordUnlock.Config, Key: append([]byte(nil), source.passwordUnlock.Key...)}
	password := []byte("test-master")
	master, err := DeriveMaster(password, s.passwordUnlock.Config.Email, s.passwordUnlock.Config.KDF)
	if err != nil {
		t.Fatal(err)
	}
	expected = AuthorizationHash(master, password)
	clear(master)
	consume := func(_ string, _ []byte, _ time.Time) error { t.Fatal("unauthorized key exposed"); return nil }
	if err := s.WithOrganizationAPIKey(context.Background(), v, "org-1", password, false, true, consume, nil); err != ErrPermission {
		t.Fatal(err)
	}
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = 0
		}
	})
	installFixtureSnapshot(t, s, v, "revision-1")
	if err := s.WithOrganizationAPIKey(context.Background(), v, "org-1", password, false, false, consume, nil); err != ErrValidation {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized HTTP")
	}
	for _, rotation := range []bool{false, true} {
		rotate = rotation
		var borrowed []byte
		err := s.WithOrganizationAPIKey(context.Background(), v, "org-1", password, rotate, true, func(clientID string, secret []byte, revision time.Time) error {
			if clientID != "organization.org-1" || string(secret) != "fixture-secret" || revision.IsZero() {
				t.Error("key response")
			}
			borrowed = secret
			return nil
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range borrowed {
			if b != 0 {
				t.Fatal("borrowed secret not cleared")
			}
		}
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}
