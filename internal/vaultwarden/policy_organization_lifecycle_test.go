// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrganizationPolicyRefreshInvalidatesPreparedWrite(t *testing.T) {
	var reads, writes, refresh atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			refresh.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/sync":
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(organizationPolicySyncFixture())
		case "/api/ciphers/create":
			writes.Add(1)
			var data struct{ Cipher map[string]any }
			_ = json.NewDecoder(r.Body).Decode(&data)
			data.Cipher["id"] = "created"
			_ = json.NewEncoder(w).Encode(data.Cipher)
		default:
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	s.expires = time.Now()
	fields := CipherFields{Type: 2, Name: "note"}
	diskFailure := errors.New("fixture checkpoint failure")
	_, err := s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", fields, func(SessionCheckpoint) error { return diskFailure })
	if !errors.Is(err, diskFailure) || reads.Load() != 0 || writes.Load() != 0 || refresh.Load() != 1 {
		t.Fatal("checkpoint bypass", err)
	}
	_, err = s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", fields, func(SessionCheckpoint) error { return nil })
	if !errors.Is(err, ErrExpired) || reads.Load() != 1 || writes.Load() != 0 || refresh.Load() != 1 {
		t.Fatal("prepared key/permission guard survived epoch change", err)
	}
	if s.writePolicies != nil {
		t.Fatal("operation authority leaked")
	}
	_, err = s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", fields, nil)
	if err != nil || reads.Load() != 2 || writes.Load() != 1 || refresh.Load() != 1 {
		t.Fatal("explicit retry did not obtain new authority", err)
	}
}

func TestOrganizationCloseDuringPolicyReadCannotDispatch(t *testing.T) {
	entered := make(chan struct{})
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			close(entered)
			<-r.Context().Done()
			return
		}
		writes.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	result := make(chan error, 1)
	go func() {
		_, err := s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", CipherFields{Type: 2, Name: "note"}, nil)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		s.Close()
		t.Fatal("policy GET did not start")
	}
	s.Close()
	select {
	case err := <-result:
		if err == nil || writes.Load() != 0 || s.writePolicies != nil {
			t.Fatal("closed policy operation dispatched", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not stop policy read")
	}
}
