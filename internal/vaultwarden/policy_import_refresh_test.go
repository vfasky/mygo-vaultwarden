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

// Called synchronously by the operation that already holds Session.mu. This
// deterministically advances token expiry after the first successful folder;
// the server and a timer goroutine never write Session state.
type policyExpiryTransport struct {
	http.RoundTripper
	session *Session
	expired bool
}

func (p *policyExpiryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := p.RoundTripper.RoundTrip(r)
	if !p.expired && err == nil && r.Method == "POST" && r.URL.Path == "/api/folders" && response.StatusCode == 200 {
		p.expired = true
		p.session.expires = time.Now()
	}
	return response, err
}
func TestPolicyImportRefreshStopsAfterKnownPartialSuccess(t *testing.T) {
	source, vault, ids := backupFixture(t, MyGoBackup, 1)
	defer source.Close()
	encoded, err := source.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	plan, err := ParseImport(encoded, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	var reads, folders, ciphers, refreshes, checkpoints atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/sync":
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
		case "/api/folders":
			folders.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			body["id"] = "created-folder"
			_ = json.NewEncoder(w).Encode(body)
		case "/identity/connect/token":
			refreshes.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		default:
			ciphers.Add(1)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	transport := s.client.http.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	s.client.http.Transport = &policyExpiryTransport{RoundTripper: transport, session: s}
	result, err := s.ImportPersonalBackup(context.Background(), Scope{Server: server.URL, Account: "account-a"}, plan, func(SessionCheckpoint) error { checkpoints.Add(1); return nil })
	if !errors.Is(err, ErrExpired) {
		t.Fatal("refresh did not invalidate import", err)
	}
	if len(result.Entries) != 2 || result.Entries[0].ID != "created-folder" || result.Entries[0].State != "已创建" || result.Entries[1].ID != "" || result.Entries[1].State != "已停止，请同步核对" {
		t.Fatal("lost known partial result", result)
	}
	if reads.Load() != 1 || folders.Load() != 1 || ciphers.Load() != 0 || refreshes.Load() != 1 || checkpoints.Load() != 1 || s.writePolicies != nil {
		t.Fatal("partial batch continued or retried", reads.Load(), folders.Load(), ciphers.Load(), refreshes.Load(), checkpoints.Load())
	}
}
