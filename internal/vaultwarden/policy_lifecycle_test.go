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

func TestPolicyExecutionCheckpointFailureAndBasePath(t *testing.T) {
	var refresh, reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nested/identity/connect/token":
			refresh.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/nested/api/sync":
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
		case "/nested/api/ciphers":
			writes.Add(1)
			policyCreateResponse(t, w, r)
		default:
			t.Error("base path lost", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL+"/nested")
	defer s.Close()
	s.expires = time.Now()
	scope := Scope{Server: server.URL + "/nested", Account: "account-a"}
	fields := CipherFields{Type: 2, Name: "note"}
	diskFailure := errors.New("fixture durable store failed")
	_, err := s.CreatePersonalCipher(context.Background(), scope, fields, func(cp SessionCheckpoint) error {
		if reads.Load() != 0 || writes.Load() != 0 || len(cp.Session) == 0 {
			t.Error("request before checkpoint")
		}
		return diskFailure
	})
	if !errors.Is(err, diskFailure) || refresh.Load() != 1 || reads.Load() != 0 || writes.Load() != 0 || s.writePolicies != nil {
		t.Fatal("checkpoint bypass", err)
	}
	if _, err = s.CreatePersonalCipher(context.Background(), scope, fields, nil); !errors.Is(err, ErrCheckpoint) {
		t.Fatal("lost pending checkpoint", err)
	}
	if _, err = s.CreatePersonalCipher(context.Background(), scope, fields, func(SessionCheckpoint) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if refresh.Load() != 1 || reads.Load() != 1 || writes.Load() != 1 {
		t.Fatal("retry rotated twice or skipped authority", refresh.Load(), reads.Load(), writes.Load())
	}
}

func TestPolicyExecutionNonDurableRefreshAlsoRevokesAuthority(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/sync":
			_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
		default:
			writes.Add(1)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	clear(s.passwordUnlock.Key)
	s.passwordUnlock = nil
	s.mu.Lock()
	ctx, finish, err := s.beginOperationLocked(context.Background())
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	_, err = s.operationPoliciesLocked(ctx, nil)
	if err != nil {
		finish()
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.expires = time.Now()
	_, _, err = s.authenticatedLocked(ctx, "POST", "/api/ciphers", "application/json", "{}", nil)
	finish()
	s.mu.Unlock()
	if !errors.Is(err, ErrExpired) || writes.Load() != 0 {
		t.Fatal("non-durable refresh retained policy capability", err, writes.Load())
	}
}

func TestPolicyExecutionIndependentOrganizationsUnionRestrictions(t *testing.T) {
	data := policySyncFixture(0, 15, []int{3})
	orgs := data["profile"].(map[string]any)["organizations"].([]any)
	orgs = append(orgs, map[string]any{"id": "org-b", "organizationUserId": "member-b", "userId": "account-a", "type": 2, "status": 2, "enabled": true, "usePolicies": true, "permissions": map[string]bool{"managePolicies": false}})
	data["profile"].(map[string]any)["organizations"] = orgs
	policies := append(data["policies"].([]any), map[string]any{"id": "policy-b", "organizationId": "org-b", "type": 15, "enabled": true, "data": []int{8}})
	data["policies"], data["policiesNew"] = policies, policies
	p, err := parsePolicyFixture(data)
	if err != nil || len(p.restrictedPersonal) != 2 || !p.restrictedPersonal[3] || !p.restrictedPersonal[8] {
		t.Fatal("multi-org restrictions lost", err)
	}
	policies = append(policies, map[string]any{"id": "policy-c", "organizationId": "org-b", "type": 5, "enabled": true, "data": nil})
	data["policies"], data["policiesNew"] = policies, policies
	p, err = parsePolicyFixture(data)
	if err != nil || !p.personalOwnership {
		t.Fatal("owner exemption incorrectly applied across organizations", err)
	}
}
