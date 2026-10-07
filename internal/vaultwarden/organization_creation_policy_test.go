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

func singleOrganizationFixture(role, status int, enabled bool) map[string]any {
	data := organizationPolicySyncFixture()
	org := data["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)
	org["type"], org["status"] = role, status
	policy := map[string]any{"id": "policy-single", "organizationId": "org-1", "type": 3, "enabled": enabled, "data": nil}
	if status == 2 {
		data["policies"] = []any{policy}
	}
	if status >= 1 {
		data["policiesNew"] = []any{policy}
	}
	return data
}

func TestOrganizationCreationSingleOrganizationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		role, status                                 int
		enabled, disabled, quarantine, pending, deny bool
	}{
		{name: "member", role: 2, status: 2, enabled: true, deny: true},
		{name: "manager", role: 4, status: 2, enabled: true, deny: true},
		{name: "owner exempt", role: 0, status: 2, enabled: true},
		{name: "admin exempt", role: 1, status: 2, enabled: true},
		{name: "disabled policy", role: 2, status: 2},
		{name: "accepted not confirmed", role: 2, status: 1, enabled: true},
		{name: "invited", role: 2, status: 0, enabled: true},
		{name: "server disabled not exempt", role: 2, status: 2, enabled: true, disabled: true, deny: true},
		{name: "local quarantine not exempt", role: 2, status: 2, enabled: true, quarantine: true, deny: true},
		{name: "unknown policy write blocks owner", role: 0, status: 2, pending: true, deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads, writes atomic.Int32
			remote := singleOrganizationFixture(tc.role, tc.status, tc.enabled)
			if tc.disabled {
				remote["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)["enabled"] = false
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "GET" && r.URL.Path == "/api/sync":
					reads.Add(1)
					_ = json.NewEncoder(w).Encode(remote)
				case r.Method == "POST" && r.URL.Path == "/api/organizations":
					writes.Add(1)
					_, _ = w.Write([]byte(`{"id":"created-org","name":"org","billingEmail":"owner@example.invalid"}`))
				default:
					t.Error("unexpected route", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			// Local fixture deliberately has no type-3 policy: only the authoritative
			// HTTP response may authorize the new organization.
			if tc.quarantine {
				vault.QuarantinedOrganizations = []string{"org-1"}
			}
			if tc.pending {
				vault.Version = 2
				vault.QuarantinedOrganizations = []string{"org-1"}
				vault.PendingPolicyMutations = []PendingPolicyMutation{{OrganizationID: "org-1", PolicyType: 3, MutationID: "mutation-single"}}
			}
			installFixtureSnapshot(t, s, vault, "revision-single")
			_, err := s.SaveOrganization(context.Background(), vault, "", OrganizationSettings{Name: "org", BillingEmail: "owner@example.invalid", CollectionName: "default"}, nil)
			if tc.deny {
				if !errors.Is(err, ErrPermission) || writes.Load() != 0 {
					t.Fatal("policy allowed creation", err, writes.Load())
				}
			} else if err != nil || writes.Load() != 1 {
				t.Fatal("allowed creation failed", err, writes.Load())
			}
			if reads.Load() != 1 {
				t.Fatal("missing authoritative read", reads.Load())
			}
		})
	}
}

func TestOrganizationCreationRefreshCheckpoint(t *testing.T) {
	var reads, writes, refresh atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			refresh.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/sync":
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(singleOrganizationFixture(0, 2, true))
		case "/api/organizations":
			writes.Add(1)
			_, _ = w.Write([]byte(`{"id":"created-org"}`))
		default:
			t.Error("unexpected route", r.URL.Path)
		}
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	s.expires = time.Now()
	settings := OrganizationSettings{Name: "org", BillingEmail: "owner@example.invalid", CollectionName: "default"}
	diskFailure := errors.New("fixture checkpoint failure")
	_, err := s.SaveOrganization(context.Background(), vault, "", settings, func(SessionCheckpoint) error { return diskFailure })
	if !errors.Is(err, diskFailure) || reads.Load() != 0 || writes.Load() != 0 || refresh.Load() != 1 {
		t.Fatal("failed checkpoint allowed request", err)
	}
	_, err = s.SaveOrganization(context.Background(), vault, "", settings, func(SessionCheckpoint) error { return nil })
	if !errors.Is(err, ErrExpired) || reads.Load() != 0 || writes.Load() != 0 || refresh.Load() != 1 {
		t.Fatal("old snapshot survived failed checkpoint", err)
	}
	if err := s.persistPendingLocked(func(SessionCheckpoint) error { return nil }); err != nil {
		t.Fatal(err)
	}
	installFixtureSnapshot(t, s, vault, "revision-after-refresh")
	_, err = s.SaveOrganization(context.Background(), vault, "", settings, nil)
	if err != nil || reads.Load() != 1 || writes.Load() != 1 || refresh.Load() != 1 || s.writePolicies != nil {
		t.Fatal("fresh authenticated snapshot did not recover", err)
	}
}

func TestOrganizationCreationPolicyReadCancellation(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closeSession], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/api/sync" {
					close(entered)
					<-release
					_ = json.NewEncoder(w).Encode(singleOrganizationFixture(0, 2, true))
					return
				}
				writes.Add(1)
				w.WriteHeader(500)
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := s.SaveOrganization(ctx, vault, "", OrganizationSettings{Name: "org", BillingEmail: "owner@example.invalid", CollectionName: "default"}, nil)
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("policy read did not start")
			}
			if closeSession {
				s.Close()
			} else {
				cancel()
			}
			close(release)
			select {
			case err := <-done:
				if err == nil || writes.Load() != 0 {
					t.Fatal("stale operation dispatched", err, writes.Load())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("operation not cancelled")
			}
		})
	}
}
