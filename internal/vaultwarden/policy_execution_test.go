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

func policySyncFixture(role, kind int, value any) map[string]any {
	data := emptyPolicySyncFixture()
	data["profile"].(map[string]any)["organizations"] = []any{map[string]any{
		"id": "org-a", "organizationUserId": "member-a", "userId": "account-a", "type": role, "status": 2,
		"enabled": true, "usePolicies": true, "permissions": map[string]any{"managePolicies": false},
	}}
	policy := map[string]any{"id": "policy-a", "organizationId": "org-a", "type": kind, "enabled": true, "data": value}
	data["policies"], data["policiesNew"] = []any{policy}, []any{policy}
	return data
}
func parsePolicyFixture(data map[string]any) (*operationPolicies, error) {
	body, _ := json.Marshal(data)
	return parseOperationPolicies(body, Scope{Server: "https://example.invalid/base", Account: "account-a"}, "fixture@example.invalid", "fixture-wrapped-user-key")
}
func TestPolicyExecutionMembershipAndTypeSemantics(t *testing.T) {
	for _, role := range []int{0, 1, 2, 4} {
		p, err := parsePolicyFixture(policySyncFixture(role, 5, nil))
		if err != nil || p.personalOwnership != (role == 2 || role == 4) {
			t.Fatalf("role %d: %v %+v", role, err, p)
		}
		p, err = parsePolicyFixture(policySyncFixture(role, 15, nil))
		if err != nil || !p.restrictedPersonal[3] || len(p.restrictedPersonal) != 1 {
			t.Fatalf("restricted cards role %d: %v", role, err)
		}
	}
	data := policySyncFixture(2, 5, nil)
	org := data["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)
	org["enabled"] = false
	p, err := parsePolicyFixture(data)
	if err != nil || !p.personalOwnership {
		t.Fatal("disabled org must not bypass server ownership policy", err)
	}
	org["status"] = 1
	data["policies"] = []any{}
	p, err = parsePolicyFixture(data)
	if err != nil || p.personalOwnership {
		t.Fatal("accepted-only policy is not confirmed ownership", err)
	}
	data = policySyncFixture(0, 15, []int{1, 3, 8})
	p, err = parsePolicyFixture(data)
	if err != nil || len(p.restrictedPersonal) != 3 {
		t.Fatal("type union", err)
	}
	data = policySyncFixture(2, 5, nil)
	data["policies"].([]any)[0].(map[string]any)["enabled"] = false
	p, err = parsePolicyFixture(data)
	if err != nil || p.personalOwnership {
		t.Fatal("disabled policy enforced", err)
	}
}
func TestPolicyExecutionRejectsIncompleteOrInconsistentAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing-policies", func(d map[string]any) { delete(d, "policies") }},
		{"null-policies", func(d map[string]any) { d["policies"] = nil }},
		{"missing-new", func(d map[string]any) { delete(d, "policiesNew") }},
		{"missing-ciphers", func(d map[string]any) { delete(d, "ciphers") }},
		{"null-orgs", func(d map[string]any) { d["profile"].(map[string]any)["organizations"] = nil }},
		{"wrong-account", func(d map[string]any) { d["profile"].(map[string]any)["id"] = "other" }},
		{"wrong-email", func(d map[string]any) { d["profile"].(map[string]any)["email"] = "other@example.invalid" }},
		{"rotated-key", func(d map[string]any) { d["profile"].(map[string]any)["key"] = "other-key" }},
		{"missing-new-counterpart", func(d map[string]any) { d["policiesNew"] = []any{} }},
		{"missing-old-counterpart", func(d map[string]any) { d["policies"] = []any{} }},
		{"duplicate-policy", func(d map[string]any) { p := d["policies"].([]any)[0]; d["policies"] = []any{p, p} }},
		{"wrong-org", func(d map[string]any) { d["policies"].([]any)[0].(map[string]any)["organizationId"] = "other" }},
		{"missing-enabled", func(d map[string]any) { delete(d["policies"].([]any)[0].(map[string]any), "enabled") }},
		{"missing-data", func(d map[string]any) { delete(d["policies"].([]any)[0].(map[string]any), "data") }},
		{"unsupported-type", func(d map[string]any) { d["policies"].([]any)[0].(map[string]any)["type"] = 4 }},
		{"wrong-user", func(d map[string]any) {
			d["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)["userId"] = "other"
		}},
		{"missing-role", func(d map[string]any) {
			delete(d["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any), "type")
		}},
		{"missing-permission", func(d map[string]any) {
			d["profile"].(map[string]any)["organizations"].([]any)[0].(map[string]any)["permissions"] = map[string]any{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := policySyncFixture(2, 5, nil)
			tc.mutate(data)
			if _, err := parsePolicyFixture(data); err == nil {
				t.Fatal("untrusted authority accepted")
			}
		})
	}
	for _, bad := range []any{[]int{0}, []int{9}, []int{3, 3}, map[string]any{"types": []int{3}}, "3", []any{3.5}} {
		if _, err := parsePolicyFixture(policySyncFixture(2, 15, bad)); err == nil {
			t.Fatalf("accepted malformed restriction %v", bad)
		}
	}
	p, err := parsePolicyFixture(emptyPolicySyncFixture())
	if err != nil || p.personalOwnership || len(p.restrictedPersonal) != 0 {
		t.Fatal("explicit empty authority rejected", err)
	}
	if _, err := parseOperationPolicies([]byte(`{"policies":[],"policies":null}`), Scope{}, "", ""); err == nil {
		t.Fatal("duplicate fields accepted")
	}
}
func policyCreateResponse(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	var body map[string]json.RawMessage
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		t.Error("invalid cipher")
		w.WriteHeader(400)
		return
	}
	body["id"] = json.RawMessage(`"created-item"`)
	body["revisionDate"] = json.RawMessage(`"2026-01-01T00:00:00Z"`)
	_ = json.NewEncoder(w).Encode(body)
}
func TestPolicyExecutionReadsAuthorityForEachCreateOperation(t *testing.T) {
	var reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" && r.Method == "GET" {
			if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
				t.Error("unauthenticated policy read")
			}
			if reads.Add(1) == 1 {
				_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
			} else {
				_ = json.NewEncoder(w).Encode(policySyncFixture(2, 5, nil))
			}
			return
		}
		if r.URL.Path != "/api/ciphers" || r.Method != "POST" {
			t.Error("unexpected request")
		}
		writes.Add(1)
		policyCreateResponse(t, w, r)
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	scope := Scope{Server: server.URL, Account: "account-a"}
	fields := CipherFields{Type: 2, Name: "private note"}
	if _, err := s.CreatePersonalCipher(context.Background(), scope, fields, nil); err != nil {
		t.Fatal(err)
	}
	if s.writePolicies != nil {
		t.Fatal("policy authority escaped operation")
	}
	// Binding a public revision or constructing an empty public snapshot grants
	// no permission: the second online read remains authoritative.
	if err := s.BindSnapshotRevision(scope, "forged-revision"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePersonalCipher(context.Background(), scope, fields, nil); !errors.Is(err, ErrPermission) {
		t.Fatal(err)
	}
	if reads.Load() != 2 || writes.Load() != 1 {
		t.Fatal("authority reused or denied request sent", reads.Load(), writes.Load())
	}
}
func TestPolicyExecutionReadFailuresDoNotDispatchWrites(t *testing.T) {
	for _, mode := range []string{"500", "401", "malformed", "missing-policy", "wrong-key", "restricted", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/sync" {
					switch mode {
					case "500":
						w.WriteHeader(500)
					case "401":
						w.WriteHeader(401)
					case "malformed":
						_, _ = w.Write([]byte(`{`))
					case "missing-policy":
						d := emptyPolicySyncFixture()
						delete(d, "policies")
						_ = json.NewEncoder(w).Encode(d)
					case "wrong-key":
						d := emptyPolicySyncFixture()
						d["profile"].(map[string]any)["key"] = "rotated"
						_ = json.NewEncoder(w).Encode(d)
					case "restricted":
						_ = json.NewEncoder(w).Encode(policySyncFixture(0, 15, []int{2}))
					case "close", "cancel":
						close(entered)
						<-release
						_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
					}
					return
				}
				if r.URL.Path == "/identity/connect/token" {
					w.WriteHeader(400)
					return
				}
				writes.Add(1)
				w.WriteHeader(500)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := s.CreatePersonalCipher(ctx, Scope{Server: server.URL, Account: "account-a"}, CipherFields{Type: 2, Name: "note"}, nil)
				done <- err
			}()
			if mode == "close" || mode == "cancel" {
				<-entered
				if mode == "close" {
					s.Close()
				} else {
					cancel()
				}
				close(release)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("read failure allowed write")
				}
				var uncertain *MutationUncertainError
				if errors.As(err, &uncertain) {
					t.Fatal("read failure reported as dispatched mutation", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("policy read did not cancel")
			}
			if writes.Load() != 0 {
				t.Fatal("write dispatched", writes.Load())
			}
		})
	}
}
func TestPolicyExecutionCheckpointBeforeReadAndEpochRevocation(t *testing.T) {
	var reads, writes, checkpoints atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/api/sync":
			if checkpoints.Load() != 1 {
				t.Error("policy read preceded durable refresh")
			}
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
		default:
			writes.Add(1)
			policyCreateResponse(t, w, r)
		}
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.expires = time.Now()
	persist := func(SessionCheckpoint) error { checkpoints.Add(1); return nil }
	if _, err := s.CreatePersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, CipherFields{Type: 2, Name: "note"}, persist); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 || writes.Load() != 1 {
		t.Fatal(reads.Load(), writes.Load())
	}
	// Internal operation contract: an intervening refresh/checkpoint invalidates
	// all already acquired policy authority; subsequent writes must stop.
	s.mu.Lock()
	ctx, finish, err := s.beginOperationLocked(context.Background())
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	p, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		finish()
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.expires = time.Now() // next dispatch must refresh and checkpoint
	_, _, err = s.authenticatedLocked(ctx, "POST", "/api/ciphers", "application/json", "{}", persist)
	if !errors.Is(err, ErrExpired) {
		t.Error("stale policy context survived", err)
	}
	if s.checkOperationPoliciesLocked(ctx, p) == nil {
		t.Error("old context accepted")
	}
	finish()
	s.mu.Unlock()
	if writes.Load() != 1 || checkpoints.Load() != 2 {
		t.Fatal("stale write sent or refresh checkpoint omitted", writes.Load(), checkpoints.Load())
	}
}
