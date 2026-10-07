// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// This is an actual HTTP fixture for tests focused on cipher/backup protocols.
// Policy failure/lifecycle tests use their own server instead. No production
// authorization or Session policy state is injected by this helper.
func newPersonalPolicyServer(next http.Handler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/sync" {
			_ = json.NewEncoder(w).Encode(emptyPolicySyncFixture())
			return
		}
		next.ServeHTTP(w, r)
	}))
}
func newPersonalStatePolicyServer(next http.Handler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/sync" {
			data := emptyPolicySyncFixture()
			data["ciphers"] = []any{map[string]any{"id": "item-1", "type": 1, "edit": true, "viewPassword": true, "reprompt": 0}, map[string]any{"id": "item-2", "type": 2, "edit": true, "viewPassword": true, "reprompt": 0}}
			_ = json.NewEncoder(w).Encode(data)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func newOrganizationPolicyServer(next http.Handler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/sync" {
			_ = json.NewEncoder(w).Encode(organizationPolicySyncFixture())
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func organizationPolicySyncFixture() map[string]any {
	data := emptyPolicySyncFixture()
	data["profile"].(map[string]any)["organizations"] = []any{map[string]any{
		"id": "org-1", "organizationUserId": "member-1", "userId": "account-a", "type": 2, "status": 2,
		"enabled": true, "usePolicies": true, "permissions": map[string]any{"managePolicies": false},
	}}
	return data
}

func emptyPolicySyncFixture() map[string]any {
	return map[string]any{
		"profile": map[string]any{"id": "account-a", "email": "fixture@example.invalid", "key": "fixture-wrapped-user-key", "organizations": []any{}},
		"ciphers": []any{}, "policies": []any{}, "policiesNew": []any{},
	}
}
