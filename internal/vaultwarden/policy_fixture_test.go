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
func emptyPolicySyncFixture() map[string]any {
	return map[string]any{
		"profile": map[string]any{"id": "account-a", "email": "fixture@example.invalid", "key": "fixture-wrapped-user-key", "organizations": []any{}},
		"ciphers": []any{}, "policies": []any{}, "policiesNew": []any{},
	}
}
