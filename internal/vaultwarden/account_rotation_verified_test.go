// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRotationCompatibilityUsesServerReleaseAndCommit(t *testing.T) {
	for _, test := range []struct {
		name, version, commit, server string
		want                          bool
	}{{"pinned", "1.37.4", rotationGit1374, "Vaultwarden", true}, {"short-pinned", "1.37.4", "7c188967", "Vaultwarden", true}, {"client-version", "2026.6.0", rotationGit1374, "Vaultwarden", false}, {"unknown-version", "", rotationGit1374, "Vaultwarden", false}, {"different-version", "1.37.5", rotationGit1374, "Vaultwarden", false}, {"custom-build", "1.37.4", "unknown", "Vaultwarden", false}, {"other-server", "1.37.4", rotationGit1374, "Bitwarden", false}} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/version" {
					json.NewEncoder(w).Encode(test.version)
					return
				}
				if r.URL.Path != "/api/config" {
					t.Error("unexpected route")
				}
				json.NewEncoder(w).Encode(map[string]any{"version": "2026.6.0", "gitHash": test.commit, "server": map[string]string{"name": test.server, "url": "https://github.com/dani-garcia/vaultwarden"}})
			}))
			defer srv.Close()
			client, _ := NewClient(srv.URL, "fixture-device-id")
			_, _, err := client.rotationCompatibility(context.Background())
			if (err == nil) != test.want {
				t.Fatal(err)
			}
		})
	}
}
