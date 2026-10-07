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

func TestOrgOperationsRefreshCheckpointAndStaleReceipt(t *testing.T) {
	for _, scenario := range []string{"missing", "disk", "old-receipt", "same-content"} {
		t.Run(scenario, func(t *testing.T) {
			var writes atomic.Int32
			var live json.RawMessage
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/identity/connect/token":
					json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
				case "/api/sync":
					data := organizationPolicySyncFixture()
					data["ciphers"] = []json.RawMessage{live}
					json.NewEncoder(w).Encode(data)
				default:
					writes.Add(1)
				}
			}))
			defer server.Close()
			s, v, _, doc := organizationFixture(t, server.URL)
			defer s.Close()
			live = doc.JSON
			s.expires = time.Now().Add(-time.Minute)
			persist := func(c SessionCheckpoint) error {
				switch scenario {
				case "missing":
					return nil
				case "disk":
					return errors.New("fixture disk")
				case "old-receipt":
					return c.AcceptAuthenticatedReceipt(v, "stale-revision", "new-revision")
				default:
					return c.AcceptAuthenticatedReceipt(v, "revision-1", "new-revision")
				}
			}
			result, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherTrash, nil, persist)
			if scenario == "same-content" {
				if err != nil || !result.Applied || writes.Load() != 1 {
					t.Fatal("durable same-content continuation", result, err)
				}
			} else if err == nil || result.Applied || writes.Load() != 0 {
				t.Fatal("refresh resurrected operation authority", scenario, result, err, writes.Load())
			}
			if s.ValidateAuthenticatedSnapshot(v, "revision-1") == nil {
				t.Fatal("old receipt survived refresh")
			}
		})
	}
}

func TestOrgOperationsRepromptGrantExpiresAndCannotCrossItems(t *testing.T) {
	var live json.RawMessage
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			data := organizationPolicySyncFixture()
			data["ciphers"] = []json.RawMessage{live}
			json.NewEncoder(w).Encode(data)
			return
		}
		writes.Add(1)
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	clear(s.passwordUnlock.Key)
	s.passwordUnlock.Key, _ = DeriveSnapshotUnlockKey([]byte("test-master"), s.passwordUnlock.Config)
	v = changeOrganizationFixture(t, v, func(m map[string]any) { m["ciphers"].([]any)[0].(map[string]any)["reprompt"] = 1 })
	installFixtureSnapshot(t, s, v, "revision-1")
	docs, _ := v.Documents(v.Scope)
	live = docs[0].JSON
	grant, err := s.AuthorizeOrganizationItem(context.Background(), v, "revision-1", "item-org", []byte("test-master"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherArchive, map[string]*ItemAuthorization{"other": grant}, nil); err != ErrPermission {
		t.Fatal("cross item", err)
	}
	if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherArchive, map[string]*ItemAuthorization{"item-org": grant}, nil); err != nil {
		t.Fatal("valid grant", err)
	}
	grant.expires = time.Now().Add(-time.Second)
	if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherArchive, map[string]*ItemAuthorization{"item-org": grant}, nil); err != ErrPermission {
		t.Fatal("expired grant", err)
	}
	if writes.Load() != 1 {
		t.Fatal("grant bypass", writes.Load())
	}
}

func TestOrgDirectoryFreshReadFailureNeverResends(t *testing.T) {
	var mutation atomic.Int32
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/organizations/org-1/users":
			if reads.Add(1) > 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Write([]byte(`{"data":[{"id":"member-1","userId":"account-a","type":0,"status":2,"email":"owner@example.invalid"}]}`))
		case "/identity/connect/token":
			w.Write([]byte(`{"access_token":"public","expires_in":3600,"token_type":"Bearer"}`))
		case "/api/public/organization/import":
			mutation.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		default:
			t.Error("unexpected", r.URL.Path)
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = 0
		}
	})
	installFixtureSnapshot(t, s, v, "revision-1")
	result, err := s.ImportOrganizationDirectory(context.Background(), v, "org-1", []byte("key"), OrganizationDirectoryImport{Members: []OrganizationDirectoryMember{{Email: "member@example.invalid", ExternalID: "member"}}}, true, func(SessionCheckpoint) error { return nil })
	if err == nil || mutation.Load() != 1 || reads.Load() != 2 || result.Reconciliation == nil || result.Reconciliation.After != nil || result.Reconciliation.Rows[0].Verified {
		t.Fatal("uncertainty lost", result, err)
	}
	if s.ValidateAuthenticatedSnapshot(v, "revision-1") == nil {
		t.Fatal("directory read removed isolation")
	}
}
