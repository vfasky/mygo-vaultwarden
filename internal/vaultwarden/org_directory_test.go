// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOrgDirectoryIsolationTokenRouteAndUnverifiedRows(t *testing.T) {
	var calls atomic.Int32
	isolated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !isolated {
			t.Error("request before isolation")
		}
		if r.URL.Path == "/api/organizations/org-1/users" {
			if r.Method != "GET" || r.Header.Get("Authorization") == "Bearer public-fixture" {
				t.Error("wrong management read")
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"member-1","userId":"account-a","email":"owner@example.invalid","type":0,"status":2}],"continuationToken":null}`))
			return
		}
		if r.URL.Path == "/identity/connect/token" {
			_ = r.ParseForm()
			if r.Form.Get("scope") != "api.organization" || r.Form.Get("client_id") != "organization.org-1" || r.Form.Get("client_secret") != "fixture-secret" || r.Header.Get("Authorization") != "" {
				t.Error("wrong organization credentials")
			}
			_, _ = w.Write([]byte(`{"access_token":"public-fixture","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.URL.Path != "/api/public/organization/import" || r.Header.Get("Authorization") != "Bearer public-fixture" || r.Method != "POST" {
			t.Error("wrong Public route or token")
		}
		var input OrganizationDirectoryImport
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.OverwriteExisting || len(input.Members) != 1 || input.Groups == nil {
			t.Error("directory body")
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	input := OrganizationDirectoryImport{Members: []OrganizationDirectoryMember{{Email: "member@example.invalid", ExternalID: "directory-1"}}}
	if _, err := s.ImportOrganizationDirectory(context.Background(), v, "org-1", []byte("fixture-secret"), input, true, nil); err != ErrPermission {
		t.Fatal(err)
	}
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = 0
		}
	})
	installFixtureSnapshot(t, s, v, "revision-1")
	if _, err := s.ImportOrganizationDirectory(context.Background(), v, "org-1", []byte("fixture-secret"), input, false, nil); err != ErrValidation {
		t.Fatal(err)
	}
	if _, err := s.ImportOrganizationDirectory(context.Background(), v, "org-1", []byte("fixture-secret"), input, true, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("early HTTP")
	}
	result, err := s.ImportOrganizationDirectory(context.Background(), v, "org-1", []byte("fixture-secret"), input, true, func(SessionCheckpoint) error { isolated = true; return nil })
	if err != nil || !result.RequestAccepted || !result.ReconcileRequired || len(result.MemberExternalIDs) != 1 || calls.Load() != 4 || result.Reconciliation == nil || result.Reconciliation.After == nil || result.Reconciliation.Rows[0].Verified {
		t.Fatal(result, err, calls.Load())
	}
}
func TestOrgDirectoryRejectsAmbiguousExternalIDs(t *testing.T) {
	for _, input := range []OrganizationDirectoryImport{
		{},
		{Members: []OrganizationDirectoryMember{{Email: "one@example.invalid", ExternalID: "same"}, {Email: "two@example.invalid", ExternalID: "same"}}},
		{Members: []OrganizationDirectoryMember{{Email: "One@example.invalid", ExternalID: "one"}}},
		{Members: []OrganizationDirectoryMember{{Email: "one@example.invalid", ExternalID: "one"}}, Groups: []OrganizationDirectoryGroup{{Name: "g", ExternalID: "g", MemberExternalIDs: []string{"missing"}}}},
	} {
		if err := validateOrganizationDirectory(input); err != ErrValidation {
			t.Fatal(err)
		}
	}
}
