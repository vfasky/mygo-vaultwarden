// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCollectionAccessMembershipDirectoryAndOpaquePreservation(t *testing.T) {
	var detail []byte
	writes, isolated := 0, false
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/organizations/org-1/users/mini-details":
			_, _ = w.Write([]byte(`{"data":[{"id":"member-other","userId":"account-other","name":"成员甲","email":"a@example.invalid"},{"id":"member-new","userId":"account-new","name":"成员乙","email":"b@example.invalid"}],"continuationToken":null}`))
		case r.Method == "GET" && r.URL.Path == "/api/organizations/org-1/groups":
			_, _ = w.Write([]byte(`{"data":[{"id":"group-other","organizationId":"org-1","name":"产品群组"}],"continuationToken":null}`))
		case r.Method == "GET":
			_, _ = w.Write(detail)
		case r.Method == "PUT":
			if !isolated {
				t.Error("access write preceded isolation")
			}
			var body map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&body)
			var users []map[string]json.RawMessage
			_ = json.Unmarshal(body["users"], &users)
			if len(users) != 2 || string(users[0]["id"]) != `"member-other"` || string(users[1]["id"]) != `"member-new"` || string(users[0]["extension"]) != `{"n":9007199254740993}` || string(users[0]["readOnly"]) != "false" {
				t.Error("membership/opaque lost", string(body["users"]))
			}
			if string(body["groups"]) != "[]" {
				t.Error("group not removed")
			}
			writes++
			_, _ = w.Write([]byte(`{"id":"collection-1","organizationId":"org-1"}`))
		default:
			t.Error("unexpected request")
		}
	}))
	defer server.Close()
	s, vault, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	vault = changeOrganizationFixture(t, collectionManagerVault(t, vault), func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["UseGroups"] = true
		}
	})
	installFixtureSnapshot(t, s, vault, "revision-1")
	detail = collectionDetailFixture(t, key)
	draft, err := s.CollectionDetails(context.Background(), vault, "org-1", "collection-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	access, err := s.CollectionAccessDetails(context.Background(), vault, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	if len(access.Access) != 3 || !access.GroupsEnabled || access.AccessChanged() {
		t.Fatal("directory", access)
	}
	for i := range access.Access {
		a := &access.Access[i]
		if a.Group {
			a.Assigned = false
		} else {
			a.Assigned, a.ReadOnly, a.HidePasswords = true, false, false
		}
	}
	before := requests
	if err := s.SaveCollection(context.Background(), vault, access, nil, nil); err != ErrCheckpoint || writes != 0 || requests != before {
		t.Fatal("missing isolation", err)
	}
	if err := s.SaveCollection(context.Background(), vault, access, func(SessionCheckpoint) error { return errors.New("disk") }, nil); err != ErrCheckpoint || writes != 0 || requests != before {
		t.Fatal("failed isolation", err)
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	if err := s.SaveCollection(context.Background(), vault, access, func(SessionCheckpoint) error { isolated = true; return nil }, nil); err != nil || writes != 1 {
		t.Fatal(err, writes)
	}
	clone := access.Clone()
	defer clone.Close()
	clone.Access[0].ID = "account-other"
	if _, _, err := clone.collectionWriteBody(); err != ErrIdentity {
		t.Fatal("global user substituted for member", err)
	}
	if access.Access[0].ID != "member-other" {
		t.Fatal("clone shares mutable choices")
	}
}

func TestCollectionAccessUnlistedEntriesPreservedAndManageConsistency(t *testing.T) {
	draft := &CollectionDraft{raw: map[string]json.RawMessage{
		"users": json.RawMessage(`[{"id":"unlisted","readOnly":true,"hidePasswords":false,"manage":false,"extension":42}]`), "groups": json.RawMessage(`[]`),
	}, AccessLoaded: true, originalAccess: map[string]CollectionAccess{"users/new": {ID: "new", ReadOnly: true, HidePasswords: true}}, Access: []CollectionAccess{{ID: "new", Assigned: true, Manage: true}}}
	body, changed, err := draft.collectionWriteBody()
	if err != nil || !changed {
		t.Fatal(err)
	}
	var users []map[string]json.RawMessage
	_ = json.Unmarshal(body["users"], &users)
	if len(users) != 2 || string(users[0]["extension"]) != "42" {
		t.Fatal("unlisted member erased")
	}
	draft.Access[0].ReadOnly = true
	if _, _, err := draft.collectionWriteBody(); err != ErrValidation {
		t.Fatal("conflicting manage accepted", err)
	}
}

func TestCollectionAccessDirectoryRejectsAccountMemberConfusion(t *testing.T) {
	for _, data := range []string{
		"{\"data\":[{\"id\":\"member-other\",\"userId\":\"account-a\"}]}",
		"{\"data\":[{\"id\":\"account-other\",\"userId\":\"account-other\"}]}",
		"{\"data\":[{\"id\":\"m1\",\"userId\":\"u\"},{\"id\":\"m2\",\"userId\":\"u\"}]}",
	} {
		t.Run(data, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(data)) }))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			vault = acceptedCollectionManagerVault(t, s, vault)
			draft, err := s.CollectionDetails(context.Background(), vault, "org-1", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer draft.Close()
			if _, err := s.CollectionAccessDetails(context.Background(), vault, draft, nil); err != ErrIdentity {
				t.Fatal("ambiguous membership accepted", err)
			}
		})
	}
}
