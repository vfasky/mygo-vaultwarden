// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func groupsEnabledVault(t *testing.T, v *VaultData) *VaultData {
	return changeOrganizationFixture(t, v, func(d map[string]any) {
		for _, field := range []string{"organizations", "organizationsNew"} {
			d["profile"].(map[string]any)[field].([]any)[0].(map[string]any)["UseGroups"] = true
		}
	})
}
func TestMemberRolePreservesDirectRelationsAndRejectsIncompleteOrChangedSources(t *testing.T) {
	var mode, collectionName string
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/organizations/org-1")
		if r.Method == "PUT" {
			writes++
			var body struct {
				Type        int
				Collections []map[string]json.RawMessage
				Groups      []string
				Permissions map[string]json.RawMessage
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Type != 4 || len(body.Collections) != 1 || len(body.Groups) != 1 || body.Groups[0] != "group-1" {
				t.Error("lost direct relationships")
			}
			if len(body.Collections) == 1 && (string(body.Collections[0]["id"]) != `"collection-1"` || string(body.Collections[0]["manage"]) != "false" || string(body.Collections[0]["opaque"]) != `9007199254740993`) {
				t.Error("changed direct rights/opaque")
			}
			if string(body.Permissions["futurePermission"]) != `9007199254740993` {
				t.Error("opaque permission")
			}
			return
		}
		switch path {
		case "/users":
			writeMembers(w, memberRows())
		case "/users/member-2":
			_, _ = w.Write([]byte(`{"id":"member-2","userId":"account-b","collections":[],"groups":[],"permissions":{"futurePermission":9007199254740993}}`))
		case "/collections":
			if mode == "incomplete" {
				_, _ = w.Write([]byte(`{"data":[],"continuationToken":"next"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]string{"id": "collection-1", "organizationId": "org-1", "name": collectionName}, map[string]string{"id": "inherited-only", "organizationId": "org-1"}}})
		case "/collections/collection-1/users":
			if mode == "changed" {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"member-2","readOnly":true,"hidePasswords":true,"manage":false,"opaque":9007199254740993}]`))
		case "/collections/inherited-only/users":
			_, _ = w.Write([]byte(`[]`))
		case "/groups":
			_, _ = w.Write([]byte(`{"data":[{"id":"group-1","organizationId":"org-1"}]}`))
		case "/groups/group-1/users":
			_, _ = w.Write([]byte(`["member-2"]`))
		default:
			t.Error(path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, v, key, _ := organizationFixture(t, server.URL)
	collectionName, _ = EncryptString([]byte("直接集合"), key)
	defer s.Close()
	v = ownerVault(t, v)
	directory, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A disabled group feature is not evidence that hidden historical groups are absent.
	if _, err = s.PrepareMemberRole(context.Background(), v, directory, "member-2", nil); err != ErrMemberRoleGroupsDisabled {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("disabled groups wrote")
	}
	v = groupsEnabledVault(t, v)
	draft, err := s.PrepareMemberRole(context.Background(), v, directory, "member-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	draft.Role = 4
	mode = "incomplete"
	if err = s.SaveMemberRole(context.Background(), v, draft, nil, nil, nil); err != ErrProtocol {
		t.Fatal(err)
	}
	mode = "changed"
	if err = s.SaveMemberRole(context.Background(), v, draft, nil, nil, nil); err != ErrConflict {
		t.Fatal(err)
	}
	if writes != 0 || draft.Role != 4 {
		t.Fatal("changed source submitted or draft lost")
	}
	mode = ""
	if err = s.SaveMemberRole(context.Background(), v, draft, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal(writes)
	}
	disabled := ownerVault(t, changeOrganizationFixture(t, v, func(d map[string]any) {
		for _, field := range []string{"organizations", "organizationsNew"} {
			d["profile"].(map[string]any)[field].([]any)[0].(map[string]any)["UseGroups"] = false
		}
	}))
	if err = s.SaveMemberRole(context.Background(), disabled, draft, nil, nil, nil); err != ErrMemberRoleGroupsDisabled {
		t.Fatal(err)
	}
	if writes != 1 || draft.Role != 4 {
		t.Fatal("disabled save discarded draft")
	}
	draft.ManageAllCollections = true
	if affected := draft.ResetCollections(); len(affected) != 1 || affected[0].Name != "直接集合" || !affected[0].ReadOnly {
		t.Fatal("incomplete affected set", affected)
	}
	if err = s.SaveMemberRole(context.Background(), v, draft, nil, nil, nil); err != ErrValidation {
		t.Fatal("missing destructive consent", err)
	}
	consent := draft.ConfirmCollectionReset()
	defer consent.Close()
	draft.Role = 1
	if err = s.SaveMemberRole(context.Background(), v, draft, consent, nil, nil); err != ErrConflict {
		t.Fatal("stale role consent", err)
	}
	draft.Role = 4
	mode = "changed"
	if err = s.SaveMemberRole(context.Background(), v, draft, consent, nil, nil); err != ErrConflict {
		t.Fatal("stale relation consent", err)
	}
	if writes != 1 {
		t.Fatal("unconfirmed side effect dispatched")
	}
	mode = ""
	if err = s.SaveMemberRole(context.Background(), v, draft, consent, nil, nil); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatal(writes)
	}
}
