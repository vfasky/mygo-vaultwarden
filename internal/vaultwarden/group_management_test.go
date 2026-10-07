// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupExplicitScopePreservesRelationsAndIsolation(t *testing.T) {
	var name, mode string
	writes, isolations := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/organizations/org-1")
		if r.Method != "GET" {
			writes++
			if isolations == 0 {
				t.Error("write before isolation")
			}
			if mode == "unknown" {
				w.WriteHeader(503)
				return
			}
			if mode == "response-identity" {
				_, _ = w.Write([]byte(`{"id":"foreign-group","organizationId":"other-org","name":"新名"}`))
				return
			}
			var body map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("body")
			}
			if string(body["accessAll"]) != "true" && string(body["accessAll"]) != "false" {
				t.Error("missing explicit scope")
			}
			if string(body["opaque"]) != `9007199254740993` || string(body["users"]) != `["member-2"]` {
				t.Error("lost opaque/users", body)
			}
			var cols []map[string]json.RawMessage
			_ = json.Unmarshal(body["collections"], &cols)
			if len(cols) != 1 || string(cols[0]["opaque"]) != `9007199254740993` {
				t.Error("lost collection opaque")
			}
			_, _ = w.Write([]byte(`{"id":"group-1","organizationId":"org-1","name":"新名"}`))
			return
		}
		switch path {
		case "/users":
			writeMembers(w, memberRows())
		case "/groups/group-1/details":
			id := "org-1"
			if mode == "identity" {
				id = "org-other"
			}
			n := "原名"
			if mode == "changed" {
				n = "别人改名"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "group-1", "organizationId": id, "name": n, "collections": []any{map[string]any{"id": "collection-1", "readOnly": true, "hidePasswords": true, "manage": false, "opaque": json.RawMessage(`9007199254740993`)}}, "opaque": json.RawMessage(`9007199254740993`)})
		case "/groups/group-1/users":
			_, _ = w.Write([]byte(`["member-2"]`))
		case "/collections":
			if mode == "page" {
				_, _ = w.Write([]byte(`{"data":[],"continuationToken":"next"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]string{"id": "collection-1", "organizationId": "org-1", "name": name}}})
		default:
			t.Error(path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, v, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = groupsEnabledVault(t, ownerVault(t, v))
	name, _ = EncryptString([]byte("集合"), key)
	d, err := s.GroupDetails(context.Background(), v, "org-1", "group-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.AccessScope != GroupScopeUnset {
		t.Fatal("inferred missing scope")
	}
	d.Name = "新名"
	isolate := func(SessionCheckpoint) error { isolations++; return nil }
	if err = s.SaveGroup(context.Background(), v, d, d.Confirm(), isolate, nil); err != ErrValidation {
		t.Fatal("rename bypass", err)
	}
	d.AccessScope = GroupAllCollections
	consent := d.Confirm()
	defer consent.Close()
	d.Name = "changed target"
	if err = s.SaveGroup(context.Background(), v, d, consent, isolate, nil); err != ErrValidation {
		t.Fatal("stale consent", err)
	}
	d.Name = "新名"
	if err = s.SaveGroup(context.Background(), v, d, consent, func(SessionCheckpoint) error { return errors.New("disk") }, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		err  error
	}{{"changed", ErrConflict}, {"identity", ErrIdentity}, {"page", ErrProtocol}} {
		mode = tc.mode
		consent = d.Confirm()
		if err = s.SaveGroup(context.Background(), v, d, consent, isolate, nil); err != tc.err {
			t.Fatal(tc.mode, err)
		}
	}
	if writes != 0 {
		t.Fatal("unsafe write", writes)
	}
	mode = ""
	for _, scope := range []GroupScope{GroupAllCollections, GroupSelectedCollections} {
		d.AccessScope = scope
		c := d.Confirm()
		err = s.SaveGroup(context.Background(), v, d, c, isolate, nil)
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if writes != 2 {
		t.Fatal(writes)
	}
	mode = "unknown"
	c := d.Confirm()
	err = s.SaveGroup(context.Background(), v, d, c, isolate, nil)
	c.Close()
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) || writes != 3 {
		t.Fatal("unknown retried", err, writes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c = d.Confirm()
	if err = s.SaveGroup(ctx, v, d, c, isolate, nil); err == nil {
		t.Fatal("cancel wrote")
	}
	c.Close()
	if writes != 3 {
		t.Fatal(writes)
	}
	mode = "response-identity"
	c = d.Confirm()
	if err = s.SaveGroup(context.Background(), v, d, c, isolate, nil); !errors.As(err, &unknown) {
		t.Fatal("bad mutation identity accepted", err)
	}
	if err = s.SaveGroup(context.Background(), v, d, c, isolate, nil); err != ErrValidation || writes != 4 {
		t.Fatal("consumed consent replay", err, writes)
	}
	c.Close()
	originalRevision := s.authorizationRevision
	s.authorizationRevision = "changed-revision"
	c = d.Confirm()
	if err = s.SaveGroup(context.Background(), v, d, c, isolate, nil); err != ErrExpired || writes != 4 {
		t.Fatal("old revision wrote", err)
	}
	c.Close()
	s.authorizationRevision = originalRevision
	s.checkpointPending = true
	c = d.Confirm()
	checkpointFailure := errors.New("checkpoint disk failure")
	if err = s.SaveGroup(context.Background(), v, d, c, isolate, func(SessionCheckpoint) error { return checkpointFailure }); !errors.Is(err, checkpointFailure) || writes != 4 {
		t.Fatal("checkpoint failure wrote", err)
	}
	c.Close()
}
func TestGroupCloseCancelsDispatchedWriteWithoutRetry(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			writes.Add(1)
			close(entered)
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		switch r.URL.Path {
		case "/api/organizations/org-1/users":
			writeMembers(w, memberRows())
		case "/api/organizations/org-1/collections":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	defer close(release)
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = groupsEnabledVault(t, ownerVault(t, v))
	d, err := s.GroupDetails(context.Background(), v, "org-1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Name = "Cancelled group"
	d.AccessScope = GroupSelectedCollections
	c := d.Confirm()
	defer c.Close()
	result := make(chan error, 1)
	go func() { result <- s.SaveGroup(context.Background(), v, d, c, nil, nil) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write not dispatched")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel")
	}
	err = <-result
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, ErrCancelled) || writes.Load() != 1 {
		t.Fatal("cancel result/retry", err, writes.Load())
	}
	if _, err = s.OrganizationGroups(context.Background(), v, "org-1", nil); err != ErrExpired {
		t.Fatal("closed group session revived", err)
	}
}

func TestGroupScopeConsentAndIdentityValidation(t *testing.T) {
	d := &GroupDraft{Name: "test", raw: map[string]json.RawMessage{"collections": json.RawMessage(`[]`)}, originalAccess: map[string]GroupAssignment{}}
	if d.Confirm() != nil {
		t.Fatal("unset consent")
	}
	for _, scope := range []GroupScope{GroupAllCollections, GroupSelectedCollections} {
		d.AccessScope = scope
		body, err := d.body()
		if err != nil {
			t.Fatal(err)
		}
		if string(body["collections"]) != "[]" || string(body["users"]) != "[]" {
			t.Fatal("empty relations")
		}
		if (string(body["accessAll"]) == "true") != (scope == GroupAllCollections) {
			t.Fatal("wrong scope")
		}
	}
	d.Access = append(d.Access, GroupAssignment{ID: "global-account", Assigned: true})
	if _, err := d.body(); err != ErrIdentity {
		t.Fatal(err)
	}
}
