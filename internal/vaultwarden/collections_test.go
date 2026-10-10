// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func collectionManagerVault(t *testing.T, vault *VaultData) *VaultData {
	return changeOrganizationFixture(t, ownerVault(t, vault), func(d map[string]any) {
		d["collections"].([]any)[0].(map[string]any)["Manage"] = true
	})
}

func collectionDetailFixture(t *testing.T, key []byte) []byte {
	t.Helper()
	name, err := vaultcrypto.EncryptString([]byte("集合原名称"), key)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]json.RawMessage{
		"id": json.RawMessage(`"collection-1"`), "organizationId": json.RawMessage(`"org-1"`),
		"users":      json.RawMessage(`[{"id":"member-other","readOnly":true,"hidePasswords":true,"manage":false,"extension":{"n":9007199254740993}}]`),
		"groups":     json.RawMessage(`[{"id":"group-other","readOnly":false,"hidePasswords":false,"manage":true}]`),
		"externalId": json.RawMessage(`"directory-reference"`), "extension": json.RawMessage(`{"n":9007199254740993}`),
	}
	body["name"], _ = json.Marshal(name)
	result, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCollectionRenamePreservesAccessAndUnknownFields(t *testing.T) {
	var detail []byte
	var key []byte
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if r.URL.Path != "/api/organizations/org-1/collections/collection-1/details" {
				t.Error("details path")
			}
			_, _ = w.Write(detail)
			return
		}
		if r.Method != "PUT" || r.URL.Path != "/api/organizations/org-1/collections/collection-1" {
			t.Error("update route")
		}
		var got, original map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.Unmarshal(detail, &original)
		for _, field := range []string{"users", "groups", "externalId", "extension"} {
			if string(got[field]) != string(original[field]) {
				t.Errorf("lost %s", field)
			}
		}
		var encrypted string
		_ = json.Unmarshal(got["name"], &encrypted)
		plain, err := vaultcrypto.DecryptString(encrypted, key)
		if err != nil || string(plain) != "改名" {
			t.Error("name encryption", err)
		}
		clear(plain)
		writes++
		_, _ = w.Write([]byte(`{"id":"collection-1","organizationId":"org-1"}`))
	}))
	defer server.Close()
	s, vault, orgKey, _ := organizationFixture(t, server.URL)
	defer s.Close()
	key = orgKey
	vault = acceptedCollectionManagerVault(t, s, vault)
	detail = collectionDetailFixture(t, key)
	draft, err := s.CollectionDetails(context.Background(), vault, "org-1", "collection-1", nil)
	if err != nil || draft.Name != "集合原名称" {
		t.Fatal(draft, err)
	}
	defer draft.Close()
	draft.Name = "改名"
	if err := s.SaveCollection(context.Background(), vault, draft, nil, nil); err != nil || writes != 1 {
		t.Fatal(err, writes)
	}
	// A fresh server change must not be silently overwritten by a stale form.
	var changed map[string]json.RawMessage
	_ = json.Unmarshal(detail, &changed)
	changed["users"] = json.RawMessage(`[]`)
	detail, _ = json.Marshal(changed)
	if err := s.SaveCollection(context.Background(), vault, draft, nil, nil); err != ErrConflict || writes != 1 {
		t.Fatal("overwrote access change", err, writes)
	}
}

func TestCollectionCreateRoleRevisionAndIdentityGuards(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/api/organizations/org-1/collections" {
			t.Error("create route")
		}
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		if string(body["users"]) != "[]" || string(body["groups"]) != "[]" {
			t.Error("new collection access")
		}
		_, _ = w.Write([]byte(`{"id":"new-collection","organizationId":"other-org"}`))
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	if _, err := s.CollectionDetails(context.Background(), vault, "org-1", "", nil); err != ErrPermission {
		t.Fatal(err)
	}
	vault = acceptedCollectionManagerVault(t, s, vault)
	draft, err := s.CollectionDetails(context.Background(), vault, "org-1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	draft.Name = "新集合"
	if err := s.SaveCollection(context.Background(), nil, draft, nil, nil); err != ErrExpired {
		t.Fatal(err)
	}
	draft.revision = "stale"
	if err := s.SaveCollection(context.Background(), vault, draft, nil, nil); err != ErrExpired || calls.Load() != 0 {
		t.Fatal(err)
	}
	draft.revision = s.authorizationRevision
	err = s.SaveCollection(context.Background(), vault, draft, nil, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
	manager := Organization{Type: 4, Permissions: map[string]bool{"createNewCollections": true}}
	if manager.CanCreateCollections() {
		t.Fatal("partial permission grants create")
	}
	manager.Permissions["editAnyCollection"], manager.Permissions["deleteAnyCollection"] = true, true
	if !manager.CanCreateCollections() {
		t.Fatal("valid accessAll manager rejected")
	}
}

func TestCollectionDeleteRequiresDurableIsolationAndNeverRetries(t *testing.T) {
	var calls atomic.Int32
	isolated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !isolated || r.Method != "DELETE" || r.URL.Path != "/api/organizations/org-1/collections/collection-1" {
			t.Error("delete before isolation or wrong route")
		}
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	vault = acceptedCollectionManagerVault(t, s, vault)
	draft := &CollectionDraft{id: "collection-1", organizationID: "org-1", scope: vault.Scope, revision: s.authorizationRevision}
	if err := s.DeleteCollection(context.Background(), vault, draft, nil, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if err := s.DeleteCollection(context.Background(), vault, draft, func(SessionCheckpoint) error { return errors.New("disk failed") }, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("request escaped")
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	err := s.DeleteCollection(context.Background(), vault, draft, func(SessionCheckpoint) error { isolated = true; return nil }, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}

func TestCollectionDetailsRejectsIncompletePermissionsAndInvalidIDs(t *testing.T) {
	for _, raw := range []string{`null`, `[{}]`, `[{"id":"m","readOnly":false,"hidePasswords":false}]`, `[{"id":"../member","readOnly":false,"hidePasswords":false,"manage":true}]`, `[{"id":"m","readOnly":false,"hidePasswords":false,"manage":true},{"id":"m","readOnly":false,"hidePasswords":false,"manage":true}]`} {
		if validateCollectionAccess(json.RawMessage(raw)) == nil {
			t.Fatal("accepted malformed access", raw)
		}
	}
}

func TestCollectionDeleteCancelAndLockAfterIsolationStayUnknown(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "lock-close"}[closeSession], func(t *testing.T) {
			received := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				close(received)
				<-release
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			vault = acceptedCollectionManagerVault(t, s, vault)
			draft := &CollectionDraft{id: "collection-1", organizationID: "org-1", scope: vault.Scope, revision: s.authorizationRevision}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			isolated := false
			done := make(chan error, 1)
			go func() {
				done <- s.DeleteCollection(ctx, vault, draft, func(SessionCheckpoint) error { isolated = true; return nil }, nil)
			}()
			select {
			case <-received:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("write not sent")
			}
			if closeSession {
				s.Close()
			} else {
				cancel()
			}
			close(release)
			select {
			case err := <-done:
				var unknown *MutationUncertainError
				if !isolated || !errors.As(err, &unknown) || calls.Load() != 1 {
					t.Fatal("isolation/cancellation boundary", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancel not honored")
			}
		})
	}
}

func TestCollectionCheckpointAndPrecancelBlockAllRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	vault = acceptedCollectionManagerVault(t, s, vault)
	draft, err := s.CollectionDetails(context.Background(), vault, "org-1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	draft.Name = "new"
	s.checkpointPending = true
	failure := errors.New("checkpoint disk failure")
	if err := s.SaveCollection(context.Background(), vault, draft, nil, func(SessionCheckpoint) error { return failure }); !errors.Is(err, failure) || calls.Load() != 0 {
		t.Fatal("checkpoint bypass", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.SaveCollection(ctx, vault, draft, nil, nil); err == nil || calls.Load() != 0 {
		t.Fatal("pre-cancel dispatch", err)
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	if err := s.SaveCollection(context.Background(), vault, draft, nil, func(SessionCheckpoint) error { return nil }); err == nil || calls.Load() != 1 || s.checkpointPending {
		t.Fatal("persisted refresh blocked or retried", err)
	}
}
