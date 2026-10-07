// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"testing"
)

func testLiveCollections(t *testing.T, ctx context.Context, s *Session, scope Scope, orgID string) {
	t.Helper()
	synced, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "live-collection-create")
	draft, err := s.CollectionDetails(ctx, synced.Vault, orgID, "", nil)
	if err != nil {
		t.Fatal("new collection draft", err)
	}
	draft.Name = "产品集合新增"
	if err := s.SaveCollection(ctx, synced.Vault, draft, nil, nil); err != nil {
		t.Fatal("product collection create", err)
	}
	draft.Close()
	synced, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, collections, err := s.Organizations(synced.Vault)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, collection := range collections {
		if collection.OrganizationID == orgID && collection.Name == "产品集合新增" {
			id = collection.ID
		}
	}
	if id == "" {
		t.Fatal("new collection absent from sync")
	}
	_ = s.BindSnapshotRevision(scope, "live-collection-rename")
	draft, err = s.CollectionDetails(ctx, synced.Vault, orgID, id, nil)
	if err != nil {
		t.Fatal("product collection details", err)
	}
	draft.Name = "产品集合改名"
	if err := s.SaveCollection(ctx, synced.Vault, draft, nil, nil); err != nil {
		t.Fatal("product collection rename", err)
	}
	draft.Close()
	draft, err = s.CollectionDetails(ctx, synced.Vault, orgID, id, nil)
	if err != nil || draft.Name != "产品集合改名" {
		t.Fatal("rename roundtrip", err)
	}
	// Protocol-only fixture; product supplies the mandatory Swift durable callback.
	if err := s.DeleteCollection(ctx, synced.Vault, draft, func(SessionCheckpoint) error { return nil }, nil); err != nil {
		t.Fatal("product collection delete", err)
	}
	draft.Close()
	synced, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, collections, err = s.Organizations(synced.Vault)
	if err != nil {
		t.Fatal(err)
	}
	for _, collection := range collections {
		if collection.ID == id {
			t.Fatal("deleted collection resurrected")
		}
	}
	t.Log("isolated 1.37.4 product collection create/details/rename/delete passed; durable store tested separately")
}

func setLiveCollectionMemberAccess(t *testing.T, ctx context.Context, s *Session, orgID, collectionID, memberID string, assigned, readOnly, hidePasswords bool) {
	t.Helper()
	synced, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(synced.Scope, "live-collection-access")
	draft, err := s.CollectionDetails(ctx, synced.Vault, orgID, collectionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	access, err := s.CollectionAccessDetails(ctx, synced.Vault, draft, nil)
	if err != nil {
		t.Fatal("product access directory", err)
	}
	defer access.Close()
	found := false
	for i := range access.Access {
		row := &access.Access[i]
		if !row.Group && row.ID == memberID {
			found = true
			row.Assigned, row.ReadOnly, row.HidePasswords, row.Manage = assigned, readOnly, hidePasswords, false
		}
	}
	if !found {
		t.Fatal("membership missing from directory")
	}
	// HTTP fixture only; production uses Swift durable organization isolation.
	if err := s.SaveCollection(ctx, synced.Vault, access, func(SessionCheckpoint) error { return nil }, nil); err != nil {
		t.Fatal("product member access configuration", err)
	}
}
