// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveOrgModule(t *testing.T) {
	server := os.Getenv("MYGO_ORG_MODULE_TEST_URL")
	if server == "" {
		t.Skip("set MYGO_ORG_MODULE_TEST_URL to an owned isolated fixture")
	}
	if !strings.HasPrefix(server, "http://127.0.0.1:") {
		t.Fatal("non-loopback fixture refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, _ := liveOrganizationMember(t, ctx, server)
	defer owner.Close()
	syncVault := func() *VaultData {
		result, err := owner.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.BindSnapshotRevision(result.Scope, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return result.Vault
	}
	v := syncVault()
	org, err := owner.SaveOrganization(ctx, v, "", OrganizationSettings{Name: "Board8 isolated module", BillingEmail: owner.email, CollectionName: "Module collection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	isolate := func(SessionCheckpoint) error { return nil } // Disposable fixture only; not storage evidence.
	defer func() {
		v = syncVault()
		if err := owner.DeleteOrganization(ctx, v, org.ID, []byte("Public-member-fixture-password!"), isolate, nil); err != nil {
			t.Error(err)
		}
	}()
	v = syncVault()
	_, collections, err := owner.Organizations(v)
	if err != nil || len(collections) != 1 {
		t.Fatal(err)
	}
	created, err := owner.CreateOrganizationCipher(ctx, v, org.ID, collections[0].ID, CipherFields{Type: 1, Name: "Board8 live item", Login: map[string]any{"username": "fixture", "password": "public-test-password"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var identity struct{ ID string }
	if json.Unmarshal(created.JSON, &identity) != nil || identity.ID == "" {
		t.Fatal("created identity")
	}
	for _, action := range []CipherAction{CipherArchive, CipherUnarchive, CipherTrash, CipherRestore} {
		v = syncVault()
		result, err := owner.ChangeOrganizationCiphers(ctx, v, org.ID, []string{identity.ID}, action, nil, nil)
		if err != nil || !result.Applied {
			t.Fatal("live state", action, result, err)
		}
	}
	v = syncVault()
	if _, err := owner.CopyOrganizationCipher(ctx, v, identity.ID, org.ID, collections[0].ID, nil, nil); err != nil {
		t.Fatal("live copy", err)
	}
	v = syncVault()
	var backup []byte
	if err := owner.WithOrganizationBackup(ctx, v, org.ID, nil, true, func(data []byte) error { backup = append([]byte(nil), data...); return nil }, nil); err != nil {
		t.Fatal("live export", err)
	}
	defer clear(backup)
	plan, err := ParseOrganizationImport(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	result, err := owner.ImportOrganizationBackup(ctx, v, org.ID, plan, map[string]string{collections[0].ID: collections[0].ID}, true, nil)
	if err != nil || !result.ReconcileRequired || result.Applied {
		t.Fatal("live import", result, err)
	}
	v = syncVault()
	entries, err := owner.OrganizationEntries(v)
	if err != nil || len(entries) != 4 {
		t.Fatal("live import count", len(entries), err)
	}
	if err := owner.CollectOrganizationEvents(ctx, v, []OrganizationClientEvent{{Type: 1107, Date: time.Now().UTC(), OrganizationID: org.ID, CipherID: identity.ID}}, nil); err != nil {
		t.Fatal("live collect", err)
	}
	page, err := owner.OrganizationEvents(ctx, v, OrganizationEventQuery{OrganizationID: org.ID, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute)}, nil)
	if err != nil || len(page.Data) == 0 {
		t.Fatal("live events", len(page.Data), err)
	}
	var secret []byte
	if err := owner.WithOrganizationAPIKey(ctx, v, org.ID, []byte("Public-member-fixture-password!"), false, true, func(_ string, key []byte, _ time.Time) error { secret = append([]byte(nil), key...); return nil }, nil); err != nil {
		t.Fatal("live API key", err)
	}
	defer clear(secret)
	// Owner is never removed by the official directory importer. Update only this
	// disposable owner's external ID, avoiding email invitations or other users.
	directory, err := owner.ImportOrganizationDirectory(ctx, v, org.ID, secret, OrganizationDirectoryImport{Members: []OrganizationDirectoryMember{{Email: owner.email, ExternalID: "board8-owner"}}}, true, isolate)
	if err != nil || !directory.RequestAccepted || !directory.ReconcileRequired {
		t.Fatal("live directory", directory, err)
	}
	v = syncVault()
	if err := owner.AssignOrganizationCipherCollections(ctx, v, org.ID, identity.ID, []string{collections[0].ID}, nil, isolate, nil); err != nil {
		t.Fatal("live collections", err)
	}
	v = syncVault()
	if _, err := owner.ChangeOrganizationCiphers(ctx, v, org.ID, []string{identity.ID}, CipherTrash, nil, nil); err != nil {
		t.Fatal(err)
	}
	v = syncVault()
	if _, err := owner.ChangeOrganizationCiphers(ctx, v, org.ID, []string{identity.ID}, CipherDeletePermanently, nil, nil); err != nil {
		t.Fatal(err)
	}
}
