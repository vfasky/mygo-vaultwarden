// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
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
		if err := owner.AcceptAuthenticatedSnapshot(result.Vault, fixtureUUID()); err != nil {
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
	if _, err := owner.CreateOrganizationCipher(ctx, v, org.ID, collections[0].ID, CipherFields{Type: 2, Name: "Unique import observation", SecureNote: map[string]any{"type": 0}}, nil); err != nil {
		t.Fatal(err)
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
	if result.ImportReconciliation == nil || !result.ImportReconciliation.ReadCompleted || len(result.ImportReconciliation.AddedIDs) != 3 {
		t.Fatal("live import fresh differences", result.ImportReconciliation)
	}
	verified := 0
	for _, row := range result.ImportReconciliation.Items {
		if row.Verified {
			verified++
		}
	}
	if verified != 1 {
		t.Fatal("expected unique item verified and duplicate items unknown", result.ImportReconciliation.Items)
	}
	v = syncVault()
	entries, err := owner.OrganizationEntries(v)
	if err != nil || len(entries) != 6 {
		t.Fatal("live import count", len(entries), err)
	}
	var officialPlan *OrganizationImportPlan
	if err := owner.WithBitwardenOrganizationJSON(ctx, v, org.ID, nil, true, func(raw []byte) error {
		var err error
		officialPlan, err = ParseBitwardenOrganizationJSON(raw)
		return err
	}, nil); err != nil {
		t.Fatal("official organization plaintext", err)
	}
	if len(officialPlan.PreviewItems()) != 6 {
		t.Fatal("official preview")
	}
	if result, err := owner.ImportOrganizationBackup(ctx, v, org.ID, officialPlan, map[string]string{collections[0].ID: collections[0].ID}, true, nil); err != nil || result.ImportReconciliation == nil || !result.ImportReconciliation.ReadCompleted {
		t.Fatal("official import", err)
	}
	officialPlan.Clear()
	liveOrgModuleRoles(t, ctx, owner, org.ID, collections[0].ID, identity.ID)
	v = syncVault()
	if err := owner.CollectOrganizationEvents(ctx, v, []OrganizationClientEvent{{Type: 1107, Date: time.Now().UTC(), OrganizationID: org.ID, CipherID: identity.ID}}, nil); err != nil {
		t.Fatal("live collect", err)
	}
	page, err := owner.OrganizationEvents(ctx, v, OrganizationEventQuery{OrganizationID: org.ID, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute)}, nil)
	if err != nil || len(page.Data) == 0 {
		t.Fatal("live events", len(page.Data), err)
	}
	organizations, _, err := owner.Organizations(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []OrganizationEventQuery{{OrganizationID: org.ID, CipherID: identity.ID, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute)}, {OrganizationID: org.ID, MemberID: organizations[0].OrganizationUserID, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute)}} {
		if _, err := owner.OrganizationEvents(ctx, v, query, nil); err != nil {
			t.Fatal("filtered events", err)
		}
	}
	var secret []byte
	if err := owner.WithOrganizationAPIKey(ctx, v, org.ID, []byte("Public-member-fixture-password!"), false, true, func(_ string, key []byte, _ time.Time) error { secret = append([]byte(nil), key...); return nil }, nil); err != nil {
		t.Fatal("live API key", err)
	}
	defer func() { clear(secret) }()
	if err := owner.WithOrganizationAPIKey(ctx, v, org.ID, []byte("Public-member-fixture-password!"), true, true, func(_ string, key []byte, _ time.Time) error {
		if bytes.Equal(secret, key) {
			t.Fatal("rotation retained old key")
		}
		clear(secret)
		secret = append([]byte(nil), key...)
		return nil
	}, nil); err != nil {
		t.Fatal("live API key rotation", err)
	}
	// Owner is never removed by the official directory importer. Update only this
	// disposable owner's external ID, avoiding email invitations or other users.
	directory, err := owner.ImportOrganizationDirectory(ctx, v, org.ID, secret, OrganizationDirectoryImport{Members: []OrganizationDirectoryMember{{Email: owner.email, ExternalID: "board8-owner"}}, Groups: []OrganizationDirectoryGroup{{Name: "Directory group", ExternalID: "board8-directory-group", MemberExternalIDs: []string{"board8-owner"}}}}, true, isolate)
	if err != nil || !directory.RequestAccepted || !directory.ReconcileRequired {
		t.Fatal("live directory", directory, err)
	}
	if directory.Reconciliation == nil || directory.Reconciliation.Before == nil || directory.Reconciliation.After == nil || len(directory.Reconciliation.Rows) != 2 || !directory.Reconciliation.Rows[0].Verified || !directory.Reconciliation.Rows[1].Verified {
		t.Fatal("live directory re-read", directory.Reconciliation)
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
