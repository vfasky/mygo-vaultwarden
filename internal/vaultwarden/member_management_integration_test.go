// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"testing"
)

// No SMTP is enabled here: an unregistered example.invalid invite stays invited.
// This proves reinvite/remove HTTP semantics, not delivery or mail-token acceptance.
func testLiveMemberLifecycle(t *testing.T, ctx context.Context, owner *Session, orgID string) {
	t.Helper()
	synced, err := owner.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.BindSnapshotRevision(synced.Scope, "member-lifecycle"); err != nil {
		t.Fatal(err)
	}
	directory, err := owner.OrganizationMembers(ctx, synced.Vault, orgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	email := "pending-" + fixtureUUID() + "@example.invalid"
	if err = owner.InviteOrganizationMember(ctx, synced.Vault, directory, email, 2, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, synced.Vault, orgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	id, self := "", ""
	for _, row := range directory.Members() {
		if row.Email == email {
			if row.Status != 0 {
				t.Fatal("invitation status")
			}
			id = row.ID
		}
		if row.UserID == owner.account {
			self = row.ID
		}
	}
	if id == "" || self == "" {
		t.Fatal("directory identities")
	}
	if err = owner.ChangeOrganizationMember(ctx, synced.Vault, directory, id, "reinvite", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = owner.ChangeOrganizationMember(ctx, synced.Vault, directory, id, "remove", nil, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, synced.Vault, orgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	for _, row := range directory.Members() {
		if row.ID == id {
			t.Fatal("removed invitation retained")
		}
	}
	err = owner.ChangeOrganizationMember(ctx, synced.Vault, directory, self, "remove", func(SessionCheckpoint) error { return nil }, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatal("last-owner guard", err)
	}
	t.Log("isolated 1.37.4 product single invite/reinvite/remove and last-owner rejection passed; no SMTP delivery exercised")
}
