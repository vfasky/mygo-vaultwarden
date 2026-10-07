// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// All accounts and writes belong to the caller's disposable loopback fixture.
func liveOrgModuleRoles(t *testing.T, ctx context.Context, owner *Session, orgID, collectionID, itemID string) {
	t.Helper()
	member, public := liveOrganizationMember(t, ctx, owner.client.base.String())
	defer member.Close()
	sync := func(s *Session) *VaultData {
		r, err := s.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return r.Vault
	}
	ov := sync(owner)
	directory, err := owner.OrganizationMembers(ctx, ov, orgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.InviteOrganizationMember(ctx, ov, directory, member.email, 2, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	ov = sync(owner)
	directory, err = owner.OrganizationMembers(ctx, ov, orgID, nil)
	if err != nil {
		t.Fatal(err)
	}
	membership := ""
	for _, m := range directory.Members() {
		if m.Email == member.email {
			membership = m.ID
		}
	}
	if membership == "" || membership == member.account {
		t.Fatal("membership identity")
	}
	proof, err := owner.PrepareMemberConfirmation(ctx, ov, directory, membership, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	trusted := base64.StdEncoding.EncodeToString(der)
	if proof.PublicKey() != trusted {
		t.Fatal("recipient identity")
	}
	if err := owner.ConfirmOrganizationMember(ctx, ov, proof, trusted, nil); err != nil {
		t.Fatal(err)
	}
	proof.Close()
	directory.Close()
	request := func(method, path string, body any) []byte {
		raw, _ := json.Marshal(body)
		status, data, err := owner.client.request(ctx, method, "/api/organizations/"+orgID+path, "application/json", string(raw), owner.access)
		if err != nil || status < 200 || status >= 300 {
			t.Fatalf("role fixture %s %s: %d %v", method, path, status, err)
		}
		return data
	}
	setRole := func(role int, readOnly, hidden bool, groups []string) {
		request("PUT", "/users/"+membership, map[string]any{"type": role, "accessAll": false, "groups": groups, "collections": []any{map[string]any{"id": collectionID, "readOnly": readOnly, "hidePasswords": hidden, "manage": false}}})
	}
	for _, tc := range []struct {
		name                      string
		role                      int
		readOnly, hidden, allowed bool
	}{{"member", 2, false, false, true}, {"readonly", 2, true, false, false}, {"hidden", 2, false, true, false}, {"admin", 1, false, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			setRole(tc.role, tc.readOnly, tc.hidden, []string{})
			v := sync(member)
			_, eventErr := member.OrganizationEvents(ctx, v, OrganizationEventQuery{OrganizationID: orgID, Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Minute)}, nil)
			if tc.role == 1 && eventErr != nil {
				t.Fatal("admin events", eventErr)
			}
			if tc.role != 1 && eventErr != ErrPermission {
				t.Fatal("member events", eventErr)
			}
			exportErr := member.WithOrganizationBackup(ctx, v, orgID, nil, true, func([]byte) error { return nil }, nil)
			if tc.role == 1 && exportErr != nil {
				t.Fatal("admin export", exportErr)
			}
			if tc.role != 1 && exportErr != ErrPermission {
				t.Fatal("member export", exportErr)
			}
			_, err := member.CopyOrganizationCipher(ctx, v, itemID, orgID, collectionID, nil, nil)
			if tc.allowed && err != nil {
				t.Fatal("allowed copy", err)
			}
			if !tc.allowed && err != ErrPermission {
				t.Fatal("restricted copy", err)
			}
			result, err := member.ChangeOrganizationCiphers(ctx, v, orgID, []string{itemID}, CipherArchive, nil, nil)
			if tc.allowed {
				if err != nil || !result.Applied {
					t.Fatal("allowed state", err)
				}
				v = sync(member)
				if _, err := member.ChangeOrganizationCiphers(ctx, v, orgID, []string{itemID}, CipherUnarchive, nil, nil); err != nil {
					t.Fatal(err)
				}
			} else if err != ErrPermission {
				t.Fatal("restricted state", err)
			}
		})
	}
	// Group-derived access is independently exercised with no direct collection.
	var group struct{ ID string }
	json.Unmarshal(request("POST", "/groups", map[string]any{"name": "Module access group", "accessAll": false, "users": []string{membership}, "collections": []any{map[string]any{"id": collectionID, "readOnly": false, "hidePasswords": false, "manage": false}}}), &group)
	if group.ID == "" {
		t.Fatal("group identity")
	}
	request("PUT", "/users/"+membership, map[string]any{"type": 2, "accessAll": false, "groups": []string{group.ID}, "collections": []any{}})
	v := sync(member)
	if _, err := member.CopyOrganizationCipher(ctx, v, itemID, orgID, collectionID, nil, nil); err != nil {
		t.Fatal("group copy", err)
	}
	// Live revocation must reject an old, formerly writable authenticated snapshot.
	request("PUT", "/users/"+membership+"/revoke", map[string]any{})
	if _, err := member.CopyOrganizationCipher(ctx, v, itemID, orgID, collectionID, nil, nil); err != ErrPermission && err != ErrExpired {
		t.Fatal("revoked copy", err)
	}
	request("DELETE", "/users/"+membership, nil)
	request("DELETE", "/groups/"+group.ID, nil)
}
