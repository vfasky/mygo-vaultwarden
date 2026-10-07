// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func liveOrganizationMember(t *testing.T, ctx context.Context, server string) (*Session, *rsa.PublicKey) {
	t.Helper()
	client, err := NewClient(server, fixtureUUID())
	if err != nil {
		t.Fatal(err)
	}
	email := "org-member-" + fixtureUUID() + "@example.invalid"
	password := []byte("Public-member-fixture-password!")
	kdf := KDF{Type: 0, Iterations: 600000}
	master, err := DeriveMaster(password, email, kdf)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	stretched, _ := StretchMaster(master)
	defer clear(stretched)
	key := make([]byte, 64)
	_, _ = rand.Read(key)
	defer clear(key)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	defer clear(privateDER)
	publicDER, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	post := func(path string, body any) []byte {
		raw, _ := json.Marshal(body)
		status, data, err := client.request(ctx, "POST", path, "application/json", string(raw), "")
		if err != nil || status < 200 || status >= 300 {
			t.Fatalf("member registration %s: %d %v", path, status, err)
		}
		return data
	}
	raw := post("/identity/accounts/register/send-verification-email", map[string]string{"email": email, "name": "Isolated member"})
	var verification string
	_ = json.Unmarshal(raw, &verification)
	post("/identity/accounts/register/finish", map[string]any{"email": email, "name": "Isolated member", "emailVerificationToken": verification, "masterPasswordHash": AuthorizationHash(master, password), "key": encryptFixture(key, stretched), "kdf": 0, "kdfIterations": 600000, "keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString(publicDER), "encryptedPrivateKey": encryptFixture(privateDER, key)}})
	session, err := client.Login(ctx, email, password, nil)
	if err != nil {
		t.Fatal(err)
	}
	return session, &private.PublicKey
}

func testLiveOrganizationMemberPermissions(t *testing.T, ctx context.Context, owner *Session, orgID, collectionID, itemID string, orgKey []byte) {
	t.Helper()
	member, public := liveOrganizationMember(t, ctx, owner.client.base.String())
	defer member.Close()
	request := func(method, path string, body any) []byte {
		raw, _ := json.Marshal(body)
		status, data, err := owner.client.request(ctx, method, "/api/organizations/"+orgID+path, "application/json", string(raw), owner.access)
		if err != nil || status < 200 || status >= 300 {
			t.Fatalf("member fixture %s %s: %d %v", method, path, status, err)
		}
		return data
	}
	permission := func(ro, hp bool) map[string]any {
		return map[string]any{"id": collectionID, "readOnly": ro, "hidePasswords": hp, "manage": false}
	}
	ownerDirectory := func() (*VaultData, *MemberDirectory) {
		synced, err := owner.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.BindSnapshotRevision(synced.Scope, "member-management-"+fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		directory, err := owner.OrganizationMembers(ctx, synced.Vault, orgID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return synced.Vault, directory
	}
	ownerVault, directory := ownerDirectory()
	if err := owner.InviteOrganizationMember(ctx, ownerVault, directory, member.email, 2, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	accepted, err := member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orgs, _, err := member.Organizations(accepted.Vault)
	if err != nil || len(orgs) != 0 {
		t.Fatal("accepted member got keys", err)
	}
	var users struct {
		Data []struct{ ID, UserID, Email string }
	}
	if json.Unmarshal(request("GET", "/users", nil), &users) != nil {
		t.Fatal("users fixture")
	}
	memberID := ""
	for _, user := range users.Data {
		if user.Email == member.email {
			memberID = user.ID
			if user.UserID != accepted.Scope.Account || memberID == accepted.Scope.Account {
				t.Fatal("member/global identity confusion")
			}
		}
	}
	if memberID == "" {
		t.Fatal("member missing")
	}
	ownerVault, directory = ownerDirectory()
	proof, err := owner.PrepareMemberConfirmation(ctx, ownerVault, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	trustedDER, _ := x509.MarshalPKIXPublicKey(public)
	trustedSPKI := base64.StdEncoding.EncodeToString(trustedDER)
	if proof.PublicKey() != trustedSPKI {
		t.Fatal("recipient key mismatch")
	}
	if err := owner.ConfirmOrganizationMember(ctx, ownerVault, proof, trustedSPKI, nil); err != nil {
		t.Fatal(err)
	}
	proof.Close()
	directory.Close()
	ownerVault, directory = ownerDirectory()
	collectionDraft, err := owner.CollectionDetails(ctx, ownerVault, orgID, collectionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	accessDraft, err := owner.CollectionAccessDetails(ctx, ownerVault, collectionDraft, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range accessDraft.Access {
		if accessDraft.Access[i].ID == memberID {
			accessDraft.Access[i].Assigned = true
			accessDraft.Access[i].ReadOnly = false
			accessDraft.Access[i].HidePasswords = false
		}
	}
	if err := owner.SaveCollection(ctx, ownerVault, accessDraft, func(SessionCheckpoint) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	collectionDraft.Close()
	accessDraft.Close()
	directory.Close()
	sync, err := member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-write")
	doc, fields, err := member.ReadOrganizationCipher(sync.Vault, itemID, nil)
	if err != nil || !fields.Edit {
		t.Fatal("confirmed writable member", err)
	}
	fields.Name = "成员更新"
	if _, err := member.UpdateOrganizationCipher(ctx, sync.Vault, doc, fields, nil, nil); err != nil {
		t.Fatal("member update", err)
	}
	// Exercise the product with a collection-scoped manager, then an accessAll
	// manager. Profile uses three permission flags, never an accessAll field.
	managerPermissions := map[string]bool{"createNewCollections": false, "editAnyCollection": false, "deleteAnyCollection": false}
	managerCollection := map[string]any{"id": collectionID, "readOnly": false, "hidePasswords": false, "manage": true}
	request("PUT", "/users/"+memberID, map[string]any{"type": 4, "permissions": managerPermissions, "groups": []string{}, "collections": []any{managerCollection}})
	managerSync, err := member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(managerSync.Scope, "scoped-manager-collection")
	if _, err := member.CollectionDetails(ctx, managerSync.Vault, orgID, "", nil); err != ErrPermission {
		t.Fatal("scoped manager created collection", err)
	}
	managerDraft, err := member.CollectionDetails(ctx, managerSync.Vault, orgID, collectionID, nil)
	if err != nil {
		t.Fatal("scoped manager details", err)
	}
	managerAccess, err := member.CollectionAccessDetails(ctx, managerSync.Vault, managerDraft, nil)
	if err != nil {
		t.Fatal("scoped manager mini-directory", err)
	}
	managerAccess.Close()
	managerDraft.Name = "经理更名后的集合"
	if err := member.SaveCollection(ctx, managerSync.Vault, managerDraft, nil, nil); err != nil {
		t.Fatal("scoped manager rename", err)
	}
	managerDraft.Close()
	for key := range managerPermissions {
		managerPermissions[key] = true
	}
	var retainedGroup struct{ ID string }
	_ = json.Unmarshal(request("POST", "/groups", map[string]any{"name": "Retained membership group", "accessAll": false, "users": []string{memberID}, "collections": []any{}}), &retainedGroup)
	if retainedGroup.ID == "" {
		t.Fatal("group fixture")
	}
	ownerVault, directory = ownerDirectory()
	roleDraft, err := owner.PrepareMemberRole(ctx, ownerVault, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	roleDraft.Role, roleDraft.ManageAllCollections = 4, true
	consent := roleDraft.ConfirmCollectionReset()
	if err := owner.SaveMemberRole(ctx, ownerVault, roleDraft, consent, nil, nil); err != nil {
		t.Fatal(err)
	}
	consent.Close()
	roleDraft.Close()
	directory.Close()
	testLiveCollections(t, ctx, member, managerSync.Scope, orgID)
	ownerVault, directory = ownerDirectory()
	roleDraft, err = owner.PrepareMemberRole(ctx, ownerVault, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(roleDraft.collections) != 0 || len(roleDraft.groups) != 1 || roleDraft.groups[0] != retainedGroup.ID {
		t.Fatal("access-all reset or group retention mismatch")
	}
	roleDraft.Role, roleDraft.ManageAllCollections = 2, false
	if err = owner.SaveMemberRole(ctx, ownerVault, roleDraft, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	roleDraft.Close()
	directory.Close()
	ownerVault, directory = ownerDirectory()
	roleDraft, err = owner.PrepareMemberRole(ctx, ownerVault, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(roleDraft.collections) != 0 || len(roleDraft.groups) != 1 {
		t.Fatal("downgrade invented old assignments")
	}
	roleDraft.Close()
	directory.Close()
	request("PUT", "/users/"+memberID, map[string]any{"type": 2, "groups": []string{}, "collections": []any{permission(false, false)}})
	memberSync, err := member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(memberSync.Scope, "ordinary-member-no-collection-admin")
	if _, err := member.CollectionDetails(ctx, memberSync.Vault, orgID, collectionID, nil); err != ErrPermission {
		t.Fatal("ordinary member management", err)
	}
	groupRaw := request("POST", "/groups", map[string]any{"name": "Writable fixture group", "accessAll": false, "users": []string{memberID}, "collections": []any{permission(false, false)}})
	var group struct{ ID string }
	_ = json.Unmarshal(groupRaw, &group)
	if group.ID == "" {
		t.Fatal("group ID")
	}
	for _, tc := range []struct {
		name   string
		ro, hp bool
	}{{"read-only", true, false}, {"hidden-password", false, true}} {
		setLiveCollectionMemberAccess(t, ctx, owner, orgID, collectionID, memberID, true, tc.ro, tc.hp)
		sync, err = member.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = member.BindSnapshotRevision(sync.Scope, "member-"+tc.name)
		// Direct grants for the same collection override the group's broader grant.
		_, cs, err := member.Organizations(sync.Vault)
		if err != nil || len(cs) != 1 || cs[0].ReadOnly != tc.ro || cs[0].HidePasswords != tc.hp {
			t.Fatal("direct-over-group collection flags", tc.name, err)
		}
		doc, fields, err = member.ReadOrganizationCipher(sync.Vault, itemID, nil)
		if tc.hp {
			if err != ErrPermission {
				t.Fatal("hidden-password read", err)
			}
		} else {
			if err != nil || fields.Edit {
				t.Fatal("read-only member", err)
			}
			fields.Name = "forbidden"
			if _, err := member.UpdateOrganizationCipher(ctx, sync.Vault, doc, fields, nil, nil); err != ErrPermission {
				t.Fatal("read-only update", err)
			}
		}
		present := false
		for _, c := range sync.Credentials {
			if c.ID == itemID {
				present = true
			}
		}
		if present == tc.hp {
			t.Fatal("member AutoFill permission projection", tc.name)
		}
	}
	// Removing the direct assignment exposes the existing group grant.
	setLiveCollectionMemberAccess(t, ctx, owner, orgID, collectionID, memberID, false, false, false)
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-group")
	_, fields, err = member.ReadOrganizationCipher(sync.Vault, itemID, nil)
	if err != nil || !fields.Edit {
		t.Fatal("group grant absent", err)
	}
	// Multiple collection restrictions use AND, after resolving direct grants
	// ahead of group grants for each collection.
	secondName, _ := EncryptString([]byte("第二个测试集合"), orgKey)
	secondRaw := request("POST", "/collections", map[string]any{"name": secondName, "groups": []any{}, "users": []any{map[string]any{"id": memberID, "readOnly": false, "hidePasswords": false, "manage": false}}})
	var second struct{ ID string }
	_ = json.Unmarshal(secondRaw, &second)
	if !validObjectID(second.ID) {
		t.Fatal("second collection missing")
	}
	request("PUT", "/users/"+memberID, map[string]any{"type": 2, "groups": []string{group.ID}, "collections": []any{permission(true, true), map[string]any{"id": second.ID, "readOnly": false, "hidePasswords": false, "manage": false}}})
	body, _ := json.Marshal(map[string]any{"collectionIds": []string{collectionID, second.ID}})
	status, _, err := owner.client.request(ctx, "PUT", "/api/ciphers/"+itemID+"/collections", "application/json", string(body), owner.access)
	if err != nil || status != 200 {
		t.Fatal("mixed collections fixture", status, err)
	}
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-mixed")
	_, fields, err = member.ReadOrganizationCipher(sync.Vault, itemID, nil)
	if err != nil || !fields.Edit || !fields.ViewPassword {
		t.Fatal("multi-collection effective permission", err)
	}
	request("PUT", "/users/"+memberID, map[string]any{"type": 2, "groups": []string{}, "collections": []any{permission(true, true)}})
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-collection-removed")
	if _, _, err := member.ReadOrganizationCipher(sync.Vault, itemID, nil); err != ErrPermission {
		t.Fatal("collection removal retained read", err)
	}
	for _, credential := range sync.Credentials {
		if credential.ID == itemID {
			t.Fatal("collection removal retained AutoFill")
		}
	}
	ownerVault, directory = ownerDirectory()
	if err := owner.ChangeOrganizationMember(ctx, ownerVault, directory, memberID, "revoke", nil, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-revoked")
	if _, _, err := member.ReadOrganizationCipher(sync.Vault, itemID, nil); err != ErrNotFound && err != ErrPermission {
		t.Fatal("revoked member access", err)
	}
	for _, c := range sync.Credentials {
		if c.ID == itemID {
			t.Fatal("revoked projection resurrected")
		}
	}
	ownerVault, directory = ownerDirectory()
	if err := owner.ChangeOrganizationMember(ctx, ownerVault, directory, memberID, "restore", nil, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = member.BindSnapshotRevision(sync.Scope, "member-voluntary-leave")
	if err := member.LeaveOrganization(ctx, sync.Vault, orgID, func(SessionCheckpoint) error { return nil }, nil); err != nil {
		t.Fatal("product member leave", err)
	}
	sync, err = member.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	remaining, _, err := member.Organizations(sync.Vault)
	if err != nil || len(remaining) != 0 {
		t.Fatal("member leave persisted", err)
	}
	t.Log("isolated organization member: accepted denied, confirmed write, direct-over-group readOnly/hidePasswords, group fallback, mixed collections, collection removal, revoke, product voluntary leave and AutoFill replacement passed")
}
