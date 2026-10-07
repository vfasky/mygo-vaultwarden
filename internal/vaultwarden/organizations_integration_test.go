// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"testing"
)

func testLiveOrganizations(t *testing.T, ctx context.Context, s *Session, scope Scope, password []byte) {
	t.Helper()
	sync, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "live-organization-management")
	org, err := s.SaveOrganization(ctx, sync.Vault, "", OrganizationSettings{Name: "MyGo isolated organization", BillingEmail: s.email, CollectionName: "真实集合"}, nil)
	if err != nil {
		t.Fatal("product create organization", err)
	}
	// The fixture has no persistent local store; Swift tests exercise the durable
	// isolation callback separately. Never use this no-op callback in product code.
	fixtureIsolate := func(SessionCheckpoint) error { return nil }
	defer func() {
		latest, err := s.Sync(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		_ = s.BindSnapshotRevision(scope, "live-organization-delete")
		if err := s.DeleteOrganization(ctx, latest.Vault, org.ID, password, fixtureIsolate, nil); err != nil {
			t.Error("product organization delete", err)
		}
	}()
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s.OrganizationProfile(ctx, sync.Vault, org.ID, nil)
	if err != nil || profile.BillingEmail != s.email {
		t.Fatal("organization profile", err)
	}
	if _, err := s.SaveOrganization(ctx, sync.Vault, org.ID, OrganizationSettings{Name: "Product organization updated", BillingEmail: s.email}, nil); err != nil {
		t.Fatal("organization update", err)
	}
	profile, err = s.OrganizationProfile(ctx, sync.Vault, org.ID, nil)
	if err != nil || profile.Name != "Product organization updated" {
		t.Fatal("organization update roundtrip", err)
	}
	err = s.LeaveOrganization(ctx, sync.Vault, org.ID, fixtureIsolate, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatal("last owner allowed to leave", err)
	}
	s.mu.Lock()
	data, err := s.organizationVaultLocked(sync.Vault)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer data.close()
	key := data.keys[org.ID]
	organizations, collections, err := s.Organizations(sync.Vault)
	if err != nil || len(organizations) != 1 || len(collections) != 1 || collections[0].Name != "真实集合" || organizations[0].UserID != scope.Account || organizations[0].OrganizationUserID == scope.Account {
		t.Fatal("live organization decode", err)
	}
	testLiveCollections(t, ctx, s, scope, org.ID)
	if err := s.BindSnapshotRevision(scope, "live-organization-1"); err != nil {
		t.Fatal(err)
	}
	created, err := s.CreateOrganizationCipher(ctx, sync.Vault, org.ID, collections[0].ID, CipherFields{Type: 1, Name: "组织登录", Login: map[string]any{"username": "member@example.invalid", "password": "org fixture password"}}, nil)
	if err != nil {
		t.Fatal("live organization create cipher", err)
	}
	fields, err := DecryptCipherDocument(created, key)
	if err != nil {
		t.Fatal(err)
	}
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "live-organization-2")
	doc, fields, err := s.ReadOrganizationCipher(sync.Vault, fields.ID, nil)
	if err != nil {
		t.Fatal("live read organization", err)
	}
	fields.Name = "组织更新"
	fields.Login["password"] = "changed org password"
	if _, err := s.UpdateOrganizationCipher(ctx, sync.Vault, doc, fields, nil, nil); err != nil {
		t.Fatal("live update organization", err)
	}
	personal, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 1, Name: "待共享", Login: map[string]any{"password": "shared password"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	personalFields, err := DecryptCipherDocument(personal, s.key)
	if err != nil {
		t.Fatal(err)
	}
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "live-organization-3")
	personal, personalFields, err = s.ReadPersonalCipherAuthorized(sync.Vault, personalFields.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SharePersonalCipher(ctx, sync.Vault, org.ID, collections[0].ID, personal, personalFields, nil, nil); err != nil {
		t.Fatal("live share", err)
	}
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "live-organization-4")
	_, shared, err := s.ReadOrganizationCipher(sync.Vault, personalFields.ID, nil)
	if err != nil || shared.Login["password"] != "shared password" {
		t.Fatal("live share key wrapping", err)
	}
	_, updated, err := s.ReadOrganizationCipher(sync.Vault, fields.ID, nil)
	if err != nil || updated.Name != "组织更新" || updated.Login["password"] != "changed org password" || len(updated.PasswordHistory) != 1 {
		t.Fatal("live organization update roundtrip", err)
	}
	projected := map[string]bool{}
	for _, credential := range sync.Credentials {
		projected[credential.ID] = true
	}
	if !projected[fields.ID] || !projected[personalFields.ID] {
		t.Fatal("authorized organization Login projection missing")
	}
	testLiveOrganizationMemberPermissions(t, ctx, s, org.ID, collections[0].ID, fields.ID, key)
	testLiveMemberLifecycle(t, ctx, s, org.ID)
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "owner-protected-1")
	doc, fields, err = s.ReadOrganizationCipher(sync.Vault, fields.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields.Reprompt = 1
	if _, err := s.UpdateOrganizationCipher(ctx, sync.Vault, doc, fields, nil, nil); err != nil {
		t.Fatal("organization set reprompt", err)
	}
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.BindSnapshotRevision(scope, "owner-protected-2")
	for _, credential := range sync.Credentials {
		if credential.ID == fields.ID {
			t.Fatal("organization reprompt entered AutoFill")
		}
	}
	if _, _, err := s.ReadOrganizationCipher(sync.Vault, fields.ID, nil); err != ErrPermission {
		t.Fatal("organization reprompt bypass", err)
	}
	grant, err := s.AuthorizeOrganizationItem(ctx, sync.Vault, "owner-protected-2", fields.ID, password)
	if err != nil {
		t.Fatal("live organization reprompt", err)
	}
	doc, fields, err = s.ReadOrganizationCipher(sync.Vault, fields.ID, grant)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "组织再次验证更新"
	if _, err := s.UpdateOrganizationCipher(ctx, sync.Vault, doc, fields, grant, nil); err != nil {
		t.Fatal("authorized organization update", err)
	}
	t.Log("isolated 1.37.4 organization owner: RSA/profile/collection/create/read/update/share/sync passed; platform validation is separate")
}
