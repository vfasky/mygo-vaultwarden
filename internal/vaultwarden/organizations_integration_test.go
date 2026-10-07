// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func testLiveOrganizations(t *testing.T, ctx context.Context, s *Session, scope Scope, password []byte) {
	t.Helper()
	request := func(method, path string, body any) []byte {
		raw, _ := json.Marshal(body)
		status, response, err := s.client.request(ctx, method, path, "application/json", string(raw), s.access)
		if err != nil || status < 200 || status >= 300 {
			t.Fatalf("organization fixture %s %s status %d: %v", method, path, status, err)
		}
		return response
	}
	sync, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var data struct{ Profile json.RawMessage }
	_ = json.Unmarshal(sync.Vault.Sync, &data)
	private, err := accountPrivateKey(data.Profile, s.key)
	if err != nil {
		t.Fatal("live account RSA", err)
	}
	key := make([]byte, 64)
	_, _ = rand.Read(key)
	defer clear(key)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	collectionName, _ := EncryptString([]byte("真实集合"), key)
	response := request("POST", "/api/organizations", map[string]any{"name": "MyGo isolated organization", "billingEmail": s.email, "collectionName": collectionName, "key": "3." + base64.StdEncoding.EncodeToString(wrapped), "planType": 0})
	var org struct{ ID string }
	if json.Unmarshal(response, &org) != nil || !validObjectID(org.ID) {
		t.Fatal("organization create identity")
	}
	defer func() {
		master, err := DeriveMaster(password, s.email, s.passwordUnlock.Config.KDF)
		if err != nil {
			t.Error(err)
			return
		}
		defer clear(master)
		request("DELETE", "/api/organizations/"+org.ID, map[string]any{"masterPasswordHash": AuthorizationHash(master, password)})
	}()
	sync, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	organizations, collections, err := s.Organizations(sync.Vault)
	if err != nil || len(organizations) != 1 || len(collections) != 1 || collections[0].Name != "真实集合" || organizations[0].UserID != scope.Account || organizations[0].OrganizationUserID == scope.Account {
		t.Fatal("live organization decode", err)
	}
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
