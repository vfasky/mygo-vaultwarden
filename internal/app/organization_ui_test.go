// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func organizationUIFixture(t *testing.T, edit, view bool, reprompt int) *app {
	t.Helper()
	a := writableUIFixture(t)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	wrapped, _ := vaultcrypto.EncryptString(der, bytes.Repeat([]byte{4}, 64))
	key := bytes.Repeat([]byte{9}, 64)
	encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, key, nil)
	name, _ := vaultcrypto.EncryptString([]byte("团队集合"), key)
	item, err := vaultwarden.NewPersonalCipher(vaultwarden.CipherFields{Type: 1, Name: "组织条目", Login: map[string]any{"username": "member", "password": "org secret"}, Reprompt: reprompt}, key, a.liveScope.Account)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(item.JSON, &object)
	object["id"], object["organizationId"], object["collectionIds"] = "organization-item", "organization-1", []string{"collection-1"}
	object["revisionDate"], object["edit"], object["viewPassword"] = "2026-06-01T00:00:00Z", edit, view
	var data map[string]any
	_ = json.Unmarshal(a.vault.Sync, &data)
	profile := data["profile"].(map[string]any)
	profile["privateKey"], profile["accountKeys"] = wrapped, map[string]any{"publicKeyEncryptionKeyPair": map[string]any{"wrappedPrivateKey": wrapped, "publicKey": base64.StdEncoding.EncodeToString(public)}}
	orgs := []any{map[string]any{"id": "organization-1", "organizationUserId": "member-1", "userId": a.liveScope.Account, "name": "团队组织", "key": "3." + base64.StdEncoding.EncodeToString(encrypted), "status": 2, "type": 2, "enabled": true}}
	profile["organizations"], profile["organizationsNew"] = orgs, orgs
	data["collections"] = []any{map[string]any{"id": "collection-1", "organizationId": "organization-1", "name": name, "readOnly": !edit, "hidePasswords": !view, "manage": false}}
	data["ciphers"] = append(data["ciphers"].([]any), object)
	raw, _ := json.Marshal(data)
	v := &vaultwarden.VaultData{Version: 1, Scope: *a.liveScope, Sync: raw}
	acceptUIReceipt(t, a, v)
	if err := a.adoptVault(v); err != nil {
		t.Fatal(err)
	}
	return a
}
func TestNativeOrganizationNavigationReadWriteAndLock(t *testing.T) {
	if !organizationUIEnabled {
		t.Skip("组织产品UI按本版范围延期；加密与权限测试仍运行")
	}
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	tt := ui.NewTester(a.view, 1280, 820)
	uitest.Click(t, tt, "团队组织")
	if len(a.filteredItems()) != 1 || a.filteredItems()[0].Title != "组织条目" {
		t.Fatal("organization filter")
	}
	uitest.Click(t, tt, "编辑")
	if a.editor == nil || a.editor.fields.OrganizationID == nil || a.editor.inputs[1].value != "org secret" {
		t.Fatal("organization editor")
	}
	a.editor = nil
	a.category = "collection:collection-1"
	tt.Frame()
	uitest.Click(t, tt, "新增")
	if a.editor == nil || a.editor.organizationID != "organization-1" || a.editor.collectionID != "collection-1" {
		t.Fatal("organization creation destination")
	}
	uitest.Click(t, tt, "类型：支付卡")
	if a.editor.fields.Type != 3 || len(a.editor.inputs) != len(editorSpecs[3]) {
		t.Fatal("organization type selector")
	}
	a.lockInterface()
	tt.Frame()
	if len(a.organizations) != 0 || len(a.collections) != 0 || a.editor != nil || tt.HasText("团队组织") {
		t.Fatal("organization lock residue")
	}
}
func TestNativeOrganizationReadOnlyHiddenAndReprompt(t *testing.T) {
	a := organizationUIFixture(t, false, true, 0)
	defer a.stopNetwork()
	a.openCipherEditor("organization-item", 0)
	if a.editor == nil || a.editor.fields.Edit {
		t.Fatal("read-only open")
	}
	tt := ui.NewTester(a.view, 1280, 820)
	if !tt.HasText("组织授予此项目查看权限。修改需要组织管理员调整集合权限。") || tt.HasText("org secret") {
		t.Fatal("read-only disclosure")
	}
	a.editor = nil
	a.category = "collection:collection-1"
	a.openCipherEditor("", 1)
	if a.editor != nil {
		t.Fatal("read-only create")
	}
	hidden := organizationUIFixture(t, true, false, 0)
	defer hidden.stopNetwork()
	hidden.openCipherEditor("organization-item", 0)
	if hidden.editor != nil {
		t.Fatal("hidden password opened")
	}
	protected := organizationUIFixture(t, true, true, 1)
	defer protected.stopNetwork()
	protected.openCipherEditor("organization-item", 0)
	if protected.editor == nil || protected.editor.repromptID != "organization-item" || len(protected.editor.inputs) != 0 {
		t.Fatal("reprompt bypass")
	}
}
func TestNativePersonalOperationsExcludeOrganizationCandidates(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.category = "all"
	a.openBackupEditor()
	if a.backupEditor == nil || len(a.backupEditor.candidates) != 1 || a.backupEditor.selected["organization-item"] {
		t.Fatal("organization entered personal export")
	}
	a.clearBackupEditor()
	a.openBulkEditor(false)
	if a.bulkEditor == nil || len(a.bulkEditor.candidates) != 1 || a.bulkEditor.candidates[0].OrganizationID != "" {
		t.Fatal("organization entered personal bulk")
	}
}

func TestNativeOrganizationSyncRevokesDraftAndNavigation(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openCipherEditor("organization-item", 0)
	draft := a.editor
	var data map[string]any
	_ = json.Unmarshal(a.vault.Sync, &data)
	profile := data["profile"].(map[string]any)
	profile["organizations"], profile["organizationsNew"] = []any{}, []any{}
	data["collections"] = []any{}
	data["ciphers"] = data["ciphers"].([]any)[:1]
	raw, _ := json.Marshal(data)
	a.sessionRevision = "org-revoked"
	a.snapshot.Revision = a.sessionRevision
	v := &vaultwarden.VaultData{Version: 1, Scope: *a.liveScope, Sync: raw}
	acceptUIReceipt(t, a, v)
	if err := a.adoptVault(v); err != nil {
		t.Fatal(err)
	}
	if a.editor != nil || draft.fields.Name != "" || len(draft.inputs) != 0 || len(a.organizations) != 0 || len(a.collections) != 0 {
		t.Fatal("sync retained revoked organization plaintext")
	}
	a.category = "org:organization-1"
	if len(a.filteredItems()) != 0 {
		t.Fatal("revoked organization navigation")
	}
}

func TestNativeOrganizationShareRequiresDestinationConfirmation(t *testing.T) {
	if !organizationUIEnabled {
		t.Skip("组织共享UI延期到下一版本")
	}
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	tt := ui.NewTester(a.view, 1280, 820)
	tt.Scroll(1100, 600, 0, 3000)
	uitest.Click(t, tt, "共享到 团队组织 / 团队集合")
	if a.editor.shareCollectionID != "collection-1" || a.editor.shareOrganizationID != "organization-1" || a.pending != 0 || !tt.HasText("确认共享到组织") {
		t.Fatal("share confirmation missing")
	}
	tt.Scroll(1100, 600, 0, 1500)
	uitest.Click(t, tt, "取消共享")
	if a.editor.shareCollectionID != "" || a.pending != 0 {
		t.Fatalf("share cancel mutation: collection=%q pending=%d", a.editor.shareCollectionID, a.pending)
	}
}
