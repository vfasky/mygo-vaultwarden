// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestCollectionManagementNativeRoleEntryAndLockClearsDraft(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 900)
	if tt.HasText("新建集合") || tt.HasText("集合管理") {
		t.Fatal("ordinary member offered management")
	}
	a.organizations[0].Type = 4
	a.organizations[0].Permissions = map[string]bool{"createNewCollections": true, "editAnyCollection": true, "deleteAnyCollection": true}
	a.collections[0].Manage = true
	tt.Frame()
	if !tt.HasText("新建集合") || !tt.HasText("集合管理") {
		t.Fatal("manager entry absent")
	}
	draft := &vaultwarden.CollectionDraft{Name: "private collection name"}
	a.organizationEditor.collectionDraft = draft
	tt.Frame()
	if !tt.HasText("保存集合") || !tt.HasText("返回集合列表") {
		t.Fatal("business form absent")
	}
	a.lockInterface()
	tt.Frame()
	if draft.Name != "" || a.organizationEditor != nil {
		t.Fatal("lock retained collection form")
	}
}

func TestCollectionManagerWithoutFullAccessCannotCreate(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	a.organizations[0].Type = 4
	a.collections[0].Manage = true
	tt := ui.NewTester(a.view, 1280, 900)
	if tt.HasText("新建集合") || !tt.HasText("集合管理") {
		t.Fatal("manager creation boundary")
	}
}

func TestCollectionAccessNativeConfirmationAndLock(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	a.organizations[0].Type = 4
	draft := &vaultwarden.CollectionDraft{Name: "collection", AccessLoaded: true, Access: []vaultwarden.CollectionAccess{{ID: "member-a", Label: "甲 · a@example.invalid", Assigned: true, ReadOnly: true, HidePasswords: true}}}
	a.organizationEditor.collectionDraft = draft
	tt := ui.NewTester(a.view, 1280, 1400)
	if !tt.HasText("成员：甲 · a@example.invalid") || !tt.HasText("服务器未启用群组。") {
		t.Fatal("friendly directory/feature boundary absent")
	}
	uitest.Click(t, tt, "管理集合：否")
	if !draft.Access[0].Manage || draft.Access[0].ReadOnly || draft.Access[0].HidePasswords {
		t.Fatal("inconsistent manage flags")
	}
	uitest.Click(t, tt, "保存集合")
	if a.pending != 0 || a.organizationEditor.confirmation != "collection-access-save" || !tt.HasText("确认保存访问配置") {
		t.Fatal("access save omitted confirmation")
	}
	a.lockInterface()
	tt.Frame()
	if draft.Name != "" || len(draft.Access) != 0 || a.organizationEditor != nil {
		t.Fatal("lock retained access form")
	}
}
