// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestGroupNativeScopeConsentCancelAndLock(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 1800)
	if tt.HasText("群组管理") {
		t.Fatal("member management entry")
	}
	a.organizations[0].Type = 1
	tt.Frame()
	if !tt.HasText("服务器未启用群组，无法读取或修改群组。") {
		t.Fatal("feature disabled")
	}
	a.organizations[0].UseGroups = true
	draft := &vaultwarden.GroupDraft{Name: "Group", Access: []vaultwarden.GroupAssignment{{ID: "member-a", Label: "甲 · a@example.invalid"}, {ID: "collection-a", Collection: true, Label: "工程集合", Assigned: true, ReadOnly: true, HidePasswords: true}}}
	a.organizationEditor.groupDraft = draft
	tt.Frame()
	if !tt.HasText("成员：甲 · a@example.invalid") || !tt.HasText("集合：工程集合") {
		t.Fatal("business labels absent")
	}
	clickUI(t, tt, "保存群组")
	if a.organizationEditor.confirmation != "" {
		t.Fatal("unset scope accepted")
	}
	clickUI(t, tt, "仅选定集合：否")
	if draft.AccessScope != vaultwarden.GroupSelectedCollections {
		t.Fatal("scope choice")
	}
	clickUI(t, tt, "保存群组")
	if a.organizationEditor.groupConsent == nil || a.organizationEditor.confirmation != "group-save" || a.pending != 0 {
		t.Fatal("missing consent phase")
	}
	clickUI(t, tt, "取消群组确认")
	if a.organizationEditor.groupConsent != nil || draft.Name != "Group" || a.pending != 0 {
		t.Fatal("cancel lost draft or dispatched")
	}
	a.lockInterface()
	tt.Frame()
	if draft.Name != "" || len(draft.Access) != 0 || a.organizationEditor != nil {
		t.Fatal("lock retained group form")
	}
}
