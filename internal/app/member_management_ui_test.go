// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestMemberNativeAdminEntryAndInvitationConfirmation(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 1600)
	if tt.HasText("管理成员与邀请") {
		t.Fatal("ordinary member admin entry")
	}
	a.organizations[0].Type = 1
	tt.Frame()
	if !tt.HasText("管理成员与邀请") {
		t.Fatal("admin entry missing")
	}
	a.clearOrganizationEditor()
	a.openOrganizationEditor("")
	tt.Frame()
	if !tt.HasText("接受组织邀请") || !tt.HasText("查看我的共享公钥") {
		t.Fatal("invitation/key entrance absent")
	}
	a.organizationEditor.invitationLink = "https://fixture.invalid/#/accept-organization/?token=sensitive"
	tt.Frame()
	if !tt.HasText("核验邀请策略") || tt.HasText("确认接受邀请") {
		t.Fatal("accept appeared before policy read")
	}
	a.organizationEditor.invitationAcceptance = &vaultwarden.InvitationAcceptance{}
	tt.Frame()
	if a.pending != 0 || !tt.HasText("确认接受邀请") {
		t.Fatal("accept omitted consent")
	}
	uitest.Click(t, tt, "取消接受邀请")
	if a.organizationEditor.confirmation != "" {
		t.Fatal("cancel")
	}
	e := a.organizationEditor
	a.lockInterface()
	tt.Frame()
	if a.organizationEditor != nil || e.invitationLink != "" || e.accountPublicKey != "" {
		t.Fatal("lock retained invitation authority")
	}
}
func TestMemberOperationsRequireExplicitConfirmationAndCurrentScope(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	a.organizations[0].Type = 1
	e := a.organizationEditor
	for _, operation := range []string{"member-invite", "member-confirm", "member-remove", "member-role-save"} {
		if a.validMemberOperation(e, operation) {
			t.Fatal("operation without authenticated draft", operation)
		}
	}
	e.id = ""
	e.invitationLink = "some link"
	if a.validMemberOperation(e, "member-accept") {
		t.Fatal("accept without consent")
	}
	e.confirmation = "member-accept"
	if a.validMemberOperation(e, "member-accept") {
		t.Fatal("accept without policy draft")
	}
	e.invitationAcceptance = &vaultwarden.InvitationAcceptance{}
	if !a.validMemberOperation(e, "member-accept") {
		t.Fatal("explicit acceptance rejected")
	}
}
