// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

func TestOrganizationInvitationEnglish(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	a := &app{}
	e := &organizationEditor{}
	tt := ui.NewTester(func(c *ui.Context) {
		ui.Column(c).Children(func() { a.memberInvitationView(c, e, false) })
	}, 1000, 800)
	for _, text := range []string{"Accept organization invite", "Email invitation link", "Verify invitation policies", "View my sharing public key"} {
		if !tt.HasText(text) {
			t.Errorf("English invitation view is missing %q", text)
		}
	}
	if tt.HasText("接受组织邀请") {
		t.Error("English invitation view retained its Chinese heading")
	}
	// Role keys must stay stable across languages.
	if got := memberRoleName(0); got != "org.member.role_owner" {
		t.Fatalf("owner role key changed with language: %q", got)
	}
	if got := i18n.T(memberRoleName(0)); got != "Owner" {
		t.Fatalf("owner display label was not translated: %q", got)
	}
	if got := orgBoolLabel("Official JSON", false); got != "Official JSON: Off" {
		t.Fatalf("toggle used a close-action label instead of an off state: %q", got)
	}
	i18n.Set(i18n.Chinese)
	if got := i18n.T(memberRoleName(0)); got != "所有者" {
		t.Fatalf("owner Chinese display label changed: %q", got)
	}
}
