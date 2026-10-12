// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"testing"
)

func TestPersonalReleaseHidesOrganizationUIWithoutDroppingSyncData(t *testing.T) {
	if organizationUIEnabled {
		t.Skip("scope assertion applies to personal release")
	}
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	original := bytes.Clone(a.vault.Sync)
	a.snapshot.SnapshotID = "release-scope-fixture"
	tester := ui.NewTester(a.view, 1280, 820)
	for _, label := range []string{"创建或加入组织", "团队组织", "  团队集合"} {
		if tester.HasText(label) {
			t.Fatalf("deferred UI visible: %s", label)
		}
	}
	for _, item := range a.filteredItems() {
		if item.OrganizationID != "" {
			t.Fatal("organization item presented as personal")
		}
	}
	uitest.Click(t, tester, "设置")
	if !a.windows.settingsOpen {
		t.Fatal("settings window did not open")
	}
	settings := ui.NewTester(a.settingsWindowView, 860, 600)
	if settings.HasText("组织条目、资源与审计") || settings.HasText("组织恢复登记与管理员恢复") {
		t.Fatal("organization management entry exposed")
	}
	a.openEmergencyServices()
	tester.Frame()
	account := ui.NewTester(a.accountWindowView, 1080, 720)
	if a.orgServices == nil || !a.orgServices.emergencyOnly || account.HasText("组织恢复登记与管理员恢复") || account.HasText("Public 目录导入") {
		t.Fatal("emergency route exposed deferred organization products")
	}
	if !bytes.Equal(original, a.vault.Sync) || len(a.organizations) == 0 {
		t.Fatal("release gating dropped encrypted organization data")
	}
}
