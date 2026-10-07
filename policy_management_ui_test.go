// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestPolicyManagementNativeRoleAndRecoveryEntry(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 2000)
	if tt.HasText("组织策略") {
		t.Fatal("non administrator policy edit")
	}
	a.organizations[0].Type = 1
	tt.Frame()
	if !tt.HasText("加载组织策略") {
		t.Fatal("administrator entry")
	}
	a.organizationEditor.policies = []vaultwarden.PolicyEntry{{Type: 15, Enabled: true}, {Type: 16, Enabled: false}}
	tt.Frame()
	if !tt.HasText("受限条目类型：是") || !tt.HasText("默认 URI 匹配：否") {
		t.Fatal("policy status")
	}
	a.clearOrganizationEditor()
	pending := *a.vault
	pending.Version = 2
	pending.QuarantinedOrganizations = []string{"organization-1"}
	record := vaultwarden.PendingPolicyMutation{OrganizationID: "organization-1", PolicyType: 15, MutationID: "mutation-1"}
	pending.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{record}
	next := *a.snapshot
	next.Revision = "pending-revision"
	next.SnapshotID = "pending-snapshot"
	if !a.adoptOrganizationIsolation(&next, &pending, "organization-1") {
		t.Fatal("pending isolation")
	}
	a.openOrganizationEditor("organization-1")
	tt.Frame()
	if !tt.HasText("读取服务器当前策略以核验") || tt.HasText("确认重新核验并恢复访问") {
		t.Fatal("missing dedicated recovery")
	}
	if a.pending != 0 {
		t.Fatal("opening recovery sent request")
	}
	restored := pending
	restored.Version = 1
	restored.PendingPolicyMutations = nil
	restored.QuarantinedOrganizations = nil
	next.Revision = "restore-revision"
	next.SnapshotID = "restore-snapshot"
	if a.adoptOrganizationSnapshot(&next, &restored, "organization-1", false) {
		t.Fatal("ordinary restore discarded pending")
	}
	a.lockInterface()
	tt.Frame()
	if a.organizationEditor != nil {
		t.Fatal("lock retained form")
	}
}
