// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestOrganizationManagementNativeEntryConfirmationAndLock(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("")
	tt := ui.NewTester(a.view, 1280, 900)
	if !tt.HasText("创建组织") || !tt.HasText("保存组织") || a.organizationEditor == nil {
		t.Fatal("create entry missing")
	}
	a.organizationEditor.name, a.organizationEditor.email = "draft", "owner@example.invalid"
	a.openFolderEditor("")
	if a.folderEditor != nil {
		t.Fatal("overlapping editors")
	}
	draft := a.organizationEditor
	a.lockInterface()
	tt.Frame()
	if a.organizationEditor != nil || draft.name != "" || draft.email != "" {
		t.Fatal("lock retained organization form")
	}
}

func TestOrganizationMemberCanConfirmLeaveWithoutOwnerControls(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 900)
	if a.organizationEditor == nil || a.organizationEditor.owner || tt.HasText("保存组织") || tt.HasText("删除组织") {
		t.Fatal("member owner controls")
	}
	clickUI(t, tt, "退出组织")
	if a.organizationEditor.confirmation != "leave" || a.pending != 0 {
		t.Fatal("leave did not require confirmation")
	}
	clickUI(t, tt, "取消组织操作")
	if a.organizationEditor.confirmation != "" || a.pending != 0 {
		t.Fatal("leave cancel")
	}
}

func TestOrganizationIsolationRecoveryRequiresExplicitEntry(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	original := *a.vault
	isolated := original
	isolated.QuarantinedOrganizations = []string{"organization-1"}
	state := *a.snapshot
	state.Revision, state.SnapshotID = "quarantine-revision", "quarantine-snapshot"
	if !a.adoptOrganizationIsolation(&state, &isolated, "organization-1") {
		t.Fatal("isolate")
	}
	a.openOrganizationEditor("organization-1")
	tt := ui.NewTester(a.view, 1280, 900)
	if a.organizationEditor == nil || !a.organizationEditor.isolated || !tt.HasText("确认重新核验并恢复访问") || tt.HasText("退出组织") || tt.HasText("删除组织") {
		t.Fatal("recovery confirmation missing or dangerous retry offered")
	}
	if a.pending != 0 {
		t.Fatal("opening recovery performed a request")
	}
	wrong := state
	wrong.Revision, wrong.SnapshotID = "restore-revision", "restore-snapshot"
	if a.adoptOrganizationSnapshot(&wrong, &isolated, "organization-1", false) {
		t.Fatal("restoration accepted remaining marker")
	}
	if !a.adoptOrganizationSnapshot(&wrong, &original, "organization-1", false) || len(a.organizations) != 1 || len(a.isolatedOrganizations) != 0 || a.organizationEditor != nil {
		t.Fatal("restoration receipt")
	}
}

func TestOrganizationIsolationReceiptKeepsSessionAndPersonalVault(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.openOrganizationEditor("organization-1")
	draft := a.organizationEditor
	session := a.session
	before := len(a.items)
	isolated := *a.vault
	isolated.QuarantinedOrganizations = []string{"organization-1"}
	state := *a.snapshot
	state.Revision, state.SnapshotID = "isolated-revision", "isolated-snapshot"
	if !a.adoptOrganizationIsolation(&state, &isolated, "organization-1") {
		t.Fatal("valid isolation receipt rejected")
	}
	if a.session != session || a.sessionRevision != state.Revision || a.itemsRevision != state.Revision || len(a.items) != before-1 || len(a.organizations) != 0 || len(a.collections) != 0 || a.organizationEditor != nil || draft.name != "" {
		t.Fatal("isolation lost unrelated data or retained org")
	}
	// A late success from an operation cancelled by lock cannot restore state.
	e := &organizationEditor{name: "private draft", password: "password"}
	epoch := a.epoch
	a.pending = 1
	a.lockInterface()
	_, cancel := context.WithCancel(context.Background())
	a.completeOrganizationManagement(epoch, e, "leave", vaultwarden.OrganizationProfile{}, &state, storageReply{}, nil, cancel)
	if a.session != nil || a.vault != nil || a.organizationEditor != nil || e.password != "" || a.pending != 0 {
		t.Fatal("late response revived locked UI")
	}
}
