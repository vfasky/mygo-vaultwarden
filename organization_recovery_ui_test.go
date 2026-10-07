// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"github.com/egoist/mygo/ui"
	"testing"
)

func TestOrganizationRecoveryKeyNativeConfirmationAndLock(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.organizationEditor = &organizationEditor{id: "organization-1", revision: a.sessionRevision, owner: true, loaded: true}
	tt := ui.NewTester(a.view, 1280, 1800)
	if !tt.HasText("查看组织恢复公钥") || !tt.HasText("初始化缺失的恢复密钥") {
		t.Fatal("recovery entrance missing")
	}
	clickUI(t, tt, "初始化缺失的恢复密钥")
	if a.pending != 0 || a.organizationEditor.confirmation != "recovery-key-create" || !tt.HasText("确认初始化恢复密钥") {
		t.Fatal("missing explicit key creation consent")
	}
	clickUI(t, tt, "取消初始化")
	if a.pending != 0 || a.organizationEditor.confirmation != "" {
		t.Fatal("cancel sent request")
	}
	a.organizationEditor.organizationRecoveryKey = "fixture public key"
	old := a.organizationEditor
	a.lockInterface()
	tt.Frame()
	if a.organizationEditor != nil || old.organizationRecoveryKey != "" || tt.HasText("fixture public key") {
		t.Fatal("lock retained organization form")
	}
}
