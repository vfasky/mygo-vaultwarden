// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestCopyConfirmationKeepsDraftAndHonorsRevision(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.fields.Name = "local copy title"
	tt := ui.NewTester(func(c *ui.Context) { a.cipherStateButtons(c, e) }, 900, 500)
	clickUI(t, tt, "复制为新项目")
	if e.confirm != copyCipherAction || a.pending != 0 {
		t.Fatal("copy without confirmation")
	}
	clickUI(t, tt, "取消操作")
	if e.confirm != "" || e.fields.Name != "local copy title" {
		t.Fatal("cancel lost draft")
	}
	clickUI(t, tt, "复制为新项目")
	e.revision = "stale"
	clickUI(t, tt, "确认")
	if a.pending != 0 || a.editor != e {
		t.Fatal("copy bypassed revision or lost draft")
	}
}
func TestCopyUnknownResultBlocksAnotherCreate(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.confirm = copyCipherAction
	a.pending = 1
	a.completeCipherMutation(a.epoch, e, nil, storageReply{}, &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrCancelled}, context.CancelFunc(func() {}))
	if !e.uncertain || a.editor != e {
		t.Fatal("unknown result lost draft")
	}
	a.mutateCipher(copyCipherAction)
	if a.pending != 0 {
		t.Fatal("uncertain create retried")
	}
}

func TestCopyLateResultCannotRestoreLockedDraft(t *testing.T) {
	a := writableUIFixture(t)
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.confirm = copyCipherAction
	epoch := a.epoch
	a.pending = 1
	a.stopNetwork()
	a.completeCipherMutation(epoch, e, nil, storageReply{}, &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrCancelled}, context.CancelFunc(func() {}))
	if a.editor != nil || e.fields.Name != "" || len(e.document.JSON) != 0 {
		t.Fatal("late copy restored secrets")
	}
}
