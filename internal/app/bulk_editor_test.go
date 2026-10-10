// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strings"
	"testing"
)

func TestEmptyTrashSelectsOnlyDeletedAndRequiresConfirmation(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.items = append(a.items, displayCredential{ID: "deleted", Title: "trash", Deleted: true}, displayCredential{ID: "archive", Archived: true})
	a.openBulkEditor(true)
	e := a.bulkEditor
	if len(e.candidates) != 1 || !e.selected["deleted"] || e.action != vaultwarden.CipherDeletePermanently || e.confirm {
		t.Fatal("unsafe empty trash selection")
	}
	a.mutateBulk()
	if a.pending != 0 {
		t.Fatal("unconfirmed deletion")
	}
	e.confirm = true
	e.revision = "old"
	a.mutateBulk()
	if a.pending != 0 {
		t.Fatal("stale bulk dispatched")
	}
}
func TestBulkReconciliationReportsPartialStateWithoutRetry(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.items = []displayCredential{{ID: "a", Title: "first"}, {ID: "b", Title: "second"}}
	a.openBulkEditor(false)
	e := a.bulkEditor
	e.selected["a"], e.selected["b"] = true, true
	e.submitted = true
	e.action = vaultwarden.CipherTrash
	a.items[0].Deleted = true
	a.reconcileBulk()
	if len(e.results) != 2 || !strings.Contains(e.results[0], "当前状态已符合") || !strings.Contains(e.results[1], "当前状态未符合") {
		t.Fatal(e.results)
	}
	a.mutateBulk()
	if a.pending != 0 {
		t.Fatal("submitted bulk retried")
	}
	e.action = vaultwarden.CipherDeletePermanently
	a.items = a.items[1:]
	a.reconcileBulk()
	if !strings.Contains(e.results[0], "当前状态已符合") || !strings.Contains(e.results[1], "当前状态未符合") {
		t.Fatal(e.results)
	}
}
func TestLateBulkCompletionCannotReviveLockedState(t *testing.T) {
	a := writableUIFixture(t)
	a.openBulkEditor(false)
	e := a.bulkEditor
	e.submitted = true
	a.pending = 1
	epoch := a.epoch
	a.lockInterface()
	ctx, cancel := context.WithCancel(context.Background())
	a.completeBulkMutation(epoch, e, nil, storageReply{}, nil, cancel)
	if a.bulkEditor != nil || e.candidates != nil || ctx.Err() == nil || a.session != nil {
		t.Fatal("late bulk resurrected")
	}
}
