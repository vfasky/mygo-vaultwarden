// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestFolderNavigationEditorAndLock(t *testing.T) {
	a := writableUIFixture(t)
	a.folders = []vaultwarden.Folder{{ID: "folder-1", Name: "个人资料"}}
	a.items[0].FolderID = "folder-1"
	a.category = "folder:folder-1"
	if len(a.filteredItems()) != 1 || a.currentCategory().title != "个人资料" {
		t.Fatal("folder filter")
	}
	a.category = "folder:"
	if len(a.filteredItems()) != 0 {
		t.Fatal("unfiled filter")
	}
	a.category = "folder:folder-1"
	a.openCipherEditor("", 1)
	if a.editor.fields.FolderID == nil || *a.editor.fields.FolderID != "folder-1" {
		t.Fatal("new item folder")
	}
	a.editor = nil
	a.openFolderEditor("folder-1")
	tt := ui.NewTester(a.view, 1280, 820)
	uitest.Click(t, tt, "删除文件夹")
	if !a.folderEditor.confirm || a.pending != 0 {
		t.Fatal("delete confirmation missing")
	}
	uitest.Click(t, tt, "取消删除")
	if a.folderEditor.confirm {
		t.Fatal("cancel failed")
	}
	a.lockInterface()
	tt.Frame()
	if a.folderEditor != nil || len(a.folders) != 0 || tt.HasText("个人资料") {
		t.Fatal("lock retained folder metadata")
	}
}

func TestFolderStaleDraftCheckpointAndLateResponse(t *testing.T) {
	a := writableUIFixture(t)
	a.openFolderEditor("")
	e := a.folderEditor
	e.name = "private name"
	next := *a.snapshot
	next.Revision = "checkpoint"
	if !a.adoptSessionCheckpoint(&next) || e.revision != "checkpoint" {
		t.Fatal("checkpoint")
	}
	a.sessionRevision, a.snapshot.Revision = "replacement", "replacement"
	a.mutateFolder(false)
	if a.pending != 0 || e.name != "private name" {
		t.Fatal("stale draft mutation")
	}
	a.pending = 1
	epoch := a.epoch
	a.lockInterface()
	ctx, cancel := context.WithCancel(context.Background())
	a.completeFolderMutation(epoch, e, &next, localstore.Reply{}, nil, cancel)
	if e.name != "" || a.folderEditor != nil || a.session != nil || ctx.Err() == nil {
		t.Fatal("late response resurrected folder")
	}
}

func TestFolderUncertainResultKeepsDraftAndBlocksRetry(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openFolderEditor("")
	e := a.folderEditor
	e.name = "retained"
	a.pending = 1
	_, cancel := context.WithCancel(context.Background())
	a.completeFolderMutation(a.epoch, e, nil, localstore.Reply{}, &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork}, cancel)
	a.mutateFolder(false)
	if !e.uncertain || a.pending != 0 || e.name != "retained" {
		t.Fatal("unknown mutation retried/lost draft")
	}
}

func TestFolderPickerDropdownPreservesIDsAndDisabledState(t *testing.T) {
	a := &app{folders: []vaultwarden.Folder{{ID: "one", Name: "Personal"}, {ID: "two", Name: "Work"}}}
	var selected *string
	disabled := false
	tt := ui.NewTester(func(c *ui.Context) { a.folderPicker(c, &selected, disabled) }, 500, 400)
	uitest.Click(t, tt, i18n.T("common.no_folder"))
	uitest.Click(t, tt, "Work")
	if selected == nil || *selected != "two" {
		t.Fatal("dropdown did not commit folder ID")
	}
	disabled = true
	tt.Frame()
	uitest.Click(t, tt, "Work")
	if selected == nil || *selected != "two" || tt.HasText("Personal") {
		t.Fatal("disabled dropdown opened or changed value")
	}
	disabled = false
	tt.Frame()
	uitest.Click(t, tt, "Work")
	uitest.Click(t, tt, i18n.T("common.no_folder"))
	if selected != nil {
		t.Fatal("no folder did not restore nil")
	}
}
