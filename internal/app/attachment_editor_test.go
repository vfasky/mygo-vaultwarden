// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestNativeAttachmentsActionsConfirmationAndCancellation(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	e := a.editor
	if e == nil {
		t.Fatal("editor")
	}
	session := a.session.(*vaultwarden.Session)
	if err := attachmentDraftSaved(session, a.vault, e); err != nil {
		t.Fatal("unchanged draft", err)
	}
	original := e.inputs[2].value
	e.inputs[2].value = "unsaved card number"
	if err := attachmentDraftSaved(session, a.vault, e); err == nil {
		t.Fatal("dirty draft accepted")
	}
	if e.fields.Card["number"] == "unsaved card number" {
		t.Fatal("draft check mutated source")
	}
	e.inputs[2].value = original
	e.attachmentsLoaded = true
	e.attachments = []vaultwarden.AttachmentInfo{{ID: "attachment-1", FileName: "fixture.txt", CiphertextSize: 81}}
	tt := ui.NewTester(func(c *ui.Context) { a.attachmentView(c, e) }, 900, 900)
	if !tt.HasText("附件") || !tt.HasText("fixture.txt") || !tt.HasText("选择并上传文件…") || !tt.HasText("下载并另存为…") {
		t.Fatal("attachment entry unavailable")
	}
	clickUI(t, tt, "删除附件…")
	if e.attachmentDelete != "attachment-1" || !tt.HasText("永久删除此附件？此操作无法撤销。") {
		t.Fatal("missing deletion confirmation")
	}
	clickUI(t, tt, "保留附件")
	if e.attachmentDelete != "" || a.pending != 0 {
		t.Fatal("cancel deletion changed state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.cancel = cancel
	a.pending = 1
	e.attachmentBusy = true
	tt.Frame()
	if !tt.HasText("正在验证权限并传输附件，请稍候…") {
		t.Fatal("missing progress state")
	}
	clickUI(t, tt, "取消附件操作")
	if ctx.Err() == nil {
		t.Fatal("cancel did not reach transfer context")
	}
	a.pending = 0
	a.lockInterface()
	if a.editor != nil || a.vault != nil {
		t.Fatal("lock retained attachment UI")
	}
}

func TestNativeReadOnlyAttachmentsExposeDownloadOnly(t *testing.T) {
	a := organizationUIFixture(t, false, true, 0)
	defer a.stopNetwork()
	a.openCipherEditor("organization-item", 0)
	e := a.editor
	if e == nil {
		t.Fatal("readonly editor")
	}
	e.attachments = []vaultwarden.AttachmentInfo{{ID: "attachment-1", FileName: "read-only.txt", CiphertextSize: 65}}
	e.attachmentsLoaded = true
	tt := ui.NewTester(func(c *ui.Context) { a.attachmentView(c, e) }, 900, 900)
	if !tt.HasText("下载并另存为…") || tt.HasText("选择并上传文件…") || tt.HasText("删除附件…") {
		t.Fatal("readonly actions")
	}
	e.uncertain = true
	before := a.epoch
	a.runAttachmentOperation("upload", vaultwarden.AttachmentInfo{})
	if a.pending != 0 || a.epoch != before {
		t.Fatal("uncertain attachment operation repeated")
	}
}
