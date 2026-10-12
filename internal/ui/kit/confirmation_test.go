// SPDX-License-Identifier: GPL-3.0-only
package kit

import (
	"github.com/egoist/mygo/ui"
	"testing"
)

func TestConfirmDialogBlocksBackgroundAndDefaultsToCancel(t *testing.T) {
	open, disabled := false, false
	deleted, background := 0, 0
	tt := ui.NewTester(func(c *ui.Context) {
		c.SetTheme(Theme)
		ui.Column(c).Padding(20).Children(func() {
			if Button(c, "删除项目", "", ButtonDanger, false).Clicked() {
				open = true
			}
			if Button(c, "底层操作", "", ButtonSecondary, false).Clicked() {
				background++
			}
		})
		if open {
			ConfirmDialog(c, "test-delete", "删除项目确认", "删除后无法恢复。", "确定删除", "保留项目", disabled,
				func() { deleted++; open = false }, func() { open = false })
		}
	}, 800, 600)
	click := func(label string) {
		t.Helper()
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	click("删除项目")
	if !open || !tt.Focused("保留项目") {
		t.Fatal("dialog did not initially focus cancel")
	}
	click("底层操作")
	if background != 0 || !open {
		t.Fatal("modal leaked a background click")
	}
	tt.Key(0, ui.KeyEnter)
	if open || deleted != 0 {
		t.Fatal("Enter on initial focus deleted the item")
	}
	click("删除项目")
	tt.Key(0, ui.KeyEscape)
	if open || deleted != 0 {
		t.Fatal("Escape did not cancel")
	}
	click("删除项目")
	disabled = true
	tt.Frame()
	click("确定删除")
	if deleted != 0 || !open {
		t.Fatal("disabled confirmation executed")
	}
	disabled = false
	tt.Frame()
	click("确定删除")
	if open || deleted != 1 || background != 0 {
		t.Fatal("confirmation was not a single explicit action")
	}
}
