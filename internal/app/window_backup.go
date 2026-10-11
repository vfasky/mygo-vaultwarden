// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// backupWindowOptions are the import and export window's native options;
// showBackupWindow adds its StateKey and Content.
func backupWindowOptions() mygo.WindowOptions {
	return mygo.WindowOptions{Title: i18n.T("backup.editor.title"), Width: 760, Height: 680, MinWidth: 640, MinHeight: 540}
}

// backupWindowView is the import and export window: a.backupEditor, which
// exists exactly while the window is open (reconcileBackupWindow).
//
// SKELETON: the editor moved from the main window's detail pane as is; the
// import and export lane replaces it with the final layout.
func (a *app) backupWindowView(c *ui.Context) {
	a.framePrelude(c)
	c.SetTheme(kit.Theme)
	ui.Column(c).Fill().TextColor(kit.Ink).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
		ui.Box(c).Height(max(c.TitleBar().Height, 28)).Shrink(0).DragWindow()
		if a.backupEditor == nil || !a.unlocked() || a.showLogin {
			kit.EmptyState(c, "lock", i18n.T("app.list.status_locked"), "")
			return
		}
		ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Children(func() { a.backupEditorView(c) })
	})
}
