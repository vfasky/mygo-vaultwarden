// SPDX-License-Identifier: GPL-3.0-only
package kit

import "github.com/egoist/mygo/ui"

// ConfirmationDialog presents an alert above the current page or editor drawer.
// Outside clicks do nothing. Escape cancels only this alert; no exit animation
// retains its contents after the owning form is closed or the vault is locked.
func ConfirmationDialog(c *ui.Context, key, title string, cancel func(), content func()) {
	ui.Overlay(c.Key(key), func() {
		backdrop := ui.Box(c).Absolute().Left(0).Top(0).Right(0).Bottom(0).Center().
			Background(ui.RGBA(38, 30, 62, .28)).Modal()
		if backdrop.OverlayShortcut(0, ui.KeyEscape) {
			cancel()
			return
		}
		backdrop.Children(func() {
			w, h := c.Size()
			ui.Column(c).Width(440).MaxWidth(w-48).MaxHeight(h-48).Padding(24).Gap(16).
				Background(White).TextColor(Ink).Radius(20).Border(1, Line).
				Shadow(0, 12, 40, 0, ui.RGBA(38, 30, 62, .22)).
				Role(ui.RoleAlertDialog).Label(title).Children(func() {
				ui.Text(c, title).FontSize(18).FontWeight(650).MaxLines(3)
				content()
			})
		})
	})
}

// ConfirmDialog leaves confirmation state owned by the caller, so action
// handlers still validate it before dispatching. Cancel has initial focus;
// pressing Enter when the dialog opens must not accidentally delete anything.
func ConfirmDialog(c *ui.Context, key, title, message, confirmLabel, cancelLabel string, disabled bool, confirm, cancel func()) {
	ConfirmationDialog(c, key, title, cancel, func() {
		ui.Text(c, message).FontSize(13).TextColor(Muted)
		ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
			if Button(c.Key(key+"-cancel"), cancelLabel, "", ButtonSecondary, false).AutoFocus().Clicked() {
				cancel()
			}
			if Button(c.Key(key+"-confirm"), confirmLabel, "", ButtonDanger, disabled).Clicked() {
				confirm()
			}
		})
	})
}
