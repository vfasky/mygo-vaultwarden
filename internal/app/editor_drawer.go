// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// The main window's editors (an item, a folder, bulk actions, an
// organization) slide in from the right as a drawer over the vault, which
// stays in place behind a dimmed, inert backdrop. The editor decides when it
// closes: its own Cancel or Close, or Escape where it has one. A click on
// the backdrop does nothing, so a stray click never discards what was typed.
//
// The drawer only slides in. It has no exit motion: the copy of its last
// frame that an exit animates would keep its secrets on screen, over the
// lock screen too, after the editor cleared them.

// drawerSlides is turned off by the package tests, which click into the
// drawer at once: while it slides, it takes the pointer where it is.
var drawerSlides = true

// drawerSlideDuration is how long the drawer slides in.
var drawerSlideDuration = 240 * time.Millisecond

var (
	drawerPanelMotion = func(width float32) ui.ElementTransition {
		return ui.ElementTransition{Enter: &ui.Motion{X: width, Opacity: 1}, Duration: drawerSlideDuration}
	}
	drawerBackdropMotion = func() ui.ElementTransition {
		return ui.ElementTransition{Enter: &ui.Motion{}, Duration: drawerSlideDuration}
	}
)

// drawerEditor names the editor the drawer shows, and builds it.
func (a *app) drawerEditor() (kind string, view func(c *ui.Context)) {
	switch {
	case a.bulkEditor != nil:
		return "bulk", a.bulkEditorView
	case a.organizationEditor != nil:
		return "organization", a.organizationEditorView
	case a.folderEditor != nil:
		return "folder", a.folderEditorView
	case a.editor != nil:
		return "item", a.cipherEditorView
	}
	return "", nil
}

// drawerWidth is half the window, within what the editors' forms need.
func drawerWidth(c *ui.Context) float32 {
	w, _ := c.Size()
	return drawerWidthFor(w)
}

func drawerWidthFor(window float32) float32 { return min(max(window*.5, 520), 680, window-120) }

// editorDrawer builds the drawer above the main window. Its layer is built
// in every frame, open or not, so the backdrop and the panel enter into a
// parent that was already there, which their transitions need.
func (a *app) editorDrawer(c *ui.Context) {
	kind, view := a.drawerEditor()
	ui.Overlay(c, func() {
		layer := ui.Box(c.Key("editor-drawer")).Absolute().Left(0).Top(0).Right(0).Bottom(0)
		if view != nil && layer.OverlayShortcut(0, ui.KeyEscape) {
			// Escape may close the editor: build what is left after it.
			a.cancelDrawerEditor()
			kind, view = a.drawerEditor()
		}
		if view == nil {
			layer.PassThrough()
			return
		}
		width := drawerWidth(c)
		layer.Modal()
		layer.Children(func() {
			backdrop := ui.Box(c.Key("editor-drawer-backdrop")).Absolute().Left(0).Top(0).Right(0).Bottom(0).
				Background(ui.RGBA(38, 30, 62, .22))
			panel := ui.Column(c.Key("editor-drawer-"+kind)).Absolute().Top(0).Right(0).Bottom(0).Width(width).
				Padding(14, 0, 18, 0).Background(kit.Panel).Role(ui.RoleDialog).Label(drawerTitle(kind)).
				Shadow(-12, 0, 32, 0, ui.RGBA(38, 30, 62, .18))
			if drawerSlides {
				backdrop.Transition(drawerBackdropMotion())
				panel.Transition(drawerPanelMotion(width))
			}
			panel.DrawOver(func(p *ui.Painter, r ui.Rect) { p.Fill(ui.Rect{X: r.X, Y: r.Y, W: 1, H: r.H}, kit.Line, 0) })
			panel.Children(func() { view(c) })
		})
	})
}

func drawerTitle(kind string) string {
	switch kind {
	case "bulk":
		return i18n.T("vault.bulk.title")
	case "folder":
		return i18n.T("vault.folder.manage_title")
	}
	return i18n.T("app.detail.view_edit")
}

// cancelDrawerEditor is Escape: what the editor's own Cancel or Close does,
// and nothing where it has none (the comparison of a conflict, an
// organization) or while an operation runs.
func (a *app) cancelDrawerEditor() {
	if a.pending != 0 {
		return
	}
	switch {
	case a.bulkEditor != nil:
		a.bulkEditor = nil
	case a.organizationEditor != nil:
	case a.folderEditor != nil:
		a.folderEditor = nil
	case a.editor != nil:
		e := a.editor
		switch {
		case e.comparison != nil:
		case e.fields.OrganizationID != nil && !e.fields.Edit && e.repromptID == "":
		case e.repromptID != "" && !e.compareAuthorization:
			*e = cipherEditor{}
			a.editor = nil
			a.secretInputVersion++
		default:
			a.editor = nil
		}
	}
}
