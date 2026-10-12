// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestDrawerCloseIconIsPinnedAndReplacesFooterAcrossEditors(t *testing.T) {
	for _, kind := range []string{"item", "folder", "bulk", "organization", "authorization", "readonly", "comparison"} {
		t.Run(kind, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			switch kind {
			case "folder":
				a.openFolderEditor("")
			case "bulk":
				a.openBulkEditor(false)
			case "organization":
				a.organizationEditor = &organizationEditor{revision: a.sessionRevision, owner: true, loaded: true}
			default:
				a.openCipherEditor("card-1", 3)
				switch kind {
				case "authorization":
					a.editor.repromptID = "card-1"
					a.editor.repromptPassword = "fixture-input"
				case "readonly":
					id := "org-fixture"
					a.editor.fields.OrganizationID = &id
					a.editor.fields.Edit = false
				case "comparison":
					a.editor.comparison = &vaultwarden.CipherRebase{}
				}
			}
			editor, org := a.editor, a.organizationEditor
			tt := ui.NewTester(a.view, 1280, 820)
			button, ok := tt.Find(i18n.T("common.close"))
			if !ok || button.X < 1200 || button.Y > 80 {
				t.Fatalf("close icon is not at the top right: %+v", button)
			}
			// The footer close buttons and their catalog entries are gone.
			for _, label := range []string{"关闭文件夹编辑", "关闭批量管理", "关闭组织管理"} {
				if tt.HasText(label) {
					t.Fatalf("old footer button remains: %s", label)
				}
			}
			if _, ok := tt.Find(i18n.T("common.cancel")); kind == "authorization" && ok {
				t.Fatal("authorization footer still closes the drawer")
			}
			tt.Scroll(1100, 600, 0, 2000)
			after, ok := tt.Find(i18n.T("common.close"))
			if !ok || after != button {
				t.Fatalf("close icon scrolled with content: before=%+v after=%+v", button, after)
			}
			a.pending = 1
			tt.Frame()
			uitest.Click(t, tt, i18n.T("common.close"))
			if current, _ := a.drawerEditor(); current == "" {
				t.Fatal("close icon discarded a busy editor")
			}
			a.pending = 0
			tt.Frame()
			uitest.Click(t, tt, i18n.T("common.close"))
			if kind == "comparison" {
				if a.editor != editor || a.editor.comparison == nil {
					t.Fatal("close bypassed conflict resolution")
				}
				return
			}
			if current, _ := a.drawerEditor(); current != "" {
				t.Fatal("close icon did not close the drawer")
			}
			if _, ok := tt.Find(i18n.T("common.close")); ok {
				t.Fatal("closed drawer still rendered")
			}
			if editor != nil && (editor.repromptPassword != "" || len(editor.inputs) != 0 || editor.fields.Name != "") {
				t.Fatal("closed item retained its draft or authentication input")
			}
			if org != nil && (org.revision != "" || org.owner) {
				t.Fatal("organization editor was not cleared")
			}
		})
	}
}
