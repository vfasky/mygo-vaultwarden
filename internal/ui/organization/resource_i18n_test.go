// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

func TestResourceRestoreEnglishKeepsStableState(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	plan := orgResourceUIFixture(t)
	panel := NewResourceRestorePanel(plan, map[string]string{"source-item": "target-item"}, false, ResourceCallbacks{})
	defer panel.Close()
	if panel.rows[0].State != ResourceNotStarted || panel.filesVerified("source-item", "target-item") {
		t.Fatal("language changed the initial resource state or verification gate")
	}
	tester := ui.NewTester(panel.View, 1500, 1200)
	for _, text := range []string{"Restore and verify organization resources", "test.bin · Source source-item/source-file · Not started"} {
		if !tester.HasText(text) {
			t.Fatalf("missing English text %q; rendered: %v", text, tester.Texts())
		}
	}
	if _, ok := tester.Find("Created or explicitly selected destination item ID"); !ok {
		t.Fatal("destination field accessibility label was not translated")
	}
	panel.rows[0].State = ResourceVerified
	if !panel.filesVerified("source-item", "target-item") {
		t.Fatal("stable verified state must still unlock the verification gate in English")
	}
	tester.Frame()
	if !tester.HasText("test.bin · Source source-item/source-file · Verified") {
		t.Fatal("verified state was not translated for display")
	}
}
