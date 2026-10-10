// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestSendEnglishViewAndDefaultFilename(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	panel := NewPanel(nil, nil, nil, vaultwarden.Scope{}, Host{Dispatch: func(f func()) { f() }, Check: func() error { return nil }})
	defer panel.Close()
	tester := ui.NewTester(panel.View, 1200, 800)
	if !tester.HasText("Send secure sharing") {
		t.Fatal("Send title was not translated")
	}
	if _, ok := tester.Find("Received Send link"); !ok {
		t.Fatal("Send link accessibility label was not translated")
	}
	if got := sendSaveName(".."); got != "Send file" {
		t.Fatalf("English fallback filename = %q", got)
	}
	if got := sendSaveName("report.txt"); got != "report.txt" {
		t.Fatalf("user filename changed: %q", got)
	}
}
