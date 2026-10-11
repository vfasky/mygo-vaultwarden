// SPDX-License-Identifier: GPL-3.0-only
package kit

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

func TestSidebarTooltipImmediateRightAndDismissal(t *testing.T) {
	tt := ui.NewTester(func(c *ui.Context) {
		ui.Column(c).Width(60).Padding(60, 10, 0, 10).Children(func() {
			anchor := ui.ButtonBase(c).Label("anchor").Size(40, 36)
			sidebarTooltip(c, anchor, "即时提示")
		})
	}, 400, 200)
	anchor, ok := tt.Find("anchor")
	if !ok {
		t.Fatal("anchor missing")
	}
	if tt.HasText("即时提示") {
		t.Fatal("tooltip shown before hover")
	}
	tt.Move(anchor.X+anchor.W/2, anchor.Y+anchor.H/2)
	tip, ok := tt.Find("即时提示")
	if !ok || tip.X <= anchor.X+anchor.W || tip.Y < anchor.Y || tip.Y+tip.H > anchor.Y+anchor.H {
		t.Fatalf("tooltip should appear immediately to the right: anchor=%+v tip=%+v visible=%v", anchor, tip, ok)
	}
	tt.Key(0, ui.KeyEscape)
	if tt.HasText("即时提示") {
		t.Fatal("Escape did not dismiss tooltip")
	}
	tt.Move(300, 150)
	tt.Move(anchor.X+anchor.W/2, anchor.Y+anchor.H/2)
	if !tt.HasText("即时提示") {
		t.Fatal("tooltip did not reappear on hover")
	}
	if err := tt.Click("anchor"); err != nil {
		t.Fatal(err)
	}
	if tt.HasText("即时提示") {
		t.Fatal("click did not dismiss tooltip")
	}
	tt.Move(300, 150)
	tt.Move(anchor.X+anchor.W/2, anchor.Y+anchor.H/2)
	tt.Move(300, 150)
	if tt.HasText("即时提示") {
		t.Fatal("tooltip remained after pointer left")
	}
}
