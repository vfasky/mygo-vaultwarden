// SPDX-License-Identifier: GPL-3.0-only
package app

import "testing"

func TestMainWindowCloseHidesUntilQuit(t *testing.T) {
	a := &app{}
	if !a.hideMainWindowOnClose() {
		t.Fatal("normal close must hide main window")
	}
	a.windows.settingsOpen, a.windows.accountOpen = true, true
	if !a.hideMainWindowOnClose() {
		t.Fatal("auxiliary windows changed close behavior")
	}
	a.windows.quitting = true
	if a.hideMainWindowOnClose() {
		t.Fatal("quit must allow main window to close")
	}
}
