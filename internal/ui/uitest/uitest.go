// SPDX-License-Identifier: GPL-3.0-only

// Package uitest provides helpers shared by MyGo UI tests across packages.
// Only test files import it, so it never links into the application binary.
package uitest

import (
	"testing"

	"github.com/egoist/mygo/ui"
)

// Click presses the element with the accessibility label or fails the test.
func Click(t testing.TB, tt *ui.Tester, label string) {
	t.Helper()
	if err := tt.Click(label); err != nil {
		t.Fatal(err)
	}
}
