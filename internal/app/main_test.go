// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Tests click into the editor drawer at once; it slides only in TestEditorDrawer.
	drawerSlides = false
	os.Exit(m.Run())
}
