// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLivePersonalRelease(t *testing.T) {
	if os.Getenv("MYGO_PERSONAL_RELEASE_TEST") != "1" {
		t.Skip("opt-in owned fixed 1.37.4 personal-release fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base, _, _ := recoveryLiveFixture(t, ctx)
	t.Setenv("MYGO_PERSONAL_RELEASE_ONLY", "1")
	t.Setenv("MYGO_VW_TEST_URL", base)
	TestLiveVaultwarden(t)
}
