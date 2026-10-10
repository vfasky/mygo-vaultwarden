// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || headless

package sysauth

import (
	"context"
	"errors"
	"testing"
)

func TestAuthUnsupportedPlatform(t *testing.T) {
	if _, err := NewAuthenticationPlatform(nil).execute(context.Background(), authNativeInput{Kind: "browser"}); !errors.Is(err, errAuthUnavailable) {
		t.Fatal("headless advertised authentication")
	}
}
