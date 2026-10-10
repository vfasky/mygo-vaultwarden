// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || headless

package sysauth

import (
	"context"
	"github.com/egoist/mygo"
)

func nativeAuthentication(ctx context.Context, window *mygo.Window, input []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errAuthUnavailable
}
