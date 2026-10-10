// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin

package localstore

import "errors"

func nativeStorageCall([]byte) ([]byte, error) {
	return nil, errors.New("secure snapshot storage requires macOS")
}
