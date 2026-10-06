// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin

package main

import "errors"

func nativeSecretInput(int32, string) ([]byte, error) {
	return nil, errors.New("secure input requires macOS")
}
func nativeCancelSecretInput() {}

func nativeStorageCall([]byte) ([]byte, error) {
	return nil, errors.New("secure snapshot storage requires macOS")
}
