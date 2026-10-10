// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || headless

package localstore

func nativeRuntimeSecretCall([]byte) ([]byte, error) { return nil, ErrRuntimeSecretUnavailable }
