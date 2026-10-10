// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || headless

package app

func nativeRuntimeSecretCall([]byte) ([]byte, error) { return nil, errRuntimeSecretUnavailable }
