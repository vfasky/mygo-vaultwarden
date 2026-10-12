// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || headless

package updatehelper

// Start does nothing without the macOS bridge.
func Start() {}

// RepairInstalled reports that the helper is unavailable without the macOS bridge.
func RepairInstalled() Result { return Unavailable }
