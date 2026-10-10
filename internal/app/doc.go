// SPDX-License-Identifier: GPL-3.0-only

// Package app is the application controller: the main window, lifecycle,
// login and unlock flows, sync, vault editors and the controllers that connect
// the domain panels in internal/ui to storage and the Vaultwarden session.
// Its central app type keeps per-window state, so its methods stay together
// in this package.
package app
