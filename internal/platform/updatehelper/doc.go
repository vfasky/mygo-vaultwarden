// SPDX-License-Identifier: GPL-3.0-only

// Package updatehelper talks to the update helper, an XPC service without
// App Sandbox inside the app (macos/UpdateHelper). Files the sandboxed app
// writes carry a quarantine flag that it cannot remove, so the bundle an
// update installs would not open. Start launches the helper from the current
// bundle; RepairInstalled, before the app quits, removes the quarantine of the
// installed bundle once its signature checks out. See docs/updates.md.
package updatehelper

import "time"

// Result of RepairInstalled, as the helper reports it.
type Result int32

const (
	Unchanged   Result = 0   // the installed app carries no quarantine
	Repaired    Result = 1   // quarantine removed from the verified app
	NotApp      Result = -1  // the helper is not inside an app bundle
	Untrusted   Result = -2  // the installed app fails the signature check
	Incomplete  Result = -3  // some files kept their quarantine
	NoAnswer    Result = -10 // the helper did not answer in time
	Unreachable Result = -11 // the helper could not be reached
	Unavailable Result = -20 // no bridge library, or not macOS
)

// Failed reports whether the installed app may still carry its quarantine.
func (r Result) Failed() bool { return r < 0 }

// repairTimeout bounds how long quitting waits for the helper, which checks
// the signature of the whole bundle.
const repairTimeout = 15 * time.Second
