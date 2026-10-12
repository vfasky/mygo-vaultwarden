// SPDX-License-Identifier: GPL-3.0-only
package updatehelper

import "testing"

func TestResultFailed(t *testing.T) {
	for _, r := range []Result{Unchanged, Repaired} {
		if r.Failed() {
			t.Fatalf("%d reported as a failure", r)
		}
	}
	for _, r := range []Result{NotApp, Untrusted, Incomplete, NoAnswer, Unreachable, Unavailable} {
		if !r.Failed() {
			t.Fatalf("%d not reported as a failure", r)
		}
	}
}

// Without the macOS bridge (headless tests, other systems) the helper is
// unavailable and Start does nothing.
func TestHeadlessUnavailable(t *testing.T) {
	Start()
	if RepairInstalled() != Unavailable {
		t.Fatal("RepairInstalled without the bridge")
	}
}
