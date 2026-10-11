// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/resources"
)

// Updates come from MyGo's updater in its native UI window, as Sparkle's
// does for other Mac apps: a daily background check, the release notes with
// Install Update, Remind Me Later and Skip This Version, the download's
// progress and the offer to relaunch. Only signed updates install. Release
// builds configured with an update feed and public key update themselves
// (scripts/xcode-build-go.sh, docs/updates.md); development builds never do.

// updaterUsed is set once Run installed the plugin; headless tests run
// without it, and every accessor below then reports updates as unavailable.
var updaterUsed atomic.Bool

// useUpdater installs the update window before App.Run. changed runs on the
// main thread after a check or a change of the user's choices.
func useUpdater(changed func()) {
	mygo.Use(native.New(updater.Options{Language: string(i18n.Current()), Icon: resources.AppLogo}))
	updaterUsed.Store(true)
	updater.OnChange(changed)
}

// updatesEnabled caches mygo.Updater.Enabled, which probes the install location.
var updatesEnabled = sync.OnceValue(func() bool { return updaterUsed.Load() && mygo.Updater.Enabled() })

// updateState is what Settings › Updates shows.
type updateState struct {
	// Enabled is whether this build can update itself: a release build with
	// an update feed, installed where it can write.
	Enabled            bool
	Version            string
	LastCheck          time.Time
	AutomaticChecks    bool
	AutomaticDownloads bool
}

func currentUpdateState() updateState {
	if !updaterUsed.Load() {
		return updateState{Version: appVersion()}
	}
	return updateState{
		Enabled:            updatesEnabled(),
		Version:            appVersion(),
		LastCheck:          updater.LastCheck(),
		AutomaticChecks:    updater.AutomaticChecks(),
		AutomaticDownloads: updater.AutomaticDownloads(),
	}
}

func appVersion() string {
	if !updaterUsed.Load() {
		return ""
	}
	return mygo.App.Version()
}

func setAutomaticUpdateChecks(on bool) {
	if updaterUsed.Load() {
		updater.SetAutomaticChecks(on)
	}
}

func setAutomaticUpdateDownloads(on bool) {
	if updaterUsed.Load() {
		updater.SetAutomaticDownloads(on)
	}
}

// checkForUpdates opens the update window, which tells what the check finds,
// including why a build cannot update itself.
func checkForUpdates() {
	if updaterUsed.Load() {
		updater.CheckForUpdates()
	}
}

// checkForUpdatesMenuItem is "Check for Updates…" in the plugin's language.
func checkForUpdatesMenuItem() *mygo.MenuItem {
	if !updaterUsed.Load() {
		return nil
	}
	return updater.MenuItem()
}
