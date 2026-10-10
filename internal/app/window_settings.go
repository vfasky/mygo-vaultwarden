// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// settingsWindowOptions are the Settings window's native options;
// showSettingsWindow adds its StateKey and Content.
func settingsWindowOptions() mygo.WindowOptions {
	return mygo.WindowOptions{Title: i18n.T("app.window.settings_title"), Width: 720, Height: 560, MinWidth: 620, MinHeight: 460}
}

// settingsWindowView is the Settings window (⌘,).
func (a *app) settingsWindowView(c *ui.Context) {
	a.framePrelude(c)
	c.SetTheme(kit.Theme)
	ui.Column(c).Fill().TextColor(kit.Ink).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
		ui.Box(c).Height(max(c.TitleBar().Height, 28)).Shrink(0).DragWindow()
		ui.Row(c).Justify(ui.Center).Gap(4).Padding(0, 8, 10, 8).Role(ui.RoleTabList).Label(i18n.T("app.settings.title")).Children(func() {
			for _, pane := range []struct {
				tab         settingsTab
				label, icon string
			}{
				{settingsTabAccount, i18n.T("settings.tab.account"), "user"},
				{settingsTabStorage, i18n.T("app.settings.local_storage_autofill"), "vault"},
				{settingsTabUpdates, i18n.T("settings.tab.updates"), "sync"},
				{settingsTabAbout, i18n.T("settings.tab.about"), "shield"},
			} {
				selected := a.windows.settingsTab == pane.tab || a.windows.settingsTab == "" && pane.tab == settingsTabAccount
				tab := ui.ButtonBase(c.Key(string(pane.tab))).Column().AlignItems(ui.Center).Gap(4).MinWidth(82).Padding(7, 12).Radius(8).
					Role(ui.RoleTab).Selected(selected).Label(pane.label).FontSize(11).TextColor(kit.Muted)
				if selected {
					tab.Background(ui.Hex("#DDD3F2")).TextColor(kit.Purple)
				} else if tab.Hovered() {
					tab.Background(ui.Hex("#E7E1F0"))
				}
				tab.Children(func() {
					kit.Icon(c, pane.icon, 21)
					ui.Text(c, pane.label).SingleLine()
				})
				if tab.Clicked() {
					a.windows.settingsTab = pane.tab
				}
			}
		})
		ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Children(func() { a.settings(c) })
	})
}

func (a *app) settingsUpdates(c *ui.Context) {
	state := currentUpdateState()
	kit.DetailCard(c, i18n.T("settings.tab.updates"), func() {
		ui.Column(c).Padding(16).Gap(14).Children(func() {
			ui.Text(c, i18n.Tf("settings.version", settingsVersion(state.Version))).FontSize(14)
			if state.Enabled {
				ui.Text(c, i18n.T("settings.updates.available_hint")).FontSize(12).TextColor(kit.Muted)
			} else {
				ui.Text(c, i18n.T("settings.updates.unavailable_hint")).FontSize(12).TextColor(kit.Muted)
			}
			if ui.Checkbox(c, &state.AutomaticChecks, i18n.T("settings.updates.automatic_checks")).Disabled(!state.Enabled).Changed() {
				setAutomaticUpdateChecks(state.AutomaticChecks)
			}
			if ui.Checkbox(c, &state.AutomaticDownloads, i18n.T("settings.updates.automatic_downloads")).Disabled(!state.Enabled || !state.AutomaticChecks).Changed() {
				setAutomaticUpdateDownloads(state.AutomaticDownloads)
			}
			lastCheck := i18n.T("settings.updates.never_checked")
			if !state.LastCheck.IsZero() {
				lastCheck = state.LastCheck.Local().Format("2006-01-02 15:04")
			}
			ui.Text(c, i18n.Tf("settings.updates.last_check", lastCheck)).FontSize(12).TextColor(kit.Muted)
			if kit.Action(c, i18n.T("settings.updates.check_now"), "sync", true, false).Clicked() {
				checkForUpdates()
			}
		})
	})
}

func settingsVersion(version string) string {
	if version == "" {
		return "—"
	}
	return version
}

func (a *app) settingsAbout(c *ui.Context) {
	ui.Column(c).AlignItems(ui.Center).Gap(12).Padding(20).Children(func() {
		if kit.AppLogo != nil {
			ui.Image(c, kit.AppLogo).Size(80, 80)
		}
		ui.Text(c, i18n.T("settings.app_name")).FontSize(24).FontWeight(650)
		ui.Text(c, i18n.Tf("settings.version", settingsVersion(currentUpdateState().Version))).FontSize(12).TextColor(kit.Muted)
	})
	kit.DetailCard(c, i18n.T("settings.tab.about"), func() {
		ui.Column(c).Padding(16).Gap(12).Children(func() {
			ui.Text(c, i18n.T("app.settings.about")).FontSize(12).LineHeight(1.6)
			ui.Text(c, i18n.T("settings.about.license")).FontSize(12).TextColor(kit.Muted)
			ui.Text(c, i18n.T("settings.about.third_party")).FontSize(12).TextColor(kit.Muted).LineHeight(1.5)
		})
	})
}

func (a *app) settings(c *ui.Context) {
	if a.windows.settingsTab == settingsTabUpdates || a.windows.settingsTab == settingsTabAbout {
		ui.Scroll(c.Key(string(a.windows.settingsTab))).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(18).Padding(10, 8).Children(func() {
				if a.windows.settingsTab == settingsTabUpdates {
					a.settingsUpdates(c)
				} else {
					a.settingsAbout(c)
				}
			})
		})
		return
	}
	if !a.unlocked() || a.showLogin {
		ui.Column(c).Grow(1).Justify(ui.Center).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Text(c, i18n.T("app.list.status_locked")).FontSize(15).FontWeight(550)
			if kit.Action(c, i18n.T("settings.show_main_window"), "lock", true, false).Clicked() {
				a.showMainWindow()
			}
		})
		return
	}
	ready := a.snapshot != nil && a.pending == 0
	available := a.snapshot != nil && a.snapshot.Available
	ui.Scroll(c.Key("settings-" + string(a.windows.settingsTab))).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(18).Padding(10, 8).Children(func() {
			if a.windows.settingsTab != settingsTabStorage {
				kit.DetailCard(c, i18n.T("app.settings.account_services"), func() {
					if warning := a.mfaWarnings.warning(a.serverURL, a.email); warning != "" {
						ui.Text(c, warning).MaxLines(4)
					}
					if a.runtimeVault != nil {
						ui.Column(c.Key(a.secretInputVersion)).Padding(16).Gap(8).Children(func() {
							ui.Text(c, i18n.T("app.settings.runtime_vault_hint")).MaxLines(4)
							if a.diskSnapshot != nil && a.diskSnapshot.Scope != nil && a.liveScope != nil && *a.diskSnapshot.Scope != *a.liveScope {
								oldAccount := a.diskSnapshot.Scope.Account
								if a.diskSnapshot.PasswordUnlock != nil {
									oldAccount = a.diskSnapshot.PasswordUnlock.Email
								}
								ui.Text(c, i18n.Tf("app.settings.account_replacement_summary", a.diskSnapshot.Scope.Server, oldAccount, a.liveScope.Server, a.email)).MaxLines(5)
								ui.Text(c, i18n.T("app.settings.account_replacement_hint")).MaxLines(6)
								label := i18n.T("app.settings.confirm_account_replacement")
								if a.runtimeReplaceConfirmed {
									label = i18n.T("app.settings.withdraw_account_replacement")
								}
								if kit.Action(c, label, "user", false, a.pending != 0).Clicked() {
									a.runtimeReplaceConfirmed = !a.runtimeReplaceConfirmed
								}
							}
							ui.TextInput(c, &a.masterPassword).Label(i18n.T("app.settings.bind_master_password_label")).Password().Disabled(a.pending != 0)
							if kit.Action(c, i18n.T("app.settings.bind_master_password_sync"), "lock", true, a.pending != 0 || a.masterPassword == "").Clicked() {
								a.bindRuntimePasswordWith(a.postUI, localstore.Call)
							}
						})
					}
					if !ready || a.mainEditorOpen() {
						reason := i18n.T("settings.account.wait_hint")
						if a.mainEditorOpen() {
							reason = i18n.T("settings.account.editor_hint")
						}
						ui.Text(c, reason).Padding(16, 16, 0, 16).FontSize(12).TextColor(kit.Muted)
					}
					ui.Row(c).Padding(16).Gap(8).Wrap().Children(func() {
						if kit.Action(c, i18n.T("app.settings.verify_target_recovery"), "vault", false, a.pending != 0).Clicked() {
							a.openTargetRecovery()
							a.showMainWindow()
						}
						busy := !ready || a.mainEditorOpen()
						if kit.Action(c, i18n.T("account.emergency.title"), "vault", false, busy).Clicked() {
							a.openAccountPage(accountTabEmergency)
						}
						if kit.Action(c, i18n.T("settings.account.send"), "send", false, busy).Clicked() {
							a.openAccountPage(accountTabSend)
						}
						if kit.Action(c, i18n.T("account.device.title"), "shield", false, busy).Clicked() {
							a.openAccountPage(accountTabDevices)
						}
						if kit.Action(c, i18n.T("account.form.title"), "user", false, busy).Clicked() {
							a.openAccountPage(accountTabSecurity)
						}
						if kit.Action(c, i18n.T("app.settings.mfa"), "shield", false, busy).Clicked() {
							a.openAccountPage(accountTabMFA)
						}
					})
				})
				kit.DetailCard(c, i18n.T("app.settings.connect_vault"), func() {
					ui.Column(c).Padding(16).Gap(13).Children(func() {
						ui.Text(c, a.connectedServer()).FontSize(14).MaxLines(2)
						ui.Text(c, i18n.T("app.settings.credentials_hint")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
						if kit.Action(c, i18n.T("login.title"), "user", true, a.pending != 0).Clicked() {
							a.resetLoginForm()
							a.showLogin = true
							a.status = ""
							a.showMainWindow()
						}
					})
				})
			}
			if a.windows.settingsTab == settingsTabStorage {
				kit.DetailCard(c, i18n.T("app.settings.local_storage_autofill"), func() {
					ui.Column(c).Padding(16).Gap(12).Children(func() {
						state := i18n.T("app.settings.no_snapshot")
						if available {
							state = i18n.Tf("app.settings.snapshot_count", a.snapshot.Count)
						}
						ui.Text(c, state).FontSize(13)
						if available && a.snapshot.UpdatedAt > 0 {
							ui.Text(c, i18n.Tf("app.settings.last_synced", time.UnixMilli(a.snapshot.UpdatedAt).Format("2006-01-02 15:04"))).FontSize(11).TextColor(kit.Muted)
						}
						ui.Row(c).Gap(8).Wrap().Children(func() {
							if kit.Action(c, i18n.T("app.settings.unlock_offline"), "lock", false, !ready || !available).Clicked() {
								a.runStorage("list")
							}
							if kit.Action(c, i18n.T("app.settings.refresh_status"), "sync", false, a.pending != 0).Clicked() {
								a.runStorage("status")
							}
						})
						ui.Divider(c)
						if a.snapshot != nil && a.snapshot.IndexPending {
							ui.Text(c, i18n.T("app.settings.autofill_pending_hint")).FontSize(12).TextColor(kit.Purple)
						}
						ui.Row(c).Gap(8).Wrap().Children(func() {
							if kit.Action(c, i18n.T("app.settings.autofill"), "settings", false, false).Clicked() {
								openAutoFillSettings(c)
							}
							if kit.Action(c, i18n.T("app.settings.update_autofill"), "shield", false, !ready || !available).Clicked() {
								a.runStorage("reindex")
							}
						})
						if a.snapshot != nil && a.snapshot.CleanupPending {
							ui.Text(c, i18n.T("app.settings.cleanup_pending_hint")).FontSize(12).TextColor(kit.Purple)
							if kit.Action(c, i18n.T("app.settings.retry_cleanup"), "sync", false, !ready).Clicked() {
								a.runStorage("retryCleanup")
							}
						}
					})
				})
			}
			if a.windows.settingsTab != settingsTabStorage {
				ui.Row(c).Gap(8).Wrap().Children(func() {
					logoutLabel := i18n.T("app.settings.log_out")
					if a.runtimeVault != nil {
						logoutLabel = i18n.T("app.settings.end_temporary_session")
					}
					if kit.Action(c, logoutLabel, "user", false, a.snapshot == nil).Clicked() {
						a.runStorage("logout")
					}
				})
			}
		})
	})
}
