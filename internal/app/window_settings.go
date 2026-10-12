// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) settingsUpdates(c *ui.Context) {
	state := currentUpdateState()
	ui.Text(c, i18n.T("settings.updates.description")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
	kit.DetailCard(c, i18n.T("settings.updates.status_title"), func() {
		lastCheck := i18n.T("settings.updates.never_checked")
		if !state.LastCheck.IsZero() {
			lastCheck = state.LastCheck.Local().Format("2006-01-02 15:04")
		}
		kit.DetailField(c, i18n.T("settings.version_label"), settingsVersion(state.Version), "")
		ui.Box(c).Height(1).Shrink(0).Background(kit.Line)
		kit.DetailField(c, i18n.T("settings.updates.last_check"), lastCheck, "")
	})
	kit.Section(c, i18n.T("settings.updates.preferences_title"), func() {
		if kit.SwitchRow(c, &state.AutomaticChecks, i18n.T("settings.updates.automatic_checks"), "", !state.Enabled).Changed() {
			setAutomaticUpdateChecks(state.AutomaticChecks)
		}
		ui.Box(c).Height(1).Shrink(0).Background(kit.Line)
		if kit.SwitchRow(c, &state.AutomaticDownloads, i18n.T("settings.updates.automatic_downloads"), "", !state.Enabled || !state.AutomaticChecks).Changed() {
			setAutomaticUpdateDownloads(state.AutomaticDownloads)
		}
		if state.Enabled {
			kit.Notice(c, kit.ToneInfo, i18n.T("settings.updates.available_hint"))
		} else {
			kit.Notice(c, kit.ToneInfo, i18n.T("settings.updates.unavailable_hint"))
		}
		ui.Row(c).Children(func() {
			if kit.Button(c, i18n.T("settings.updates.check_now"), "sync", kit.ButtonPrimary, false).Clicked() {
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
	kit.Section(c, i18n.T("settings.tab.about"), func() {
		ui.Text(c, i18n.T("app.settings.about")).FontSize(12).LineHeight(1.6)
		ui.Text(c, i18n.T("settings.about.license")).FontSize(12)
		ui.Text(c, i18n.T("settings.about.third_party")).FontSize(12).TextColor(kit.Muted).LineHeight(1.5)
	})
}

// settingsGeneral works while the vault is locked, as the language picker of
// the login and unlock pages does.
func (a *app) settingsGeneral(c *ui.Context) {
	ui.Column(c).Gap(8).Children(func() {
		ui.Text(c, i18n.T("app.language.title")).Padding(0, 4).FontSize(12.5).FontWeight(600).TextColor(kit.Muted)
		options := []struct {
			value         i18n.Lang
			title, detail string
		}{{"", i18n.T("app.language.system"), i18n.T("app.language.system_detail")}}
		for _, l := range i18n.Languages {
			options = append(options, struct {
				value         i18n.Lang
				title, detail string
			}{l, l.Name(), ""})
		}
		selected := i18n.Preference()
		kit.ChoiceGroup(c, i18n.T("app.language.title"), func() {
			for _, option := range options {
				if kit.Choice(c, &selected, option.value, option.title, option.detail, "", false).Changed() {
					i18n.SetPreference(selected)
				}
			}
		})
		ui.Text(c, i18n.T("app.language.hint")).Padding(0, 4).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
	})
}

// settingsServiceRow navigates to an account page, with a leading icon and
// trailing disclosure instead of a centered, full-width action label.
func settingsServiceRow(c *ui.Context, title, symbol string, disabled bool) ui.Element {
	row := ui.ButtonBase(c).Label(title).MinHeight(44).Padding(10).Gap(12).
		Radius(kit.ControlRadius).AlignItems(ui.Center).TextColor(kit.Ink).Disabled(disabled)
	if disabled {
		row.Opacity(.45)
	} else if row.Pressed() {
		row.Background(kit.Lavender)
	} else if row.Hovered() {
		row.Background(kit.Selected)
	}
	return row.Children(func() {
		kit.Icon(c, symbol, 18).TextColor(kit.Purple).Shrink(0)
		ui.Text(c, title).FontSize(13).LineHeight(1.4).Grow(1).MinWidth(0)
		kit.Icon(c, "chevron", 14).TextColor(kit.Muted).Shrink(0)
	})
}

func (a *app) settings(c *ui.Context) {
	if a.windows.settingsTab == settingsTabGeneral || a.windows.settingsTab == settingsTabUpdates || a.windows.settingsTab == settingsTabAbout {
		ui.Scroll(c.Key(string(a.windows.settingsTab))).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(16).MinWidth(0).Padding(10, 0).Children(func() {
				if a.windows.settingsTab == settingsTabGeneral {
					a.settingsGeneral(c)
				} else if a.windows.settingsTab == settingsTabUpdates {
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
			kit.EmptyState(c, "lock", i18n.T("app.list.status_locked"), i18n.T("settings.locked_hint")).Grow(0)
			if kit.Action(c, i18n.T("settings.show_main_window"), "lock", true, false).Clicked() {
				a.showMainWindow()
			}
		})
		return
	}
	ready := a.snapshot != nil && a.pending == 0
	available := a.snapshot != nil && a.snapshot.Available
	ui.Scroll(c.Key("settings-" + string(a.windows.settingsTab))).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(16).MinWidth(0).Padding(10, 0).Children(func() {
			if a.windows.settingsTab != settingsTabStorage {
				ui.Text(c, i18n.T("settings.account.description")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
				kit.DetailCard(c, i18n.T("app.settings.connect_vault"), func() {
					kit.DetailField(c, i18n.T("settings.account.server"), a.connectedServer(), "—")
					ui.Box(c).Height(1).Shrink(0).Background(kit.Line)
					kit.DetailField(c, i18n.T("settings.tab.account"), a.email, "—")
					ui.Column(c).Padding(0, 16, 14, 16).Gap(12).Children(func() {
						ui.Text(c, i18n.T("app.settings.credentials_hint")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
						ui.Row(c).Gap(8).Wrap().Children(func() {
							if kit.Action(c, i18n.T("login.title"), "user", true, a.pending != 0).Clicked() {
								a.resetLoginForm()
								a.showLogin = true
								a.status = ""
								a.showMainWindow()
							}
						})
					})
				})
				kit.Section(c, i18n.T("app.settings.account_services"), func() {
					if warning := a.mfaWarnings.warning(a.serverURL, a.email); warning != "" {
						kit.Notice(c, kit.ToneWarning, warning)
					}
					if a.runtimeVault != nil {
						ui.Column(c.Key(a.secretInputVersion)).Gap(12).Children(func() {
							kit.Notice(c, kit.ToneInfo, i18n.T("app.settings.runtime_vault_hint"))
							if a.diskSnapshot != nil && a.diskSnapshot.Scope != nil && a.liveScope != nil && *a.diskSnapshot.Scope != *a.liveScope {
								oldAccount := a.diskSnapshot.Scope.Account
								if a.diskSnapshot.PasswordUnlock != nil {
									oldAccount = a.diskSnapshot.PasswordUnlock.Email
								}
								kit.Notice(c, kit.ToneWarning, i18n.Tf("app.settings.account_replacement_summary", a.diskSnapshot.Scope.Server, oldAccount, a.liveScope.Server, a.email))
								kit.Notice(c, kit.ToneInfo, i18n.T("app.settings.account_replacement_hint"))
								label := i18n.T("app.settings.confirm_account_replacement")
								if a.runtimeReplaceConfirmed {
									label = i18n.T("app.settings.withdraw_account_replacement")
								}
								ui.Row(c).Children(func() {
									if kit.Action(c, label, "user", false, a.pending != 0).Clicked() {
										a.runtimeReplaceConfirmed = !a.runtimeReplaceConfirmed
									}
								})
							}
							kit.Field(c, i18n.T("app.settings.bind_master_password_label"), "", func() {
								kit.Input(ui.TextInput(c, &a.masterPassword).Label(i18n.T("app.settings.bind_master_password_label")).Password().Disabled(a.pending != 0))
							})
							ui.Row(c).Children(func() {
								if kit.Action(c, i18n.T("app.settings.bind_master_password_sync"), "lock", true, a.pending != 0 || a.masterPassword == "").Clicked() {
									a.bindRuntimePasswordWith(a.postUI, localstore.Call)
								}
							})
						})
					}
					if !ready || a.mainEditorOpen() {
						reason := i18n.T("settings.account.wait_hint")
						if a.mainEditorOpen() {
							reason = i18n.T("settings.account.editor_hint")
						}
						kit.Notice(c, kit.ToneInfo, reason)
					}
					busy := !ready || a.mainEditorOpen()
					ui.Column(c).Gap(6).Children(func() {
						for index, page := range accountPages {
							if index > 0 {
								ui.Box(c).Height(1).Shrink(0).Background(kit.Line)
							}
							title := i18n.T(page.title)
							if page.tab == accountTabSend {
								title = i18n.T("settings.account.send")
							}
							if settingsServiceRow(c.Key(string(page.tab)), title, page.symbol, busy).Clicked() {
								a.openAccountPage(page.tab)
							}
						}
					})
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if kit.Action(c, i18n.T("app.settings.verify_target_recovery"), "vault", false, a.pending != 0).Clicked() {
							a.openTargetRecovery()
							a.showMainWindow()
						}
					})
				})
			}
			if a.windows.settingsTab == settingsTabStorage {
				a.loadAutofillSettings()
				ui.Text(c, i18n.T("settings.storage.description")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
				kit.Section(c, i18n.T("settings.storage.snapshot_title"), func() {
					ui.Column(c).Gap(12).Children(func() {
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
								a.runStorage(localstore.OperationList)
							}
							if kit.Action(c, i18n.T("app.settings.refresh_status"), "sync", false, a.pending != 0).Clicked() {
								a.runStorage(localstore.OperationStatus)
							}
						})
						ui.Divider(c)
						if a.snapshot != nil && a.snapshot.IndexPending {
							kit.Notice(c, kit.ToneInfo, i18n.T("app.settings.autofill_pending_hint"))
						}
						ui.Row(c).Gap(8).Wrap().Children(func() {
							if kit.Action(c, i18n.T("app.settings.autofill"), "settings", false, false).Clicked() {
								openAutoFillSettings(c)
							}
							if kit.Action(c, i18n.T("app.settings.update_autofill"), "shield", false, !ready || !available).Clicked() {
								a.runStorage(localstore.OperationReindex)
							}
						})
						copyTOTP := a.autofillSettings.copyTOTP
						if kit.SwitchRow(c, &copyTOTP, i18n.T("settings.storage.copy_totp"), i18n.T("settings.storage.copy_totp_hint"), !a.autofillSettings.loaded || a.autofillSettings.busy).Changed() {
							a.requestAutofillSettings(&copyTOTP)
						}
						if a.autofillSettings.message != "" {
							kit.Notice(c, kit.ToneWarning, a.autofillSettings.message)
						}
						if a.snapshot != nil && a.snapshot.CleanupPending {
							kit.Notice(c, kit.ToneWarning, i18n.T("app.settings.cleanup_pending_hint"))
							ui.Row(c).Children(func() {
								if kit.Action(c, i18n.T("app.settings.retry_cleanup"), "sync", false, !ready).Clicked() {
									a.runStorage(localstore.OperationRetryCleanup)
								}
							})
						}
					})
				})
			}
			if a.windows.settingsTab != settingsTabStorage {
				ui.Row(c).Gap(8).Wrap().Padding(0, 16).Children(func() {
					logoutLabel := i18n.T("app.settings.log_out")
					if a.runtimeVault != nil {
						logoutLabel = i18n.T("app.settings.end_temporary_session")
					}
					if kit.Button(c, logoutLabel, "user", kit.ButtonDanger, a.snapshot == nil).Clicked() {
						a.runStorage(localstore.OperationLogout)
					}
				})
			}
		})
	})
}
