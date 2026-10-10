// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) organizationRecoveryKeyView(c *ui.Context, e *organizationEditor, disabled bool) {
	ui.Text(c, i18n.T("org.recovery.public_key_title")).FontSize(18)
	ui.Text(c, i18n.T("org.recovery.public_key_hint")).MaxLines(4)
	if kit.Action(c, i18n.T("org.recovery.show_public_key"), "", false, disabled).Key("organization-recovery-key-load").Clicked() {
		a.runOrganizationManagement("recovery-key-load")
	}
	if e.organizationRecoveryKey != "" {
		ui.TextInput(c, &e.organizationRecoveryKey).Label(i18n.T("org.recovery.public_key")).Disabled(disabled)
	} else {
		if e.confirmation != "recovery-key-create" {
			if kit.Action(c, i18n.T("org.recovery.initialize_keys"), "", false, disabled).Key("organization-recovery-key-create").Clicked() {
				e.confirmation = "recovery-key-create"
			}
		} else {
			ui.Text(c, i18n.T("org.recovery.initialize_hint")).MaxLines(6)
			if kit.Action(c, i18n.T("org.recovery.confirm_initialize"), "", true, disabled).Key("organization-recovery-key-confirm").Clicked() {
				a.runOrganizationManagement("recovery-key-create")
			}
			if kit.Action(c, i18n.T("org.recovery.cancel_initialize"), "", false, disabled).Clicked() {
				e.confirmation = ""
			}
		}
	}
}
