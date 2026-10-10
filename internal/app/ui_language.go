// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// languageMenu shows the interface language and lets the user follow the
// system or choose one language for this app; the change applies at once.
func languageMenu(c *ui.Context) ui.Element {
	return ui.Button(c, "").Label(i18n.T("app.language.title")).Tooltip(i18n.T("app.language.title")).
		Height(30).Padding(0, 12).Gap(6).Radius(15).Border(0, ui.Transparent).Background(ui.Transparent).
		TextColor(kit.Muted).Children(func() {
		kit.Icon(c, "globe", 14)
		ui.Text(c, i18n.Current().Name()).FontSize(12)
	}).Menu(func(m *ui.Menu) {
		preference := i18n.Preference()
		if m.Item(i18n.T("app.language.system")).Checked(preference == "").Chosen() {
			i18n.SetPreference("")
		}
		m.Separator()
		for _, l := range i18n.Languages {
			if m.Item(l.Name()).Checked(preference == l).Chosen() {
				i18n.SetPreference(l)
			}
		}
	})
}
