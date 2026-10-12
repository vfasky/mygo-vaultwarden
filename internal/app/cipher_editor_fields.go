// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"encoding/json"
	"fmt"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"time"
)

// Bitwarden clients 5983f56ce0cf924eea56c7d8f066f7885825a7ce:
// libs/common/src/vault/enums/linked-id-type.enum.ts.
var linkedFields = map[int][]struct {
	id    json.Number
	label string
}{
	1: {{"100", "common.username"}, {"101", "common.password"}},
	3: {{"300", "vault.field.card.holder"}, {"301", "vault.field.card.expiration_month"}, {"302", "vault.field.card.expiration_year"}, {"303", "vault.field.card.security_code"}, {"304", "vault.field.card.brand"}, {"305", "vault.field.card.number"}},
	4: {
		{"400", "vault.field.identity.title"},
		{"401", "vault.field.middle_name"},
		{"402", "vault.field.identity.address_one"},
		{"403", "vault.field.identity.address_two"},
		{"404", "vault.field.identity.address_three"},
		{"405", "vault.field.identity.city"},
		{"406", "vault.field.identity.state"},
		{"407", "vault.field.identity.postal_code"},
		{"408", "vault.field.identity.country"},
		{"409", "vault.field.identity.company"},
		{"410", "common.email"},
		{"411", "vault.field.identity.phone"},
		{"412", "vault.field.identity.social_security_number"},
		{"413", "common.username"},
		{"414", "vault.field.passport.number"},
		{"415", "vault.field.license.number"},
		{"416", "vault.field.first_name"},
		{"417", "vault.field.last_name"},
		{"418", "vault.field.identity.full_name"},
	},
}

// The match numbers are from the same commit's
// libs/common/src/models/domain/domain-service.ts.
var uriMatches = []struct {
	value any
	label string
}{
	{nil, "common.default"}, {json.Number("0"), "vault.uri.base_domain"}, {json.Number("1"), "urimatch.host"}, {json.Number("2"), "vault.uri.starts_with"}, {json.Number("3"), "urimatch.exact"}, {json.Number("4"), "urimatch.regular_expression"}, {json.Number("5"), "vault.uri.never"},
}

func (a *app) uriMatchPicker(c *ui.Context, u *editorURI, disabled bool) {
	label := i18n.T("vault.uri.unknown")
	for _, m := range uriMatches {
		if u.source["match"] == m.value {
			label = i18n.T(m.label)
		}
	}
	if u.source["match"] == nil && a.editor != nil {
		for _, m := range uriMatches[1:] {
			if m.value == json.Number(fmt.Sprint(a.editor.defaultURIMatch)) {
				ui.Text(c, i18n.Tf("vault.uri.default_policy_hint", i18n.T(m.label))).FontSize(11).MaxLines(3)
			}
		}
	}
	if kit.Button(c, i18n.Tf("vault.uri.match_label", label), "", kit.ButtonQuiet, disabled).AlignSelf(ui.Start).Clicked() {
		u.showMatch = !u.showMatch
	}
	if u.showMatch {
		kit.ChoiceGroup(c, i18n.Tf("vault.uri.match_label", label), func() {
			for _, m := range uriMatches {
				selected := u.source["match"]
				if kit.Choice(c, &selected, m.value, i18n.T(m.label), "", "", disabled).Changed() {
					copy := map[string]any{}
					for key, value := range u.source {
						copy[key] = value
					}
					copy["match"] = m.value
					u.source = copy
					u.showMatch = false
				}
			}
		})
		kit.Notice(c, kit.ToneInfo, i18n.T("vault.uri.autofill_hint"))
	}
}
func (a *app) customValueEditor(c *ui.Context, e *cipherEditor, f *editorCustom) {
	disabled := a.pending != 0 || e.uncertain || !f.editable
	switch f.kind {
	case "2":
		label := i18n.T("vault.field.boolean_false")
		if f.value == "true" {
			label = i18n.T("vault.field.boolean_true")
		} else if f.value != "false" {
			label = i18n.T("vault.field.boolean_unknown")
		}
		on := f.value == "true"
		if kit.Checkbox(c, &on, label, disabled).Changed() {
			if on {
				f.value = "true"
			} else {
				f.value = "false"
			}
		}
	case "3":
		label := i18n.T("vault.field.linked_unknown")
		for _, linked := range linkedFields[e.fields.Type] {
			if linked.id == f.linkedID {
				label = i18n.T(linked.label)
			}
		}
		if kit.Button(c, i18n.Tf("vault.field.linked_target", label), "", kit.ButtonQuiet, disabled).AlignSelf(ui.Start).Clicked() {
			f.showLinks = !f.showLinks
		}
		if f.showLinks {
			kit.ChoiceGroup(c, i18n.Tf("vault.field.linked_target", label), func() {
				for _, linked := range linkedFields[e.fields.Type] {
					if kit.Choice(c, &f.linkedID, linked.id, i18n.T(linked.label), "", "", disabled).Changed() {
						f.showLinks = false
					}
				}
			})
		}
	default:
		kit.Field(c, i18n.T("vault.field.custom_value"), "", func() {
			value := kit.Input(ui.TextInput(c, &f.value).Label(i18n.T("vault.field.custom_value")).Disabled(disabled))
			if f.hidden {
				value.Password()
			}
		})
	}
}
func (a *app) passwordHistoryView(c *ui.Context, e *cipherEditor) {
	if e.showHistory && (!time.Now().Before(e.historyExpires) || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision) {
		e.showHistory = false
		clear(e.shownHistory)
		e.shownHistory = nil
	}
	if e.showHistory {
		c.After(time.Until(e.historyExpires))
	}
	if len(e.fields.PasswordHistory) == 0 {
		return
	}
	kit.Section(c, i18n.T("vault.history.title"), func() {
		if e.confirmHistoryDelete {
			kit.ConfirmDialog(c, "history-clear", i18n.T("vault.history.clear"), i18n.T("vault.history.confirm_clear_hint"), i18n.T("vault.history.confirm_clear"), i18n.T("vault.history.keep"), a.pending != 0 || e.uncertain,
				func() {
					e.fields.PasswordHistory = nil
					e.confirmHistoryDelete, e.showHistory = false, false
					clear(e.shownHistory)
					e.shownHistory = nil
				}, func() {
					if a.pending == 0 {
						e.confirmHistoryDelete = false
					}
				})
		}
		if kit.Button(c, i18n.T("vault.history.clear"), "", kit.ButtonDanger, a.pending != 0 || e.uncertain).AlignSelf(ui.Start).Clicked() {
			e.confirmHistoryDelete = true
		}
		label := i18n.Tf("vault.history.show_saved", len(e.fields.PasswordHistory))
		if e.showHistory {
			label = i18n.T("vault.history.hide")
		}
		if kit.Button(c, label, "key", kit.ButtonQuiet, a.pending != 0 || e.uncertain).AlignSelf(ui.Start).Clicked() {
			if e.showHistory {
				e.showHistory = false
				clear(e.shownHistory)
				e.shownHistory = nil
			} else {
				a.showCipherHistory(a.vaultStorage())
			}
		}
		if e.showHistory {
			ui.Scroll(c).Height(float32(min(160, len(e.shownHistory)*48))).Children(func() {
				ui.Column(c).Gap(8).Children(func() {
					for _, entry := range e.shownHistory {
						ui.Row(c).Gap(12).Padding(8).AlignItems(ui.Center).Children(func() {
							ui.Text(c, entry.Password).FontSize(12).Grow(1).MinWidth(0).MaxLines(3)
							ui.Text(c, entry.LastUsedDate).FontSize(11).TextColor(kit.Muted)
						})
					}
				})
			})
		}
	})
}
