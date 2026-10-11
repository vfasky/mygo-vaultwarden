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
	if kit.Action(c, i18n.Tf("vault.uri.match_label", label), "", false, disabled).Clicked() {
		u.showMatch = !u.showMatch
	}
	if u.showMatch {
		for _, m := range uriMatches {
			if kit.NavItem(c, i18n.T(m.label), "globe", "", u.source["match"] == m.value, disabled).Clicked() {
				copy := map[string]any{}
				for key, value := range u.source {
					copy[key] = value
				}
				copy["match"] = m.value
				u.source = copy
				u.showMatch = false
			}
		}
		ui.Text(c, i18n.T("vault.uri.autofill_hint")).FontSize(11).MaxLines(3)
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
		if kit.Action(c, label, "", false, disabled).Clicked() {
			if f.value == "true" {
				f.value = "false"
			} else {
				f.value = "true"
			}
		}
	case "3":
		label := i18n.T("vault.field.linked_unknown")
		for _, linked := range linkedFields[e.fields.Type] {
			if linked.id == f.linkedID {
				label = i18n.T(linked.label)
			}
		}
		if kit.Action(c, i18n.Tf("vault.field.linked_target", label), "", false, disabled).Clicked() {
			f.showLinks = !f.showLinks
		}
		if f.showLinks {
			for _, linked := range linkedFields[e.fields.Type] {
				if kit.NavItem(c, i18n.T(linked.label), "key", "", linked.id == f.linkedID, disabled).Clicked() {
					f.linkedID = linked.id
					f.showLinks = false
				}
			}
		}
	default:
		value := ui.TextInput(c, &f.value).Label(i18n.T("vault.field.custom_value")).Disabled(disabled)
		if f.hidden {
			value.Password()
		}
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
	if e.confirmHistoryDelete {
		ui.Text(c, i18n.T("vault.history.confirm_clear_hint")).FontSize(12)
		ui.Row(c).Gap(8).Children(func() {
			if kit.Action(c, i18n.T("vault.history.confirm_clear"), "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.fields.PasswordHistory = nil
				e.confirmHistoryDelete, e.showHistory = false, false
				clear(e.shownHistory)
				e.shownHistory = nil
			}
			if kit.Action(c, i18n.T("vault.history.keep"), "", false, a.pending != 0).Clicked() {
				e.confirmHistoryDelete = false
			}
		})
		return
	}
	if kit.Action(c, i18n.T("vault.history.clear"), "", false, a.pending != 0 || e.uncertain).Clicked() {
		e.confirmHistoryDelete = true
	}
	label := i18n.Tf("vault.history.show_saved", len(e.fields.PasswordHistory))
	if e.showHistory {
		label = i18n.T("vault.history.hide")
	}
	if kit.Action(c, label, "key", false, a.pending != 0 || e.uncertain).Clicked() {
		if e.showHistory {
			e.showHistory = false
			clear(e.shownHistory)
			e.shownHistory = nil
		} else {
			a.showCipherHistory(a.vaultStorage())
		}
	}
	if e.showHistory {
		ui.Scroll(c).Height(160).Children(func() {
			ui.Column(c).Gap(8).Children(func() {
				for _, entry := range e.shownHistory {
					ui.Text(c, entry.LastUsedDate).FontSize(11)
					ui.Text(c, entry.Password).FontSize(12).MaxLines(3)
				}
			})
		})
	}
}
