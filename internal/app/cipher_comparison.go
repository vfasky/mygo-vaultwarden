// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"errors"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) compareCipher(grant *vaultwarden.ItemAuthorization) {
	e := a.editor
	if e == nil || e.fields.ID == "" || a.pending != 0 || !a.sessionOwnsSnapshot() || e.revision == a.sessionRevision {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	e.applyInputs()
	e.shownSecret = ""
	clearCipherRowReveal(e)
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	plan, changes, err := s.ComparePersonalCipher(a.vault, a.sessionRevision, e.document, e.fields, grant)
	if err != nil {
		if errors.Is(err, vaultwarden.ErrPermission) && grant == nil && s.PersonalItemRequiresPassword(a.vault, e.fields.ID) {
			e.compareAuthorization = true
			e.repromptID = e.fields.ID
			e.authorization = nil
			a.secretInputVersion++
		}
		a.status = i18n.Tf("vault.compare.err_unavailable", vaultwarden.ErrorMessage(err))
		return
	}
	e.repromptID, e.repromptPassword = "", ""
	e.compareAuthorization = false
	e.authorization = grant
	if grant != nil {
		e.authorizationExpires = grant.ExpiresAt()
	}
	e.comparison, e.changes = plan, changes
	e.localChoices = map[string]bool{}
	e.rowChoices = map[string][]int{}
	for _, change := range changes {
		choices := make([]int, len(change.LocalRows))
		for i := range choices {
			choices[i] = -2
		}
		e.rowChoices[change.Path] = choices
	}
	a.status = i18n.T("vault.compare.status_review_required")
	a.secretInputVersion++
}

func comparisonFieldLabel(path string) string {
	switch path {
	case "name":
		return i18n.T("vault.field.title")
	case "notes":
		return i18n.T("common.notes")
	case "folderId":
		return i18n.T("common.folder")
	case "favorite":
		return i18n.T("vault.field.favorite")
	case "fields":
		return i18n.T("vault.field.custom")
	case "passwordHistory":
		return i18n.T("vault.compare.password_history")
	case "login.uris":
		return i18n.T("vault.compare.websites")
	case "secureNote.type":
		return i18n.T("vault.field.note.type")
	}
	key := path[strings.Index(path, ".")+1:]
	for _, specs := range editorSpecs {
		for _, spec := range specs {
			if spec.key == key {
				return i18n.T(spec.label)
			}
		}
	}
	return i18n.T("vault.compare.item_content")
}

func (a *app) cipherComparisonView(c *ui.Context) {
	e := a.editor
	if e.rowPreview != nil {
		if !time.Now().Before(e.rowPreview.expires) || !a.sessionOwnsSnapshot() || e.rowPreview.revision != a.sessionRevision {
			clearCipherRowReveal(e)
		} else {
			c.After(time.Until(e.rowPreview.expires))
		}
	}
	ui.Column(c).Grow(1).MinHeight(0).Children(func() {
		if a.drawerHeader(c, i18n.T("vault.compare.title"), i18n.T("vault.compare.description")) {
			return
		}
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(16).Padding(20).Children(func() {
				if e.uncertain {
					kit.Notice(c, kit.ToneWarning, i18n.T("vault.compare.uncertain_hint"))
				}
				if len(e.changes) == 0 {
					kit.Notice(c, kit.ToneInfo, i18n.T("vault.compare.status_no_changes"))
				}
				for _, change := range e.changes {
					text := i18n.Tf("vault.compare.status_remote_changed", comparisonFieldLabel(change.Path))
					if change.Local {
						text = i18n.Tf("vault.compare.status_local_changed", comparisonFieldLabel(change.Path))
						if change.Remote {
							text = i18n.Tf("vault.compare.status_both_changed", comparisonFieldLabel(change.Path))
						}
					}
					if change.SameValue {
						text = i18n.Tf("vault.compare.same_value", text)
					}
					kit.Section(c.Key(change.Path), comparisonFieldLabel(change.Path), func() {
						ui.Text(c, text).FontSize(12).TextColor(kit.Muted)
						if change.Local && change.CanApply {
							local := e.localChoices[change.Path]
							kit.ChoiceGroup(c, comparisonFieldLabel(change.Path), func() {
								ui.Row(c).Gap(8).Children(func() {
									if kit.Choice(c, &local, false, i18n.T("vault.compare.remote"), "", "", a.pending != 0).Grow(1).MinWidth(0).Changed() {
										e.localChoices[change.Path] = local
									}
									if kit.Choice(c, &local, true, i18n.T("vault.compare.use_local"), "", "", a.pending != 0).Grow(1).MinWidth(0).Changed() {
										e.localChoices[change.Path] = local
									}
								})
							})
						} else if change.Local {
							a.cipherRowPreviewView(c, e, change.Path)
							kit.Notice(c, kit.ToneInfo, i18n.T("vault.compare.row_matching_hint"))
							ui.Row(c).Gap(12).Children(func() {
								ui.Column(c).Grow(1).MinWidth(0).Gap(8).Children(func() {
									ui.Text(c, i18n.T("vault.compare.remote")).FontWeight(600)
									for _, label := range change.RemoteRows {
										ui.Text(c, i18n.Tf("vault.compare.remote_row", label)).FontSize(12).MaxLines(3)
									}
								})
								ui.Column(c).Grow(1).MinWidth(0).Gap(8).Children(func() {
									ui.Text(c, i18n.T("vault.compare.local")).FontWeight(600)
									for i, label := range change.LocalRows {
										choices := e.rowChoices[change.Path]
										if i >= len(choices) {
											continue
										}
										options := []string{i18n.T("vault.compare.keep_remote_row"), i18n.T("vault.compare.add_row")}
										for j := range change.RemoteRows {
											options = append(options, i18n.Tf("vault.compare.match_remote_row", j+1))
										}
										selected := options[choices[i]+2]
										kit.Field(c.Key(i), i18n.Tf("vault.compare.local_row", label), "", func() {
											if ui.Select(c, &selected, options).Label(i18n.Tf("vault.compare.local_row", label)).Disabled(a.pending != 0).Changed() {
												for j, option := range options {
													if option == selected {
														choices[i] = j - 2
														break
													}
												}
											}
										})
									}
								})
							})
						}
					})
				}
				kit.Notice(c, kit.ToneInfo, i18n.T("vault.compare.version_conflict_hint"))
			})
		})
		kit.ActionBar(c, func() {
			ui.Spacer(c)
			if kit.Action(c, i18n.T("vault.compare.use_remote"), "", false, a.pending != 0).Clicked() {
				a.applyCipherComparison(false)
			}
			if kit.Action(c, i18n.T("vault.compare.back_keep_draft"), "", false, a.pending != 0).Clicked() {
				clearCipherRowReveal(e)
				e.comparison = nil
				e.changes = nil
				e.localChoices = nil
				a.secretInputVersion++
			}
			if kit.Action(c, i18n.T("vault.compare.reapply_selections"), "", true, a.pending != 0).Clicked() {
				a.applyCipherComparison(true)
			}
		}).Wrap().Justify(ui.End).Margin(0, 20) // in line with the padded content above
	})
}

func (a *app) applyCipherComparison(useChoices bool) {
	e := a.editor
	if e == nil || e.comparison == nil || a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	clearCipherRowReveal(e)
	choices := []string{}
	if useChoices {
		for path, selected := range e.localChoices {
			if selected {
				choices = append(choices, path)
			}
		}
	}
	rows := []vaultwarden.CipherRowChoice{}
	if useChoices {
		for path, choices := range e.rowChoices {
			for local, remote := range choices {
				if remote >= -1 {
					rows = append(rows, vaultwarden.CipherRowChoice{Path: path, Local: local, Remote: remote})
				}
			}
		}
	}
	document, fields, err := s.ApplyPersonalCipherComparisonRows(a.vault, a.sessionRevision, e.comparison, choices, rows)
	if err != nil {
		a.status = i18n.Tf("vault.compare.err_expired", vaultwarden.ErrorMessage(err))
		e.comparison = nil
		e.changes = nil
		e.localChoices = nil
		return
	}
	grant, expires := e.authorization, e.authorizationExpires
	*e = cipherEditor{document: document, fields: fields, revision: a.sessionRevision, authorization: grant, authorizationExpires: expires}
	populateCipherEditor(e)
	a.secretInputVersion++
	a.status = i18n.T("vault.compare.status_applied")
}
