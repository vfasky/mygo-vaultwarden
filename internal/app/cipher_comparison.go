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
		a.status = err.Error()
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
		a.status = i18n.Tf("vault.compare.err_unavailable", err.Error())
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
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Gap(12).Padding(18).Children(func() {
			ui.Text(c, i18n.T("vault.compare.title")).FontSize(23).FontWeight(600)
			ui.Text(c, i18n.T("vault.compare.description"))
			if e.uncertain {
				ui.Text(c, i18n.T("vault.compare.uncertain_hint"))
			}
			if len(e.changes) == 0 {
				ui.Text(c, i18n.T("vault.compare.no_changes"))
			}
			for _, change := range e.changes {
				text := i18n.Tf("vault.compare.remote_changed", comparisonFieldLabel(change.Path))
				if change.Local {
					text = i18n.Tf("vault.compare.local_changed", comparisonFieldLabel(change.Path))
					if change.Remote {
						text = i18n.Tf("vault.compare.both_changed", comparisonFieldLabel(change.Path))
					}
				}
				if change.SameValue {
					text = i18n.Tf("vault.compare.same_value", text)
				}
				ui.Text(c, text)
				if change.Local && change.CanApply {
					label := i18n.T("vault.compare.use_local")
					if e.localChoices[change.Path] {
						label = i18n.T("vault.compare.local_selected")
					}
					if kit.Action(c, label, "", false, a.pending != 0).Clicked() {
						e.localChoices[change.Path] = !e.localChoices[change.Path]
					}
				} else if change.Local {
					a.cipherRowPreviewView(c, e, change.Path)
					ui.Text(c, i18n.T("vault.compare.row_matching_hint"))
					for _, label := range change.RemoteRows {
						ui.Text(c, i18n.Tf("vault.compare.remote_row", label)).FontSize(12)
					}
					for i, label := range change.LocalRows {
						ui.Text(c, i18n.Tf("vault.compare.local_row", label)).FontSize(12)
						choices := e.rowChoices[change.Path]
						if i >= len(choices) {
							continue
						}
						label := i18n.T("vault.compare.keep_remote_row")
						if choices[i] == -1 {
							label = i18n.T("vault.compare.add_row")
						} else if choices[i] >= 0 {
							label = i18n.Tf("vault.compare.match_remote_row", choices[i]+1)
						}
						if kit.Action(c, label, "", false, a.pending != 0).Clicked() {
							choices[i]++
							if choices[i] >= len(change.RemoteRows) {
								choices[i] = -2
							}
						}
					}
				}
			}
			ui.Text(c, i18n.T("vault.compare.version_conflict_hint"))
			if kit.Action(c, i18n.T("vault.compare.use_remote"), "", false, a.pending != 0).Clicked() {
				a.applyCipherComparison(false)
			}
			if kit.Action(c, i18n.T("vault.compare.reapply_selections"), "", true, a.pending != 0).Clicked() {
				a.applyCipherComparison(true)
			}
			if kit.Action(c, i18n.T("vault.compare.back_keep_draft"), "", false, a.pending != 0).Clicked() {
				clearCipherRowReveal(e)
				e.comparison = nil
				e.changes = nil
				e.localChoices = nil
				a.secretInputVersion++
			}
		})
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
		a.status = i18n.Tf("vault.compare.err_expired", err.Error())
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
