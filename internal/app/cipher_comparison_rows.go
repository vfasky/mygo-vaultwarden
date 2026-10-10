// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

type cipherRowReveal struct {
	path, revision string
	local, remote  []vaultwarden.CipherRowPreview
	expires        time.Time
}

func clearCipherRowReveal(e *cipherEditor) {
	if e.rowPreview != nil {
		clear(e.rowPreview.local)
		clear(e.rowPreview.remote)
		e.rowPreview = nil
	}
}
func (a *app) revealCipherRows(path string, storage func(localstore.Request) localstore.Reply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if e == nil || e.comparison == nil || a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	clearCipherRowReveal(e)
	err := session.WithCipherComparisonRows(a.vault, a.sessionRevision, e.comparison, path, func(local, remote []vaultwarden.CipherRowPreview, key []byte, deadline time.Time) error {
		reply := storage(localstore.Request{Operation: "authorizeSecretDisplay", SecretProtocol: 1, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.Failure()
		}
		if !time.Now().Before(deadline) {
			return vaultwarden.ErrExpired
		}
		e.rowPreview = &cipherRowReveal{path: path, revision: a.sessionRevision, local: append([]vaultwarden.CipherRowPreview(nil), local...), remote: append([]vaultwarden.CipherRowPreview(nil), remote...), expires: deadline}
		return nil
	})
	if err != nil {
		a.status = err.Error()
	}
}
func (a *app) cipherRowPreviewView(c *ui.Context, e *cipherEditor, path string) {
	shown := e.rowPreview != nil && e.rowPreview.path == path
	label := i18n.T("vault.compare.reveal_rows")
	if shown {
		label = i18n.T("vault.compare.hide_rows")
	}
	if kit.Action(c, label, "key", false, a.pending != 0).Clicked() {
		if shown {
			clearCipherRowReveal(e)
		} else {
			a.revealCipherRows(path, a.vaultStorage())
		}
	}
	if e.rowPreview == nil || e.rowPreview.path != path {
		return
	}
	for _, side := range []struct {
		name string
		rows []vaultwarden.CipherRowPreview
	}{{i18n.T("vault.compare.local"), e.rowPreview.local}, {i18n.T("vault.compare.remote"), e.rowPreview.remote}} {
		for _, row := range side.rows {
			ui.Text(c, i18n.Tf("vault.compare.row_details", side.name, row.Index+1, row.Name, row.Metadata)).FontSize(12).MaxLines(3)
			ui.Text(c, row.Value).FontSize(12).MaxLines(3)
			if row.HasUnknown {
				ui.Text(c, i18n.T("vault.compare.row_extensions_hint")).FontSize(11).MaxLines(2)
			}
		}
	}
}
