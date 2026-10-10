// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) itemAuthorizationView(c *ui.Context) {
	e := a.editor
	ui.Column(c).Gap(12).Padding(18).Children(func() {
		ui.Text(c, i18n.T("app.reprompt.title")).FontSize(23).FontWeight(600)
		ui.Text(c, i18n.T("app.reprompt.hint")).FontSize(13)
		ui.TextInput(c, &e.repromptPassword).Label(i18n.T("login.master_password")).Password().Disabled(a.pending != 0)
		ui.Row(c).Gap(8).Children(func() {
			if kit.Action(c, i18n.T("app.reprompt.verify_open"), "", true, a.pending != 0 || e.repromptPassword == "").Clicked() {
				a.authorizePersonalItem()
			}
			if kit.Action(c, i18n.T("common.cancel"), "", false, a.pending != 0).Clicked() {
				*e = cipherEditor{}
				a.editor = nil
				a.secretInputVersion++
			}
		})
	})
}
func (a *app) authorizePersonalItem() {
	e := a.editor
	if e == nil || e.repromptID == "" || a.pending != 0 || !a.sessionOwnsSnapshot() || (!e.compareAuthorization && e.revision != a.sessionRevision) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	password := []byte(e.repromptPassword)
	e.repromptPassword = ""
	a.secretInputVersion++
	vault, revision, id := a.vault, e.revision, e.repromptID
	if e.compareAuthorization {
		revision = a.sessionRevision
	}
	organization := a.organizationItem(id)
	a.advanceEpoch()
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	a.cancel = cancel
	a.pending++
	go func() {
		defer clear(password)
		var grant *vaultwarden.ItemAuthorization
		var err error
		if organization {
			grant, err = session.AuthorizeOrganizationItem(ctx, vault, revision, id, password)
		} else {
			grant, err = session.AuthorizePersonalItem(ctx, vault, revision, id, password)
		}
		a.dispatchUI(func() {
			defer cancel()
			a.pending--
			if a.epoch != epoch {
				*e = cipherEditor{}
				return
			}
			a.cancel = nil
			if err != nil {
				a.status = err.Error()
				return
			}
			if a.editor != e {
				*e = cipherEditor{}
				return
			}
			if !a.sessionOwnsSnapshot() || a.sessionRevision != revision || ctx.Err() != nil {
				return
			}
			if e.compareAuthorization {
				a.compareCipher(grant)
			} else {
				a.openCipherEditorAuthorized(id, 0, grant)
			}
		})
	}()
}
