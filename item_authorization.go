// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) itemAuthorizationView(c *ui.Context) {
	e := a.editor
	ui.Column(c).Gap(12).Padding(18).Children(func() {
		ui.Text(c, "再次验证主密码").FontSize(23).FontWeight(600)
		ui.Text(c, "仅授权此项目 30 秒，到期会关闭表单并清除未保存的内容。不会取消项目的主密码验证要求。").FontSize(13)
		ui.TextInput(c, &e.repromptPassword).Label("主密码").Password().Disabled(a.pending != 0)
		ui.Row(c).Gap(8).Children(func() {
			if action(c, "验证并打开", "", true, a.pending != 0 || e.repromptPassword == "").Clicked() {
				a.authorizePersonalItem()
			}
			if action(c, "取消", "", false, a.pending != 0).Clicked() {
				*e = cipherEditor{}
				a.editor = nil
				a.secretInputVersion++
			}
		})
	})
}
func (a *app) authorizePersonalItem() {
	e := a.editor
	if e == nil || e.repromptID == "" || a.pending != 0 || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
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
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	a.cancel = cancel
	a.pending++
	go func() {
		defer clear(password)
		grant, err := session.AuthorizePersonalItem(ctx, vault, revision, id, password)
		a.window.Update(func() {
			defer cancel()
			a.pending--
			if a.epoch != epoch {
				return
			}
			a.cancel = nil
			if err != nil {
				a.status = err.Error()
				return
			}
			if !a.sessionOwnsSnapshot() || a.sessionRevision != revision || a.editor != e || ctx.Err() != nil {
				return
			}
			a.openCipherEditorAuthorized(id, 0, grant)
		})
	}()
}
