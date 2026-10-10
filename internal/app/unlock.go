// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) unlockWithPassword() {
	if a.pending != 0 || a.snapshot == nil || !a.snapshot.Available || a.snapshot.Scope == nil {
		return
	}
	if a.snapshot.PasswordUnlock == nil {
		a.status = "请重新登录一次，以启用主密码解锁；也可以使用 Touch ID 解锁。"
		return
	}
	if a.masterPassword == "" {
		a.status = "请输入主密码。"
		return
	}
	if len(a.masterPassword) > 8192 {
		a.clearLoginInputs()
		a.status = "主密码过长，请检查输入。"
		return
	}
	password := []byte(a.masterPassword)
	config, scope := *a.snapshot.PasswordUnlock, *a.snapshot.Scope
	request := localstore.Request{Operation: "listPassword", ExpectedRevision: a.snapshot.Revision, Scope: &scope}
	a.clearLoginInputs()
	a.startStorage(request, func() localstore.Reply {
		defer clear(password)
		key, err := vaultwarden.DeriveSnapshotUnlockKey(password, config)
		clear(password)
		if err != nil {
			return localstore.Reply{Code: "invalid_password_config", Message: err.Error()}
		}
		defer clear(key)
		request.UnlockKey = key
		return localstore.Call(request)
	})
}
