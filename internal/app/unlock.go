// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) unlockWithPassword() {
	if a.pending != 0 || a.snapshot == nil || !a.snapshot.Available || a.snapshot.Scope == nil {
		return
	}
	if a.snapshot.PasswordUnlock == nil {
		a.status = i18n.T("login.unlock.login_or_touch_id_hint")
		return
	}
	if a.masterPassword == "" {
		a.status = i18n.T("login.err_password_required")
		return
	}
	if len(a.masterPassword) > 8192 {
		a.clearLoginInputs()
		a.status = i18n.T("login.err_password_too_long")
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
