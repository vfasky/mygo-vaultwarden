// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

func (a *app) showCipherHistory(storage func(localstore.Request) localstore.Reply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if e == nil || a.pending != 0 || e.fields.ID == "" || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := session.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	err := session.WithCipherPasswordHistory(a.vault, a.sessionRevision, e.fields.ID, e.authorization, func(history []vaultwarden.PasswordHistoryValue, key []byte, deadline time.Time) error {
		reply := storage(localstore.Request{Operation: localstore.OperationAuthorizeSecretDisplay, SecretProtocol: 1, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.Failure()
		}
		if !time.Now().Before(deadline) {
			return vaultwarden.ErrExpired
		}
		e.shownHistory = append([]vaultwarden.PasswordHistoryValue(nil), history...)
		e.historyExpires = deadline
		e.showHistory = true
		return nil
	})
	if err != nil {
		e.showHistory = false
		clear(e.shownHistory)
		e.shownHistory = nil
		a.status = vaultwarden.ErrorMessage(err)
	}
}
