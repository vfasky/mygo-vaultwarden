// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

func (a *app) showCipherHistory(storage func(storageRequest) storageReply) {
	e := a.editor
	if e == nil || a.pending != 0 || e.fields.ID == "" || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := session.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = err.Error()
		return
	}
	err := session.WithCipherPasswordHistory(a.vault, a.sessionRevision, e.fields.ID, e.authorization, func(history []vaultwarden.PasswordHistoryValue, key []byte, deadline time.Time) error {
		reply := storage(storageRequest{Operation: "authorizeSecretDisplay", SecretProtocol: 1, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.failure()
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
		a.status = err.Error()
	}
}
