// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Called only from a synchronous UI event: lock/account-switch UI events cannot
// interleave with the native write. No worker or late network callback copies.
func (a *app) copyPersonalSecret(kind string, storage func(storageRequest) storageReply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if a.pending != 0 || e == nil || e.fields.ID == "" || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = err.Error()
		return
	}
	useSecret := s.WithPersonalSecret
	if e.fields.OrganizationID != nil {
		useSecret = s.WithOrganizationSecret
	}
	err := useSecret(a.vault, a.sessionRevision, e.fields.ID, kind, e.authorization, func(secret string, key []byte, deadline time.Time) error {
		reply := storage(storageRequest{Operation: "copySecret", SecretProtocol: 1, Secret: secret, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.failure()
		}
		a.secretClipboardOwned = true
		return nil
	})
	if err != nil {
		a.status = err.Error()
		return
	}
	a.status = "已复制已保存的内容；最多 30 秒后尽力清除。"
}

func (a *app) showPersonalSecret(kind string, storage func(storageRequest) storageReply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if a.pending != 0 || e == nil || e.fields.ID == "" || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = err.Error()
		return
	}
	useSecret := s.WithPersonalSecret
	if e.fields.OrganizationID != nil {
		useSecret = s.WithOrganizationSecret
	}
	err := useSecret(a.vault, a.sessionRevision, e.fields.ID, kind, e.authorization, func(secret string, key []byte, deadline time.Time) error {
		reply := storage(storageRequest{Operation: "authorizeSecretDisplay", SecretProtocol: 1, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.failure()
		}
		if !time.Now().Before(deadline) {
			return vaultwarden.ErrExpired
		}
		e.shownSecret, e.shownSecretExpires = secret, deadline
		return nil
	})
	if err != nil {
		e.shownSecret = ""
		a.status = err.Error()
	}
}

func (a *app) clearSecretClipboard() {
	if !a.secretClipboardOwned {
		return
	}
	a.secretClipboardOwned = false
	if a.runtimeVault != nil {
		a.runtimeVault.revokeSecrets()
		return
	}
	_ = callStorage(storageRequest{Operation: "clearSecretClipboard"})
}
