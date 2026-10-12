// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Called only from a synchronous UI event: lock/account-switch UI events cannot
// interleave with the native write. No worker or late network callback copies.
func (a *app) copyPersonalSecret(kind string, storage func(localstore.Request) localstore.Reply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if e == nil || e.uncertain || e.revision != a.sessionRevision {
		return
	}
	a.copyItemSecret(e.fields.ID, e.fields.OrganizationID != nil, kind, e.authorization, storage)
}

// copyDetailSecret copies the password or current code of the item the
// details show. Items that need the master password again copy from their
// editor, which holds the authorization.
func (a *app) copyDetailSecret(item localstore.DisplayCredential, kind string, storage func(localstore.Request) localstore.Reply) {
	a.prepareRuntimeSecret()
	if item.RequiresPassword || item.OrganizationID != "" {
		return
	}
	a.copyItemSecret(item.ID, false, kind, nil, storage)
}

// copyItemSecret writes a secret of the item to the clipboard through the
// protected native path, which clears it after its deadline. Callers revoke
// earlier runtime secrets first (prepareRuntimeSecret).
func (a *app) copyItemSecret(id string, organization bool, kind string, grant *vaultwarden.ItemAuthorization, storage func(localstore.Request) localstore.Reply) {
	if a.readsBlocked() || id == "" || !a.sessionOwnsSnapshot() {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	useSecret := s.WithPersonalSecret
	if organization {
		useSecret = s.WithOrganizationSecret
	}
	err := useSecret(a.vault, a.sessionRevision, id, kind, grant, func(secret string, key []byte, deadline time.Time) error {
		reply := storage(localstore.Request{Operation: localstore.OperationCopySecret, SecretProtocol: 1, Secret: secret, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.Failure()
		}
		a.secretClipboardOwned = true
		return nil
	})
	if err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	a.status = ""
}

func (a *app) showPersonalSecret(kind string, storage func(localstore.Request) localstore.Reply) {
	a.prepareRuntimeSecret()
	e := a.editor
	if a.readsBlocked() || e == nil || e.fields.ID == "" || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	useSecret := s.WithPersonalSecret
	if e.fields.OrganizationID != nil {
		useSecret = s.WithOrganizationSecret
	}
	err := useSecret(a.vault, a.sessionRevision, e.fields.ID, kind, e.authorization, func(secret string, key []byte, deadline time.Time) error {
		reply := storage(localstore.Request{Operation: localstore.OperationAuthorizeSecretDisplay, SecretProtocol: 1, SecretNotAfter: deadline.UnixMilli(), Scope: a.liveScope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
		if !reply.OK {
			return reply.Failure()
		}
		if !time.Now().Before(deadline) {
			return vaultwarden.ErrExpired
		}
		e.shownSecret, e.shownSecretExpires = secret, deadline
		return nil
	})
	if err != nil {
		e.shownSecret = ""
		a.status = vaultwarden.ErrorMessage(err)
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
	_ = localstore.Call(localstore.Request{Operation: localstore.OperationClearSecretClipboard})
}
