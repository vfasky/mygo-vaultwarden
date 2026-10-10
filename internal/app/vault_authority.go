// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) storageCall(request localstore.Request) localstore.Reply {
	if a.storageBackend != nil {
		return a.storageBackend(request)
	}
	return localstore.Call(request)
}

func mergeRuntimeProtection(vault, protection *vaultwarden.VaultData) error {
	if vault == nil {
		return vaultwarden.ErrIdentity
	}
	if protection == nil {
		return nil
	}
	if vault.Scope != protection.Scope {
		return vaultwarden.ErrIdentity
	}
	for _, record := range protection.PendingPolicyMutations {
		if !vault.HasPendingPolicy(record) {
			vault.PendingPolicyMutations = append(vault.PendingPolicyMutations, record)
		}
	}
	for _, id := range protection.QuarantinedOrganizations {
		found := false
		for _, old := range vault.QuarantinedOrganizations {
			if old == id {
				found = true
			}
		}
		if !found {
			vault.QuarantinedOrganizations = append(vault.QuarantinedOrganizations, id)
		}
	}
	if len(vault.PendingPolicyMutations) > 0 {
		vault.Version = 2
	}
	return nil
}

// vaultStorage captures a backend and operation generation on the UI thread.
// Persistent and runtime revisions never travel to the other backend.
func (a *app) vaultStorage() func(localstore.Request) localstore.Reply {
	return a.routeStorage(a.storageCall, a.epoch)
}
func (a *app) routeStorage(fallback func(localstore.Request) localstore.Reply, epoch uint64) func(localstore.Request) localstore.Reply {
	if a.runtimeVault == nil {
		return fallback
	}
	runtime := a.runtimeVault
	return func(request localstore.Request) localstore.Reply { return runtime.call(epoch, request) }
}

type runtimeSecretBackend interface {
	Use(scope vaultwarden.Scope, generation uint64, deadline time.Time, secret string, copy bool) error
	Revoke()
}

// runtimeVault keeps an independent capability and a read-only authenticated
// protection source. No request is forwarded as a disk write or session save.
type runtimeVault struct {
	mu         sync.Mutex
	active     bool
	clock      *atomic.Uint64
	session    *vaultwarden.Session
	authority  *vaultwarden.RuntimeAuthority
	vault      *vaultwarden.VaultData
	source     localstore.SnapshotStatus
	protection *vaultwarden.VaultData
	native     runtimeSecretBackend
	// sourceCheck also queries persistent cross-account target blockers; a
	// mismatched/unreadable source or unknown record is never an empty policy.
	sourceCheck func(localstore.SnapshotStatus, vaultwarden.Scope) error
}

func (r *runtimeVault) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.active = false
	cap := r.authority
	native := r.native
	r.mu.Unlock()
	cap.Close()
	if native != nil {
		native.Revoke()
	}
}
func (r *runtimeVault) revokeSecrets() {
	if r == nil {
		return
	}
	r.mu.Lock()
	native := r.native
	r.mu.Unlock()
	if native != nil {
		native.Revoke()
	}
}
func runtimeFailure(err error) localstore.Reply {
	return localstore.Reply{Code: "runtime_revoked", Message: vaultwarden.ErrorMessage(err)}
}
func runtimeSnapshot(cap *vaultwarden.RuntimeAuthority) *localstore.SnapshotStatus {
	scope := cap.Scope()
	return &localstore.SnapshotStatus{Available: true, Scope: &scope, Revision: cap.Revision(), SnapshotID: cap.Revision()}
}
func (r *runtimeVault) call(epoch uint64, request localstore.Request) localstore.Reply {
	r.mu.Lock()
	active, cap, source, native := r.active, r.authority, r.source, r.native
	r.mu.Unlock()
	if !active || cap == nil || r.clock.Load() != epoch {
		return runtimeFailure(vaultwarden.ErrCancelled)
	}
	scope := cap.Scope()
	if request.Scope != nil && *request.Scope != scope {
		return runtimeFailure(vaultwarden.ErrIdentity)
	}
	if request.ExpectedRevision != "" && request.ExpectedRevision != cap.Revision() {
		return runtimeFailure(vaultwarden.ErrIdentity)
	}
	if r.sourceCheck == nil {
		return runtimeFailure(vaultwarden.ErrIdentity)
	}
	if err := r.sourceCheck(source, scope); err != nil {
		return runtimeFailure(err)
	}
	if r.clock.Load() != epoch {
		return runtimeFailure(vaultwarden.ErrCancelled)
	}
	if request.Operation == localstore.OperationPublishVault {
		if request.Scope == nil || request.Vault == nil {
			return runtimeFailure(vaultwarden.ErrIdentity)
		}
		// Sync revoked the old capability, so acceptance checks the Session's new
		// private Sync digest rather than pretending the old lease is still live.
		next, vault, err := r.session.AcceptRuntimeSnapshotWithProtection(request.Vault, r.protection)
		if err != nil {
			return runtimeFailure(err)
		}
		r.mu.Lock()
		if !r.active || r.clock.Load() != epoch || r.authority != cap {
			r.mu.Unlock()
			next.Close()
			return runtimeFailure(vaultwarden.ErrCancelled)
		}
		r.authority, r.vault = next, vault
		r.mu.Unlock()
		cap.Close()
		if native != nil {
			native.Revoke()
		}
		return localstore.Reply{OK: true, State: runtimeSnapshot(next), Vault: vault}
	}
	if err := cap.CheckLease(); err != nil {
		return runtimeFailure(err)
	}
	switch request.Operation {
	case localstore.OperationStatus:
		return localstore.Reply{OK: true, State: runtimeSnapshot(cap)}
	case localstore.OperationClearSecretClipboard:
		if native != nil {
			native.Revoke()
		}
		return localstore.Reply{OK: true, State: runtimeSnapshot(cap)}
	case localstore.OperationCopySecret, localstore.OperationAuthorizeSecretDisplay:
		if request.Scope == nil || request.ExpectedRevision != cap.Revision() || request.SecretProtocol != 1 || native == nil {
			return runtimeFailure(vaultwarden.ErrPermission)
		}
		deadline := time.UnixMilli(request.SecretNotAfter)
		if deadline.After(cap.Expires()) {
			deadline = cap.Expires()
		}
		if !time.Now().Before(deadline) || deadline.After(time.Now().Add(30*time.Second)) {
			return runtimeFailure(vaultwarden.ErrExpired)
		}
		if err := native.Use(scope, epoch, deadline, request.Secret, request.Operation == localstore.OperationCopySecret); err != nil {
			return runtimeFailure(err)
		}
		if r.clock.Load() != epoch || cap.CheckLease() != nil {
			native.Revoke()
			return runtimeFailure(vaultwarden.ErrCancelled)
		}
		return localstore.Reply{OK: true, State: runtimeSnapshot(cap)}
	default:
		return localstore.Reply{Code: "runtime_requires_password", Message: i18n.T("app.sync.err_persistent_recovery_required")}
	}
}
