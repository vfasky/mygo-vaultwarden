// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"sync/atomic"
	"time"
)

type personalBackupImporter interface {
	ImportPersonalBackup(context.Context, vaultwarden.Scope, *vaultwarden.ImportPlan, func(vaultwarden.SessionCheckpoint) error) (vaultwarden.ImportResult, error)
}
type backupImportOutcome struct {
	result     vaultwarden.ImportResult
	reply      localstore.Reply
	checkpoint *localstore.SnapshotStatus
	err        error
}

// Host callbacks execute on the dispatcher. Settled always balances the host's
// busy accounting; Apply is only called for the still-current, unclosed form.
type backupImportHost interface {
	Current() bool
	Settled()
	Apply(backupImportOutcome)
}

// Owns a single non-replayable import, including plan lifetime, cancellation,
// checkpoint progression and late-result filtering. No app or Session fields.
type backupImportController struct {
	importer personalBackupImporter
	host     backupImportHost
	storage  func(localstore.Request) localstore.Reply
	dispatch func(func())
	scope    vaultwarden.Scope
	prior    *localstore.SnapshotStatus
	plan     *vaultwarden.ImportPlan
	ctx      context.Context
	cancel   context.CancelFunc
	started  atomic.Bool
	closed   atomic.Bool
}

func newBackupImportController(
	importer personalBackupImporter, host backupImportHost,
	storage func(localstore.Request) localstore.Reply, dispatch func(func()),
	scope vaultwarden.Scope, prior *localstore.SnapshotStatus, plan *vaultwarden.ImportPlan,
) *backupImportController {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	return &backupImportController{importer: importer, host: host, storage: storage, dispatch: dispatch, scope: scope, prior: prior, plan: plan, ctx: ctx, cancel: cancel}
}
func (c *backupImportController) Close() { c.closed.Store(true); c.cancel() }
func (c *backupImportController) Start() bool {
	if !c.started.CompareAndSwap(false, true) {
		return false
	}
	go c.run()
	return true
}
func (c *backupImportController) run() {
	defer c.plan.Clear()
	prior := c.prior
	out := backupImportOutcome{}
	persist := func(cp vaultwarden.SessionCheckpoint) error {
		var err error
		out.reply, err = localstore.SaveSessionCheckpoint(prior, cp, c.storage)
		if err == nil {
			prior = out.reply.State
			out.checkpoint = out.reply.State
		}
		return err
	}
	state := c.storage(localstore.Request{Operation: localstore.OperationStatus})
	if !state.OK || !backupLease(state.State, c.scope, prior.Revision) || c.ctx.Err() != nil {
		out.err = vaultwarden.ErrConflict
	} else {
		out.result, out.err = c.importer.ImportPersonalBackup(c.ctx, c.scope, c.plan, persist)
	}
	c.dispatch(func() {
		defer c.cancel()
		c.host.Settled()
		if c.closed.Load() || !c.host.Current() {
			return
		}
		c.host.Apply(out)
	})
}

type appBackupImportHost struct {
	app     *app
	editor  *backupEditor
	epoch   uint64
	refresh func()
}

func (h appBackupImportHost) Current() bool {
	return h.app.epoch == h.epoch && h.app.backupEditor == h.editor
}
func (h appBackupImportHost) Settled() { h.app.pending-- }
func (h appBackupImportHost) Apply(out backupImportOutcome) {
	a, e := h.app, h.editor
	a.cancel = nil
	if out.checkpoint != nil && !a.adoptBackupCheckpoint(e, out.checkpoint) {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
		return
	}
	e.results = out.result.Entries
	if e.resources != nil {
		for _, entry := range out.result.Entries {
			if entry.SourceID != "" && entry.ID != "" {
				e.resources.targets[entry.SourceID] = entry.ID
			}
		}
	}
	if out.err != nil {
		e.results = append(e.results, vaultwarden.ImportEntry{Kind: i18n.T("backup.import.status_stopped"), State: vaultwarden.ErrorMessage(out.err)})
		a.syncFailed(out.reply, out.err)
	}
	if a.backupEditor == e && a.sessionOwnsSnapshot() {
		a.status = i18n.T("backup.import.status_syncing")
		h.refresh()
	}
}
