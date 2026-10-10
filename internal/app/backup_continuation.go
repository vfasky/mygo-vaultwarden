// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// A continuation belongs to one existing resource form and one sync attempt.
// Capture is not authorization: network.go checks current before accepting the
// authenticated publication, and calls resume only after adopting its receipt.
type backupContinuation struct {
	editor               *backupEditor
	resources            *backupResourceEditor
	plan                 *vaultwarden.ResourceImportPlan
	session              *vaultwarden.Session
	scope                vaultwarden.Scope
	revision, snapshotID string
	epoch                uint64
}

func (a *app) adoptBackupCheckpoint(e *backupEditor, state *localstore.SnapshotStatus) bool {
	current := e != nil && a.backupEditor == e && e.resources != nil && e.submitted && a.backupCurrent(e, a.epoch)
	if !a.adoptSessionCheckpoint(state) {
		return false
	}
	if current {
		e.revision = a.sessionRevision
		e.resources.password = ""
		e.exportGrants = nil
	}
	return true
}

func (a *app) captureBackupContinuation(epoch uint64) *backupContinuation {
	e := a.backupEditor
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || e == nil || e.resources == nil || e.resources.plan == nil || !e.submitted || !a.backupCurrent(e, epoch) {
		return nil
	}
	return &backupContinuation{editor: e, resources: e.resources, plan: e.resources.plan, session: session, scope: *a.liveScope, revision: e.revision, snapshotID: a.snapshot.SnapshotID, epoch: epoch}
}

func (c *backupContinuation) sameForm(a *app) bool {
	return c != nil && a.epoch == c.epoch && a.backupEditor == c.editor && c.editor.resources == c.resources && c.resources.plan == c.plan && len(c.plan.Resources()) != 0 && c.editor.submitted && c.editor.revision == c.revision && a.session == c.session && a.sessionOwnsSnapshot() && *a.liveScope == c.scope
}

func (c *backupContinuation) current(a *app) bool {
	// A saved token checkpoint may change the revision during this attempt, but
	// must keep the same snapshot identity. The existing checkpoint adopter has
	// already checked its authenticated storage receipt.
	return c.sameForm(a) && a.snapshot.SnapshotID == c.snapshotID
}

func (c *backupContinuation) resume(a *app) {
	if !c.sameForm(a) || a.snapshot.SnapshotID == "" || a.snapshot.SnapshotID == c.snapshotID || a.sessionRevision == c.revision || a.itemsRevision != a.sessionRevision || a.vault == nil || a.vault.Scope != c.scope {
		return
	}
	c.editor.revision = a.sessionRevision
	// Do not carry password input or item grants across an authenticated snapshot.
	// Each explicit file action checks current ownership/permissions and obtains
	// a fresh reprompt grant in runResourceRestore. No file state is upgraded here.
	c.resources.password = ""
	c.editor.exportPassword = ""
	c.editor.exportGrants = nil
	c.editor.exportIDs = nil
	c.editor.confirm = false
	for i := range c.resources.rows {
		row := &c.resources.rows[i]
		if row.target == "" {
			row.target = c.resources.targets[row.resource.CipherID]
		}
	}
}
