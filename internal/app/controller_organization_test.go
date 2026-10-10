// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"testing"
)

func orgControllerFixture(t *testing.T) *resourceControllerFixture {
	t.Helper()
	f := newResourceControllerFixture(t, true)
	source := organizationUIFixture(t, true, true, 0)
	defer source.stopNetwork()
	f.mu.Lock()
	if err := json.Unmarshal(source.vault.Sync, &f.body); err != nil {
		t.Fatal(err)
	}
	f.mu.Unlock()
	f.a.uiDispatcher, f.a.storageBackend = f.dispatch, f.storage
	f.refresh()
	f.drain()
	f.a.openOrgServices()
	if f.a.orgServices == nil || len(f.a.orgServices.entries) == 0 {
		t.Fatalf("organization controller unavailable: %s", f.a.status)
	}
	return f
}
func TestOrgControllerRoutesRealComponentsAndCancelsStaleWorker(t *testing.T) {
	f := orgControllerFixture(t)
	c := f.a.orgServices
	c.selectedItem = "organization-item"
	for _, action := range []string{"state", "events", "cipher-events", "api-key", "directory", "collections", "copy", "export"} {
		c.selectAction(action)
		if c.panel == nil {
			t.Fatalf("%s has no connected component", action)
		}
	}
	c.selectAction("state")
	panel := c.panel.(*orgOperationsPanel)
	panel.selected["organization-item"] = true
	panel.confirmation = true
	f.mu.Lock()
	f.failLease = true
	f.mu.Unlock()
	panel.start()
	if f.a.pending != 1 {
		t.Fatal("worker not tracked")
	}
	f.a.advanceEpoch()
	f.drain()
	if f.a.orgServices != nil || !panel.closed || f.a.pending != 0 {
		t.Fatal("closed controller revived or worker accounting leaked")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 0 || f.uploads != 0 || f.trashes != 0 {
		t.Fatal("stale source dispatched a mutation")
	}
}
func TestOrgControllerResourceContinuationAdoptsOnlyNormalPublication(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "publication-failed"}[fail], func(t *testing.T) {
			f := orgControllerFixture(t)
			c := f.a.orgServices
			plan := orgResourceUIFixture(t)
			c.installResources(plan, map[string]string{}, "organization-1", false)
			panel := c.panel.(*orgResourceRestorePanel)
			priorEpoch, priorRevision := f.a.epoch, f.a.snapshot.Revision
			f.mu.Lock()
			f.failPublish = fail
			f.mu.Unlock()
			panel.run(func(ctx context.Context) (func(), error) {
				err := panel.callbacks.refresh(ctx)
				return func() {
					if err == nil {
						panel.needsRefresh = false
					}
				}, err
			})
			f.drain()
			if fail {
				if f.a.snapshot.Revision != priorRevision || !panel.needsRefresh {
					t.Fatal("failed publication adopted continuation")
				}
				return
			}
			if f.a.orgServices != c || c.panel != panel || panel.closed || panel.needsRefresh || f.a.epoch <= priorEpoch || f.a.snapshot.Revision == priorRevision {
				t.Fatalf("continuation was lost or not authenticated: %s", f.a.status)
			}
			env, err := c.environment()
			if err != nil || env.epoch != f.a.epoch || env.leaseRevision() != f.a.sessionRevision {
				t.Fatal("controller retained stale authority")
			}
			if err := env.session.ValidateAuthenticatedSnapshot(env.vault, env.leaseRevision()); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.creates != 0 || f.uploads != 0 || f.trashes != 0 {
				t.Fatal("sync replayed a mutation")
			}
		})
	}
}
