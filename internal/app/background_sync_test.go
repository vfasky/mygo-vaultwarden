// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

const backgroundLoginID = "10000000-0000-4000-8000-000000000101"

// backgroundSyncFixture has a personal login adopted, and holds the next
// /api/sync download until release.
type backgroundSyncFixture struct {
	*resourceControllerFixture
	arrived, gate chan struct{}
}

func newBackgroundSyncFixture(t *testing.T) *backgroundSyncFixture {
	t.Helper()
	f := &backgroundSyncFixture{resourceControllerFixture: newResourceControllerFixture(t, true), arrived: make(chan struct{}, 1), gate: make(chan struct{})}
	doc, err := vaultwarden.NewPersonalCipher(vaultwarden.CipherFields{Type: 1, Name: "Background login", Login: map[string]any{"username": "user", "password": "background-secret"}}, bytes.Repeat([]byte{4}, 64), f.a.liveScope.Account)
	if err != nil {
		t.Fatal(err)
	}
	var login map[string]any
	if err = json.Unmarshal(doc.JSON, &login); err != nil {
		t.Fatal(err)
	}
	login["id"], login["revisionDate"], login["edit"], login["viewPassword"] = backgroundLoginID, "2026-01-01T00:00:00Z", true, true
	f.body["ciphers"] = append(f.body["ciphers"].([]any), login)
	f.refresh()
	f.drain()
	if f.login().ID == "" {
		t.Fatal("login not adopted")
	}
	held := false
	f.additional = func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/sync" && !held {
			held = true
			f.arrived <- struct{}{}
			<-f.gate
		}
		return false
	}
	t.Cleanup(f.release)
	return f
}

func (f *backgroundSyncFixture) login() localstore.DisplayCredential {
	for _, item := range f.a.items {
		if item.ID == backgroundLoginID {
			return item
		}
	}
	return localstore.DisplayCredential{}
}

func (f *backgroundSyncFixture) release() {
	select {
	case <-f.gate:
	default:
		close(f.gate)
	}
}

// step runs the next UI callback a worker dispatched.
func (f *backgroundSyncFixture) step() {
	f.t.Helper()
	select {
	case fn := <-f.q:
		fn()
	case <-time.After(10 * time.Second):
		f.t.Fatal("controller callback timeout")
	}
}

// startDownload starts a background sync and runs the callback that opens its
// read window once the download reached the server.
func (f *backgroundSyncFixture) startDownload() {
	f.t.Helper()
	f.refresh()
	select {
	case <-f.arrived:
	case <-time.After(10 * time.Second):
		f.t.Fatal("download did not start")
	}
	f.step()
}

// onUIWithin fails instead of hanging when a UI action waits for the sync.
func onUIWithin(t *testing.T, action func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { action(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UI action waited for the sync download")
	}
}

func TestBackgroundSyncKeepsCopyOpenDuringDownload(t *testing.T) {
	f := newBackgroundSyncFixture(t)
	f.startDownload()
	if f.a.pending != 1 || f.a.readsBlocked() {
		t.Fatalf("reads closed during download: pending=%d", f.a.pending)
	}
	var copied string
	onUIWithin(t, func() {
		f.a.copyDetailSecret(f.login(), "password", func(r localstore.Request) localstore.Reply {
			if r.Operation == localstore.OperationCopySecret && r.ExpectedRevision == f.a.sessionRevision {
				copied = r.Secret
				return localstore.Reply{OK: true}
			}
			return localstore.Reply{Code: "unexpected"}
		})
	})
	if copied != "background-secret" || !f.a.secretClipboardOwned {
		t.Fatalf("copy during download failed: %q", f.a.status)
	}
	// Adopting the new revision clears an owned clipboard through the native
	// bridge, which this headless test must not call.
	f.a.secretClipboardOwned = false
	// Anything that may lead to a mutation still waits for the sync.
	f.a.openCipherEditor(backgroundLoginID, 1)
	if f.a.editor != nil {
		t.Fatal("editor opened during sync")
	}
	f.release()
	f.step() // the download returned: reads close before the response is applied
	if !f.a.readsBlocked() {
		t.Fatal("reads stayed open while the sync commits")
	}
	f.drain()
	if f.a.readsBlocked() || f.a.syncReads || f.login().ID == "" || f.a.itemsRevision != f.a.sessionRevision {
		t.Fatal("sync result not adopted")
	}
}

func TestLockDuringBackgroundDownloadCancelsWithoutLogout(t *testing.T) {
	f := newBackgroundSyncFixture(t)
	f.startDownload()
	f.a.stopNetwork()
	f.release()
	// f.storage reports any logout or publication as an unexpected request.
	f.drain()
	if f.a.pending != 0 || f.a.session != nil || f.a.syncReads {
		t.Fatal("locked sync left state behind")
	}
	if !f.state.Available {
		t.Fatal("snapshot was logged out")
	}
}

func TestReadsBlockedOnlyOutsideOwnDownloadWindow(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pending        int
		reads          bool
		syncEpoch, now uint64
		blocked        bool
	}{
		{"idle", 0, false, 0, 3, false},
		{"downloading", 1, true, 3, 3, false},
		{"preparing or committing", 1, false, 3, 3, true},
		{"detached by a newer epoch", 1, true, 3, 4, true},
		{"another operation in flight", 2, true, 3, 3, true},
	} {
		a := &app{pending: tc.pending, syncReads: tc.reads, syncEpoch: tc.syncEpoch, epoch: tc.now}
		if a.readsBlocked() != tc.blocked {
			t.Fatal(tc.name)
		}
	}
}
