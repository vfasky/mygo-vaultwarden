// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func writableUIFixture(t *testing.T) *app {
	t.Helper()
	a := passwordLockedApp()
	key := bytes.Repeat([]byte{4}, 64)
	doc, err := vaultwarden.NewPersonalCipher(vaultwarden.CipherFields{Type: 3, Name: "Fixture card", Card: map[string]any{"number": "4242424242424242"}}, key, a.snapshot.Scope.Account)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if json.Unmarshal(doc.JSON, &object) != nil {
		t.Fatal("fixture")
	}
	object["id"], object["revisionDate"], object["edit"], object["viewPassword"] = "card-1", "2026-01-01T00:00:00Z", true, true
	raw, err := json.Marshal(map[string]any{"profile": map[string]any{"id": a.snapshot.Scope.Account}, "ciphers": []any{object}})
	if err != nil {
		t.Fatal(err)
	}
	a.pending, a.epoch = 1, 1
	a.completeStorage(storageRequest{Operation: "listPassword", ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}, 1, storageReply{OK: true, State: a.snapshot, Session: savedUIFixture(t, a), Vault: &vaultwarden.VaultData{Version: 1, Scope: *a.snapshot.Scope, Sync: raw}})
	if a.vault == nil || len(a.items) != 1 {
		t.Fatal("complete vault not restored")
	}
	return a
}
func TestNativeEditorUsesAuthenticatedVaultAndClearsOnLock(t *testing.T) {
	a := writableUIFixture(t)
	tt := ui.NewTester(a.view, 1280, 820)
	clickUI(t, tt, "支付卡")
	clickUI(t, tt, "查看与编辑")
	if a.editor == nil || !tt.HasText("编辑支付卡") {
		t.Fatal("editor unreachable")
	}
	if a.editor.inputs[2].value != "4242424242424242" {
		t.Fatal("authenticated decryption missing")
	}
	tt.Scroll(1100, 600, 0, 2000)
	clickUI(t, tt, "移入回收站")
	if a.editor.confirm != vaultwarden.CipherTrash || !tt.HasText("确认将项目移入回收站？") {
		t.Fatal("destructive action lacks confirmation")
	}
	clickUI(t, tt, "取消操作")
	if a.pending != 0 || a.editor.confirm != "" {
		t.Fatal("confirmation cancellation mutated vault")
	}
	a.lockInterface()
	tt.Frame()
	if a.editor != nil || a.vault != nil || len(a.items) != 0 || tt.HasText("Fixture card") {
		t.Fatal("lock retained vault/editor metadata")
	}
}
func TestStaleEditorAndLateMutationCannotReuseAuthority(t *testing.T) {
	a := writableUIFixture(t)
	a.openCipherEditor("card-1", 3)
	draft := a.editor
	draft.fields.Name = "unsaved local name"
	oldRevision := a.sessionRevision
	next := *a.snapshot
	next.Revision = "checkpoint"
	if !a.adoptSessionCheckpoint(&next) || draft.revision != "checkpoint" {
		t.Fatal("checkpoint lost unchanged draft lease")
	}
	// A full sync has a different snapshot identity and cannot renew this draft.
	a.sessionRevision, a.snapshot.Revision = "replacement", "replacement"
	a.saveCipher()
	if a.pending != 0 || a.editor != draft || draft.fields.Name != "unsaved local name" {
		t.Fatal("stale draft dispatched or lost")
	}
	a.sessionRevision, a.snapshot.Revision = oldRevision, oldRevision
	a.pending = 1
	epoch := a.epoch
	a.lockInterface()
	ctx, cancel := context.WithCancel(context.Background())
	a.completeCipherMutation(epoch, draft, &next, storageReply{OK: true, State: &next}, nil, cancel)
	if a.editor != nil || a.vault != nil || a.session != nil || a.itemsRevision != "" || draft.fields.Name != "" || ctx.Err() == nil {
		t.Fatal("late mutation revived locked data")
	}
}

func TestConflictAndUncertainMutationKeepLocalDraft(t *testing.T) {
	for _, err := range []error{vaultwarden.ErrConflict, &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork}} {
		a := writableUIFixture(t)
		a.openCipherEditor("card-1", 3)
		draft := a.editor
		draft.fields.Name = "unsaved local name"
		a.pending = 1
		_, cancel := context.WithCancel(context.Background())
		a.completeCipherMutation(a.epoch, draft, nil, storageReply{}, err, cancel)
		if a.editor != draft || draft.fields.Name != "unsaved local name" || a.pending != 0 {
			t.Fatal("error discarded draft")
		}
		if err != vaultwarden.ErrConflict && !draft.uncertain {
			t.Fatal("uncertain mutation allowed resubmit")
		}
		a.stopNetwork()
	}
}

func TestNativeEightTypeCreationAndArchiveCategories(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	for _, category := range []struct {
		id   string
		kind int
	}{{"login", 1}, {"note", 2}, {"card", 3}, {"identity", 4}, {"ssh", 5}, {"bank", 6}, {"license", 7}, {"passport", 8}} {
		a.category = category.id
		a.editor = nil
		tt := ui.NewTester(a.view, 1280, 820)
		clickUI(t, tt, "新增")
		if a.editor == nil || a.editor.fields.Type != category.kind {
			t.Fatalf("wrong create type %s", category.id)
		}
	}
	a.editor = nil
	a.items = []displayCredential{{ID: "active", Type: 1}, {ID: "archived", Type: 1, Archived: true}, {ID: "deleted", Type: 1, Deleted: true}, {ID: "favorite", Type: 1, Favorite: true}}
	for _, tc := range []struct {
		category string
		count    int
	}{{"all", 2}, {"login", 2}, {"archive", 1}, {"trash", 1}, {"favorites", 1}} {
		a.category = tc.category
		if len(a.filteredItems()) != tc.count {
			t.Fatal("category mismatch", tc.category)
		}
	}
	a.observeSnapshot(&snapshotStatus{Revision: "revoked", Available: true})
	if a.vault != nil || a.editor != nil {
		t.Fatal("revocation retained documents")
	}
}
