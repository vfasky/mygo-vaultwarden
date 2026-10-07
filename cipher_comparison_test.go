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

func TestCipherComparisonRepromptNeedsLatestGrant(t *testing.T) {
	a, s := repromptUIFixture(t)
	a.openCipherEditor("login-1", 1)
	grant, err := s.AuthorizePersonalItem(context.Background(), a.vault, a.sessionRevision, "login-1", []byte("fixture-master"))
	if err != nil {
		t.Fatal(err)
	}
	a.openCipherEditorAuthorized("login-1", 1, grant)
	e := a.editor
	e.fields.Name = "protected draft"
	publishComparisonFixture(t, a, func(o map[string]any) { o["futureExtension"] = "remote" })
	a.compareCipher(nil)
	if !e.compareAuthorization || e.repromptID != "login-1" || e.comparison != nil || e.authorization != nil || e.fields.Name != "protected draft" {
		t.Fatal("missing fresh auth form")
	}
	a.compareCipher(grant)
	if e.comparison != nil {
		t.Fatal("old grant accepted")
	}
	fresh, err := s.AuthorizePersonalItem(context.Background(), a.vault, a.sessionRevision, "login-1", []byte("fixture-master"))
	if err != nil {
		t.Fatal(err)
	}
	a.compareCipher(fresh)
	if e.comparison == nil || e.repromptID != "" || e.authorization != fresh || e.fields.Name != "protected draft" {
		t.Fatal("fresh auth lost draft", a.status)
	}
	e.localChoices["name"] = true
	a.applyCipherComparison(true)
	if e.fields.Name != "protected draft" || e.authorization != fresh || e.fields.Reprompt != 1 || e.revision != a.sessionRevision || a.pending != 0 {
		t.Fatal("new draft lost protected authority")
	}
	// A second server conflict keeps this new draft and disables repeat save.
	a.pending = 1
	_, cancel := context.WithCancel(context.Background())
	a.completeCipherMutation(a.epoch, e, nil, storageReply{}, vaultwarden.ErrConflict, cancel)
	a.saveCipher()
	if !e.conflict || e.fields.Name != "protected draft" || a.pending != 0 {
		t.Fatal("second conflict dispatched or lost draft")
	}
}

func publishComparisonFixture(t *testing.T, a *app, mutate func(map[string]any)) {
	t.Helper()
	var sync map[string]any
	if err := json.Unmarshal(a.vault.Sync, &sync); err != nil {
		t.Fatal(err)
	}
	item := sync["ciphers"].([]any)[0].(map[string]any)
	item["revisionDate"] = "2026-01-02T00:00:00Z"
	mutate(item)
	raw, err := json.Marshal(sync)
	if err != nil {
		t.Fatal(err)
	}
	next := *a.snapshot
	next.Revision = "new-snapshot"
	a.snapshot = &next
	a.sessionRevision = next.Revision
	a.itemsRevision = next.Revision
	if err := a.adoptVault(&vaultwarden.VaultData{Version: 1, Scope: *a.liveScope, Sync: raw}); err != nil {
		t.Fatal(err)
	}
}
func TestCipherComparisonNativeEntryMaskedAndExplicit(t *testing.T) {
	a := writableUIFixture(t)
	a.openCipherEditor("card-1", 3)
	draft := a.editor
	draft.fields.Name = "local-sensitive-title"
	draft.conflict = true
	publishComparisonFixture(t, a, func(o map[string]any) { o["futureExtension"] = "remote opaque" })
	tt := ui.NewTester(a.view, 1280, 820)
	tt.Scroll(1100, 600, 0, 4000)
	clickUI(t, tt, "比较本地与远端改动")
	if draft.comparison == nil || !tt.HasText("比较本地与远端改动") || !tt.HasText("标题：本地已改；远端未改") {
		t.Fatal("comparison not reachable")
	}
	if tt.HasText("local-sensitive-title") || tt.HasText("4242424242424242") {
		t.Fatal("comparison exposes secret values")
	}
	clickUI(t, tt, "采用我的修改")
	clickUI(t, tt, "按以上选择重新应用到草稿")
	if a.editor != draft || draft.comparison != nil || draft.revision != a.sessionRevision || draft.fields.Name != "local-sensitive-title" || draft.fields.RevisionDate != "2026-01-02T00:00:00Z" || a.pending != 0 || draft.conflict || draft.uncertain {
		t.Fatal("reapply did not produce unsent current draft")
	}
	if !bytes.Contains(draft.document.JSON, []byte("remote opaque")) {
		t.Fatal("not based on latest document")
	}
}
func TestCipherComparisonUnknownResultNeedsSyncAndUserChoice(t *testing.T) {
	a := writableUIFixture(t)
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.fields.Name = "unsure local name"
	e.uncertain = true
	a.compareCipher(nil)
	if e.comparison != nil {
		t.Fatal("unknown write compared without sync")
	}
	publishComparisonFixture(t, a, func(o map[string]any) {
		// Item keys differ from the owner key, so use the retained document transform.
		fields := e.fields
		fields.Name = "unsure local name"
		doc, err := vaultwarden.EncryptCipherDocument(e.document, fields, bytes.Repeat([]byte{4}, 64), a.liveScope.Account)
		if err != nil {
			t.Fatal(err)
		}
		var saved map[string]any
		if json.Unmarshal(doc.JSON, &saved) != nil {
			t.Fatal("fixture")
		}
		o["name"] = saved["name"]
	})
	a.compareCipher(nil)
	if e.comparison == nil || !e.uncertain {
		t.Fatal("comparison automatically cleared uncertain gate")
	}
	a.applyCipherComparison(false)
	if e.uncertain || e.revision != a.sessionRevision || e.fields.Name != "unsure local name" || a.pending != 0 {
		t.Fatal("remote adoption sent write or failed")
	}
}
func TestCipherComparisonCancelLockAndSecondSync(t *testing.T) {
	for _, scenario := range []string{"return", "lock", "resync", "deleted", "permission"} {
		t.Run(scenario, func(t *testing.T) {
			a := writableUIFixture(t)
			a.openCipherEditor("card-1", 3)
			e := a.editor
			e.fields.Name = "local"
			publishComparisonFixture(t, a, func(o map[string]any) {
				if scenario == "deleted" {
					o["deletedDate"] = "2026-01-02T00:00:00Z"
				}
				if scenario == "permission" {
					o["edit"] = false
				}
			})
			a.compareCipher(nil)
			if scenario == "deleted" || scenario == "permission" {
				if e.comparison != nil || e.fields.Name != "local" {
					t.Fatal("transition discarded or reapplied draft")
				}
				return
			}
			if e.comparison == nil {
				t.Fatal(a.status)
			}
			switch scenario {
			case "return":
				tt := ui.NewTester(a.view, 1280, 820)
				clickUI(t, tt, "返回，保留原草稿")
				if e.comparison != nil || e.fields.Name != "local" || e.revision == a.sessionRevision {
					t.Fatal("return lost old draft")
				}
			case "lock":
				a.lockInterface()
				a.applyCipherComparison(true)
				if a.editor != nil || a.session != nil {
					t.Fatal("locked comparison revived")
				}
			case "resync":
				next := *a.snapshot
				next.Revision = "even-newer"
				a.snapshot = &next
				a.sessionRevision = next.Revision
				a.applyCipherComparison(true)
				if e.comparison != nil || e.revision == a.sessionRevision || e.fields.Name != "local" || a.pending != 0 {
					t.Fatal("stale comparison reused")
				}
			}
		})
	}
}
