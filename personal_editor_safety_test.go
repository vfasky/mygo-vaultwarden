// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestFolderPublicationUpdatesNavigationButNotDraftAuthority(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	var raw map[string]any
	if json.Unmarshal(a.vault.Sync, &raw) != nil {
		t.Fatal("fixture")
	}
	encrypted, err := vaultwarden.EncryptString([]byte("renamed"), bytes.Repeat([]byte{4}, 64))
	if err != nil {
		t.Fatal(err)
	}
	raw["folders"] = []any{map[string]any{"id": "folder-1", "name": encrypted}}
	raw["ciphers"].([]any)[0].(map[string]any)["folderId"] = "folder-1"
	a.vault.Sync, _ = json.Marshal(raw)
	a.category = "folder:folder-1"
	acceptUIReceipt(t, a, a.vault)
	if err = a.adoptVault(a.vault); err != nil {
		t.Fatal(err)
	}
	if a.currentCategory().title != "renamed" || len(a.filteredItems()) != 1 {
		t.Fatal("renamed/moved state stale")
	}
	a.openCipherEditor("card-1", 3)
	draft := a.editor
	raw["folders"] = []any{}
	raw["ciphers"].([]any)[0].(map[string]any)["folderId"] = nil
	vault := *a.vault
	vault.Sync, _ = json.Marshal(raw)
	acceptUIReceipt(t, a, &vault)
	if err = a.adoptVault(&vault); err != nil {
		t.Fatal(err)
	}
	a.sessionRevision, a.snapshot.Revision, a.itemsRevision = "new-publication", "new-publication", "new-publication"
	if a.category != "folder:" || len(a.filteredItems()) != 1 || a.editor != draft || draft.revision == a.sessionRevision {
		t.Fatal("deleted folder navigation/draft revision")
	}
	a.saveCipher()
	if a.pending != 0 {
		t.Fatal("stale folder draft could be saved")
	}
}

func TestHistoryDeletionRequiresConfirmationAndStaysInDraft(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.fields.PasswordHistory = []map[string]any{{"password": "fixture", "lastUsedDate": "2026-01-01T00:00:00Z"}}
	tester := ui.NewTester(func(c *ui.Context) { a.passwordHistoryView(c, e) }, 600, 400)
	clickUI(t, tester, "清除密码历史")
	if !e.confirmHistoryDelete || len(e.fields.PasswordHistory) != 1 || a.pending != 0 {
		t.Fatal("history changed before confirmation")
	}
	clickUI(t, tester, "保留历史")
	if e.confirmHistoryDelete || len(e.fields.PasswordHistory) != 1 {
		t.Fatal("cancel removed history")
	}
	clickUI(t, tester, "清除密码历史")
	clickUI(t, tester, "确认清除历史")
	if len(e.fields.PasswordHistory) != 0 || a.pending != 0 {
		t.Fatal("confirmation should only edit draft")
	}
}

func TestCustomAndHistoryEditorCannotBypassCipherPermissions(t *testing.T) {
	for _, restriction := range []string{"reprompt", "viewPassword", "organizationId"} {
		t.Run(restriction, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			var raw map[string]any
			json.Unmarshal(a.vault.Sync, &raw)
			item := raw["ciphers"].([]any)[0].(map[string]any)
			switch restriction {
			case "reprompt":
				item[restriction] = 1
			case "viewPassword":
				item[restriction] = false
			case "organizationId":
				item[restriction] = "org-1"
			}
			a.vault.Sync, _ = json.Marshal(raw)
			acceptUIReceipt(t, a, a.vault)
			a.openCipherEditor("card-1", 3)
			if restriction == "reprompt" {
				if a.editor == nil || a.editor.repromptID != "card-1" || a.editor.fields.Name != "" || len(a.editor.inputs) != 0 || len(a.editor.document.JSON) != 0 {
					t.Fatal("reauthentication form exposed protected data")
				}
			} else if a.editor != nil {
				t.Fatal("restricted secrets/editor revealed")
			}
		})
	}
}
