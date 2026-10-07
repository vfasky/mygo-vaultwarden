// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"testing"
)

func testLiveFoldersAndBulk(t *testing.T, ctx context.Context, s *Session, scope Scope) {
	t.Helper()
	folder, err := s.SaveFolder(ctx, scope, "", "个人测试", nil)
	if err != nil {
		t.Fatal("create folder", err)
	}
	folder, err = s.SaveFolder(ctx, scope, folder.ID, "更名测试", nil)
	if err != nil {
		t.Fatal("rename folder", err)
	}
	ids := []string{}
	for i := 0; i < 2; i++ {
		doc, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 1, Name: "bulk fixture", Login: map[string]any{"password": "fixture secret"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := DecryptCipherDocument(doc, s.key)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, fields.ID)
	}
	snapshot, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	folders, err := s.PersonalFolders(snapshot.Vault)
	if err != nil || len(folders) != 1 || folders[0].Name != "更名测试" {
		t.Fatal("offline folder", folders, err)
	}
	verify := func(op CipherAction) {
		t.Helper()
		var target *string
		if op == CipherMove {
			target = &folder.ID
		}
		if err := s.ChangePersonalCiphers(ctx, scope, snapshot.Vault, ids, op, target, nil); err != nil {
			t.Fatal("bulk", op, err)
		}
		snapshot, err = s.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := s.PersonalEntries(snapshot.Vault)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			found := false
			for _, e := range entries {
				if e.ID != id {
					continue
				}
				found = true
				if op == CipherMove && e.FolderID != folder.ID || op == CipherArchive && !e.Archived || op == CipherUnarchive && e.Archived || op == CipherTrash && !e.Deleted || op == CipherRestore && e.Deleted {
					t.Fatal("wrong batch result", op)
				}
			}
			if found == (op == CipherDeletePermanently) {
				t.Fatal("batch presence mismatch", op)
			}
		}
	}
	verify(CipherMove)
	// Deleting the folder must unfile, never delete its contents.
	if err = s.DeleteFolder(ctx, scope, folder.ID, nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		_, fields, err := s.ReadPersonalCipher(snapshot.Vault, id)
		if err != nil || fields.FolderID != nil {
			t.Fatal("folder deletion damaged item", err)
		}
	}
	for _, op := range []CipherAction{CipherArchive, CipherUnarchive, CipherTrash, CipherRestore, CipherTrash, CipherDeletePermanently} {
		verify(op)
	}
	// A stale snapshot can contain IDs already removed remotely. Bulk move writes
	// the accessible item and still returns 400: verify this against the real server.
	doc, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 2, Name: "partial fixture", SecureNote: map[string]any{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := DecryptCipherDocument(doc, s.key)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(stale.Vault.Sync, &raw)
	var ciphers []json.RawMessage
	json.Unmarshal(raw["ciphers"], &ciphers)
	missing := `{"id":"00000000-0000-0000-0000-000000000000","type":2}`
	ciphers = append(ciphers, json.RawMessage(missing))
	raw["ciphers"], _ = json.Marshal(ciphers)
	stale.Vault.Sync, _ = json.Marshal(raw)
	folder, err = s.SaveFolder(ctx, scope, "", "partial destination", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ChangePersonalCiphers(ctx, scope, stale.Vault, []string{fields.ID, "00000000-0000-0000-0000-000000000000"}, CipherMove, &folder.ID, nil)
	if _, ok := err.(*MutationUncertainError); !ok {
		t.Fatal("partial batch must be uncertain", err)
	}
	snapshot, err = s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, fields, err = s.ReadPersonalCipher(snapshot.Vault, fields.ID)
	if err != nil || fields.FolderID == nil || *fields.FolderID != folder.ID {
		t.Fatal("expected partial move", err)
	}
	if err = s.ChangeCipherState(ctx, scope, fields.ID, CipherDeletePermanently, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteFolder(ctx, scope, folder.ID, nil); err != nil {
		t.Fatal(err)
	}
}
