// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"testing"
)

func testLiveFoldersAndBulk(t *testing.T, ctx context.Context, s *Session, scope Scope) {
	t.Helper()
	// Go-only stand-in for an authenticated publication receipt.
	authenticatedSync := func() (SyncResult, error) {
		r, err := s.Sync(ctx)
		if err == nil {
			err = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID())
		}
		return r, err
	}
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
	snapshot, err := authenticatedSync()
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
		snapshot, err = authenticatedSync()
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
	snapshot, err = authenticatedSync()
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
	// The authenticated policy preflight detects a missing server ID before the
	// batch is dispatched. A deletion after this GET can still cause a partial
	// server result; exercise that protocol separately with a fixture request.
	doc, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 2, Name: "partial fixture", SecureNote: map[string]any{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := DecryptCipherDocument(doc, s.key)
	if err != nil {
		t.Fatal(err)
	}
	missingDoc, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 2, Name: "stale missing fixture", SecureNote: map[string]any{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	missingFields, err := DecryptCipherDocument(missingDoc, s.key)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := authenticatedSync()
	if err != nil {
		t.Fatal(err)
	}
	// Cache a real authenticated item, then remove it on the server. Do not
	// forge public snapshot bytes to simulate an authenticated stale snapshot.
	if err = s.ChangeCipherState(ctx, scope, missingFields.ID, CipherDeletePermanently, nil); err != nil {
		t.Fatal(err)
	}
	folder, err = s.SaveFolder(ctx, scope, "", "partial destination", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ChangePersonalCiphers(ctx, scope, stale.Vault, []string{fields.ID, missingFields.ID}, CipherMove, &folder.ID, nil)
	if err != ErrConflict {
		t.Fatal("missing server item must block the batch", err)
	}
	snapshot, err = authenticatedSync()
	if err != nil {
		t.Fatal(err)
	}
	_, unchanged, err := s.ReadPersonalCipher(snapshot.Vault, fields.ID)
	if err != nil || unchanged.FolderID != nil {
		t.Fatal("preflight rejection changed an item", err)
	}
	body, _ := json.Marshal(map[string]any{"ids": []string{fields.ID, missingFields.ID}, "folderId": folder.ID})
	status, _, err := s.client.request(ctx, "PUT", "/api/ciphers/move", "application/json", string(body), s.access)
	if err != nil || status != 400 {
		t.Fatal("fixture partial server rejection", status, err)
	}
	snapshot, err = authenticatedSync()
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
