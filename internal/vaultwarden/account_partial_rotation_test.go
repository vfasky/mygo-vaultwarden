// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAccountNontransactionalFolderWriteKeepsBothDecryptPaths(t *testing.T) {
	var serverFolder AccountRotationFolder
	s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, _ *Session, _ *VaultData) {
		var req AccountRotationRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Data.Folders) != 1 {
			t.Error("missing folder DTO")
			w.WriteHeader(422)
			return
		}
		// Mirrors fixed server ordering: folder saved, later cipher/user save fails.
		serverFolder = req.Data.Folders[0]
		w.WriteHeader(400)
	})
	name, _ := EncryptString([]byte("Folder before partial rotation"), s.key)
	var original map[string]json.RawMessage
	_ = json.Unmarshal(v.Sync, &original)
	original["folders"] = mustAccountJSON(t, []AccountRotationFolder{{ID: "folder-a", Name: name}})
	v.Sync = mustAccountJSON(t, original)
	if err := s.AcceptAuthenticatedSnapshot(v, "with-folder"); err != nil {
		t.Fatal(err)
	}
	adapter := accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
		out, _ := accountEmptyRotation(ctx, in)
		folder, err := AccountRewrapRotationFolder(AccountRotationFolder{ID: "folder-a", Name: name}, in.OldUserKey, in.NewUserKey)
		if err != nil {
			return out, err
		}
		out.Data.Folders = []AccountRotationFolder{folder}
		return out, nil
	})
	plan, err := s.PrepareAccountRotation(context.Background(), v, accountTestPassword, adapter, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	var saved []byte
	result, err := s.CommitAccountChange(context.Background(), plan, string(AccountRotateKey), nil, func(r AccountRecovery) error { saved = mustAccountJSON(t, r); return nil })
	defer clear(saved)
	if err == nil || !result.Unknown || !s.closed {
		t.Fatal("partial mutation not blocked")
	}
	var recovery AccountRecovery
	_ = json.Unmarshal(saved, &recovery)
	defer recovery.Close()
	old, err := RestoreSession(recovery.OldSession, recovery.Scope, &recovery.OldUnlock.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if _, err = DecryptString(serverFolder.Name, old.key); err == nil {
		t.Fatal("fixture did not rotate remote folder")
	}
	remote, err := DecryptString(serverFolder.Name, recovery.NewUserKey)
	if err != nil || string(remote) != "Folder before partial rotation" {
		t.Fatal("new decrypt path lost")
	}
	clear(remote)
	var savedVault VaultData
	_ = json.Unmarshal(recovery.OldVault, &savedVault)
	var oldSync struct{ Folders []AccountRotationFolder }
	_ = json.Unmarshal(savedVault.Sync, &oldSync)
	local, err := DecryptString(oldSync.Folders[0].Name, old.key)
	if err != nil || string(local) != "Folder before partial rotation" {
		t.Fatal("old decrypt path lost")
	}
	clear(local)
}
