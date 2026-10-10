// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFolderEncryptedCRUDAndScope(t *testing.T) {
	var session *Session
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
			t.Error("missing auth")
		}
		if r.Method == "DELETE" {
			if r.URL.Path != "/api/folders/folder-1" {
				t.Error("wrong delete")
			}
			w.WriteHeader(204)
			return
		}
		if (r.Method != "POST" || r.URL.Path != "/api/folders") && (r.Method != "PUT" || r.URL.Path != "/api/folders/folder-1") {
			t.Error("wrong save")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 {
			t.Error("invalid body")
		}
		plain, err := vaultcrypto.DecryptString(body["name"], session.key)
		defer clear(plain)
		if err != nil || string(plain) != "私人文件夹" {
			t.Error("name not encrypted")
		}
		json.NewEncoder(w).Encode(Folder{ID: "folder-1", Name: body["name"]})
	}))
	defer server.Close()
	session, _ = resumableFixture(t, server.URL)
	defer session.Close()
	scope := Scope{Server: server.URL, Account: "account-a"}
	if _, err := session.SaveFolder(context.Background(), Scope{Server: server.URL, Account: "other"}, "", "私人文件夹", nil); err != ErrIdentity {
		t.Fatal(err)
	}
	if _, err := session.SaveFolder(context.Background(), scope, "../x", "私人文件夹", nil); err != ErrValidation {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("rejected request sent")
	}
	for _, id := range []string{"", "folder-1"} {
		f, err := session.SaveFolder(context.Background(), scope, id, "私人文件夹", nil)
		if err != nil || f.Name != "私人文件夹" || f.ID != "folder-1" {
			t.Fatal(f, err)
		}
	}
	if err := session.DeleteFolder(context.Background(), scope, "folder-1", nil); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatal("mutation retried")
	}
}

func TestFolderUncertainReplyNeverRetried(t *testing.T) {
	for _, status := range []int{200, 202, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(status)
				w.Write([]byte(`{"id":"different","name":"invalid"}`))
			}))
			defer server.Close()
			session, _ := resumableFixture(t, server.URL)
			defer session.Close()
			_, err := session.SaveFolder(context.Background(), Scope{Server: server.URL, Account: "account-a"}, "folder-1", "test", nil)
			var unknown *MutationUncertainError
			if !errors.As(err, &unknown) || requests != 1 {
				t.Fatal("uncertain result/retry", err, requests)
			}
		})
	}
}

func TestFolderOfflineSnapshotIsolation(t *testing.T) {
	session, _ := resumableFixture(t, "https://example.invalid")
	defer session.Close()
	encrypted, _ := vaultcrypto.EncryptString([]byte("私人文件夹"), session.key)
	scope := Scope{Server: "https://example.invalid", Account: "account-a"}
	makeVault := func(folders []Folder) *VaultData {
		raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": "account-a"}, "ciphers": []any{}, "folders": folders})
		return &VaultData{Version: 1, Scope: scope, Sync: raw}
	}
	vault := makeVault([]Folder{{ID: "f-1", Name: encrypted}})
	installFixtureSnapshot(t, session, vault, "folder-revision")
	folders, err := session.PersonalFolders(vault)
	if err != nil || len(folders) != 1 || folders[0].Name != "私人文件夹" {
		t.Fatal(folders, err)
	}
	if _, err = session.PersonalFolders(makeVault([]Folder{{ID: "f-1", Name: encrypted}, {ID: "f-1", Name: encrypted}})); err != ErrExpired {
		t.Fatal("duplicate id accepted")
	}
	vault.Scope.Account = "other"
	if _, err = session.PersonalFolders(vault); err != ErrIdentity {
		t.Fatal("scope crossed")
	}
	session.Close()
	if _, err = session.PersonalFolders(makeVault(nil)); err != ErrExpired {
		t.Fatal("closed session decrypted")
	}
}
