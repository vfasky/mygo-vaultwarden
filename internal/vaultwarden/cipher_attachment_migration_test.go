// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type resourceRevokeWriter struct {
	io.Writer
	revoked bool
	revoke  func()
}

func (w *resourceRevokeWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if !w.revoked && bytes.Contains(data, []byte("manifest.json")) {
		w.revoked = true
		w.revoke()
	}
	return n, err
}

func TestCipherLegacyAttachmentUpgradeRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "bad-old-mac", "upload-unknown", "bad-new-mac", "different-content", "cancel-before-delete", "revoke-before-delete"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var cipher map[string]any
			blobs := map[string][]byte{}
			writes, deletes := 0, 0
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if strings.HasPrefix(r.URL.Path, "/files/") {
					if r.Header.Get("Authorization") != "" {
						t.Error("signed credentials leaked")
					}
					id := strings.TrimPrefix(r.URL.Path, "/files/")
					data := append([]byte(nil), blobs[id]...)
					if (scenario == "bad-old-mac" && id == "old") || (scenario == "bad-new-mac" && id == "new") {
						data[len(data)-1] ^= 1
					}
					w.Write(data)
					return
				}
				if r.URL.Path == "/api/sync" {
					data := emptyPolicySyncFixture()
					data["ciphers"] = []any{cipher}
					json.NewEncoder(w).Encode(data)
					return
				}
				if r.URL.Path == "/api/ciphers/item/attachment/v2" {
					writes++
					var body struct {
						FileName, Key string
						FileSize      int64
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("metadata")
					}
					row := map[string]any{"id": "new", "fileName": body.FileName, "key": body.Key, "size": body.FileSize, "url": server.URL + "/files/new"}
					cipher["attachments"] = append(cipher["attachments"].([]any), row)
					json.NewEncoder(w).Encode(map[string]any{"attachmentId": "new", "url": "/ciphers/item/attachment/new", "fileUploadType": 0, "cipherResponse": cipher})
					return
				}
				if r.URL.Path == "/api/ciphers/item/attachment/new" && r.Method == "POST" {
					reader, err := r.MultipartReader()
					if err != nil {
						t.Error(err)
						return
					}
					part, err := reader.NextPart()
					if err != nil {
						t.Error(err)
						return
					}
					blobs["new"], err = io.ReadAll(part)
					if err != nil {
						t.Error(err)
					}
					cipher["revisionDate"] = "2026-07-01T00:00:00Z"
					if scenario == "upload-unknown" {
						w.WriteHeader(500)
					}
					return
				}
				if r.URL.Path == "/api/ciphers/item/attachment/old" && r.Method == "DELETE" {
					deletes++
					rows := cipher["attachments"].([]any)
					cipher["attachments"] = rows[1:]
					w.WriteHeader(200)
					return
				}
				if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/ciphers/item/attachment/") {
					id := strings.TrimPrefix(r.URL.Path, "/api/ciphers/item/attachment/")
					for _, row := range cipher["attachments"].([]any) {
						if row.(map[string]any)["id"] == id {
							json.NewEncoder(w).Encode(row)
							return
						}
					}
				}
				t.Error("unexpected route", r.Method, r.URL.Path)
				w.WriteHeader(404)
			}))
			defer server.Close()
			s, _ := resumableFixture(t, server.URL)
			defer s.Close()
			doc, err := NewPersonalCipher(CipherFields{Type: 1, Name: "legacy attachment", Login: map[string]any{"password": "secret"}}, s.key, s.account)
			if err != nil {
				t.Fatal(err)
			}
			cipher, _ = documentObject(doc)
			cipher["id"], cipher["edit"], cipher["viewPassword"], cipher["revisionDate"] = "item", true, true, "2026-06-01T00:00:00Z"
			cipherKey, _ := cipherItemKey(cipher, s.key)
			defer clear(cipherKey)
			name, _ := EncryptString([]byte("same-name.txt"), cipherKey)
			plain := []byte("legacy verified contents")
			encrypted, err := encryptAttachment(context.Background(), bytes.NewReader(plain), int64(len(plain)), s.key)
			if err != nil {
				t.Fatal(err)
			}
			blobs["old"], _ = io.ReadAll(encrypted.file)
			encrypted.close()
			cipher["attachments"] = []any{map[string]any{"id": "old", "fileName": name, "key": "", "size": len(blobs["old"]), "url": server.URL + "/files/old"}}
			snapshot := func(revision string) *VaultData {
				mu.Lock()
				defer mu.Unlock()
				raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": s.account}, "ciphers": []any{cipher}})
				vault := &VaultData{Version: 1, Scope: Scope{Server: server.URL, Account: s.account}, Sync: raw}
				installFixtureSnapshot(t, s, vault, revision)
				return vault
			}
			vault := snapshot("before")
			result, err := s.UpgradeLegacyCipherAttachment(context.Background(), vault, "item", "old", true, nil, nil)
			if scenario == "bad-old-mac" {
				if err == nil || writes != 0 || deletes != 0 {
					t.Fatal("bad old binary wrote", err)
				}
				return
			}
			if scenario == "upload-unknown" {
				if err == nil || result.ReplacementID != "new" || deletes != 0 || writes != 1 {
					t.Fatal("unknown result lost", result, err)
				}
			} else if err != nil || !result.Uploaded || !result.Reconciled {
				t.Fatal("upgrade", result, err)
			}
			if deletes != 0 {
				t.Fatal("upgrade deleted original")
			}
			// Reconstruct from server state, with no upload plan/digest retained. This
			// models restart: both copies remain independently readable on the server.
			if scenario == "different-content" {
				row := cipher["attachments"].([]any)[1].(map[string]any)
				attachmentKey, _ := DecryptString(row["key"].(string), cipherKey)
				other := bytes.Repeat([]byte{'x'}, len(plain))
				spool, err := encryptAttachment(context.Background(), bytes.NewReader(other), int64(len(other)), attachmentKey)
				clear(attachmentKey)
				if err != nil {
					t.Fatal(err)
				}
				blobs["new"], _ = io.ReadAll(spool.file)
				spool.close()
			}
			if scenario == "success" {
				mu.Lock()
				cipher["deletedDate"] = "2026-07-02T00:00:00Z"
				mu.Unlock()
				trashed := snapshot("trash-backup")
				var archive bytes.Buffer
				proof, err := s.WriteResourceBackup(context.Background(), trashed, []string{"item"}, "", nil, true, &archive, nil)
				if err != nil {
					t.Fatal("trash resource export", err)
				}
				published := false
				if err = s.PublishResourceBackup(context.Background(), proof, nil, func() error { published = true; return nil }); err != nil || !published {
					t.Fatal("resource publication", err)
				}
				var deniedArchive bytes.Buffer
				revoking := &resourceRevokeWriter{Writer: &deniedArchive, revoke: func() { mu.Lock(); cipher["viewPassword"] = false; mu.Unlock() }}
				denied, deniedErr := s.WriteResourceBackup(context.Background(), trashed, []string{"item"}, "", nil, true, revoking, nil)
				if !revoking.revoked || deniedErr == nil || denied != nil {
					t.Fatal("archive final authority reused earlier file permission")
				}
				mu.Lock()
				cipher["viewPassword"] = true
				mu.Unlock()
				file, err := os.CreateTemp("", "mygo-resource-test-*")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(file.Name())
				if _, err = file.Write(archive.Bytes()); err != nil {
					t.Fatal(err)
				}
				file.Seek(0, io.SeekStart)
				plan, err := ParseResourceImport(context.Background(), file)
				if err != nil {
					t.Fatal("resource parse", err)
				}
				defer plan.Clear()
				if len(plan.Resources()) != 2 || len(plan.DeferredTrashIDs()) != 1 {
					t.Fatal("resource manifest missing data")
				}
				metadata, err := plan.PersonalRestoreMetadata()
				if err != nil || metadata.Deleted != 0 {
					t.Fatal("restore did not defer trash", err)
				}
				metadata.Clear()
				if err = s.VerifyRestoredResource(context.Background(), trashed, "item", "old", plan, 0, nil, nil); err != nil {
					t.Fatal("trash backup verify", err)
				}
				if err = s.DeleteAttachment(context.Background(), trashed, "item", "old", nil, nil); err == nil || deletes != 0 {
					t.Fatal("trash write bypass")
				}
				if _, err = s.DownloadAttachment(context.Background(), trashed, "item", "old", nil, nil, func(*os.File, int64) error { return nil }); err == nil {
					t.Fatal("ordinary trash read changed")
				}
				mu.Lock()
				delete(cipher, "deletedDate")
				mu.Unlock()
			}
			vault = snapshot("after")
			if scenario == "revoke-before-delete" {
				mu.Lock()
				cipher["viewPassword"] = false
				mu.Unlock()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel-before-delete" {
				cancel()
			}
			checked, err := s.VerifyAndDeleteLegacyCipherAttachment(ctx, vault, "item", "old", "new", true, nil, nil)
			rejected := scenario == "bad-new-mac" || scenario == "different-content" || scenario == "cancel-before-delete" || scenario == "revoke-before-delete"
			if rejected {
				if err == nil || deletes != 0 || checked.OriginalDeleted {
					t.Fatal("unsafe original deletion", checked, err)
				}
			} else if err != nil || !checked.ContentVerified || !checked.OriginalDeleted || deletes != 1 {
				t.Fatal("verified delete", checked, err)
			}
		})
	}
}
