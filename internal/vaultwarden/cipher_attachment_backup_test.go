// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAttachmentBackupTrashReadOnlyAuthority(t *testing.T) {
	for _, scenario := range []string{"normal", "readonly", "hidden", "reprompt", "expired", "quarantined", "bad-mac", "revoke-after-staging", "cancel", "deleted-remotely"} {
		t.Run(scenario, func(t *testing.T) {
			var cipher, record map[string]any
			var encoded []byte
			var mutations atomic.Int32
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					mutations.Add(1)
					w.WriteHeader(500)
					return
				}
				if r.URL.Path == "/file" {
					if r.Header.Get("Authorization") != "" {
						t.Error("signed credential leak")
					}
					data := bytes.Clone(encoded)
					if scenario == "bad-mac" {
						data[len(data)-1] ^= 1
					}
					w.Write(data)
					return
				}
				if r.URL.Path == "/api/sync" {
					data := organizationPolicySyncFixture()
					data["ciphers"] = []any{cipher}
					if scenario == "deleted-remotely" {
						data["ciphers"] = []any{}
					}
					json.NewEncoder(w).Encode(data)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/attachment/file-a") {
					json.NewEncoder(w).Encode(record)
					return
				}
				w.WriteHeader(404)
			}))
			defer server.Close()
			s, vault, ownerKey, document := organizationFixture(t, server.URL)
			defer s.Close()
			cipher, _ = documentObject(document)
			cipher["deletedDate"] = "2026-06-02T00:00:00Z"
			if scenario == "readonly" {
				cipher["edit"] = false
			}
			if scenario == "hidden" {
				cipher["viewPassword"] = false
			}
			if scenario == "reprompt" || scenario == "expired" {
				cipher["reprompt"] = json.Number("1")
			}
			key, _ := cipherItemKey(cipher, ownerKey)
			defer clear(key)
			fileKey := bytes.Repeat([]byte{23}, 64)
			wrapped, _ := vaultcrypto.EncryptString(fileKey, key)
			name, _ := vaultcrypto.EncryptString([]byte("trash.bin"), key)
			content := []byte("trash content")
			spool, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(content), int64(len(content)), fileKey)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ = io.ReadAll(spool.File)
			spool.Close()
			record = map[string]any{"id": "file-a", "key": wrapped, "fileName": name, "size": len(encoded), "url": server.URL + "/file"}
			cipher["attachments"] = []any{record}
			document.JSON, _ = json.Marshal(cipher)
			var raw map[string]json.RawMessage
			json.Unmarshal(vault.Sync, &raw)
			raw["ciphers"], _ = json.Marshal([]json.RawMessage{document.JSON})
			vault.Sync, _ = json.Marshal(raw)
			if scenario == "quarantined" {
				vault.QuarantinedOrganizations = []string{"org-1"}
			}
			installFixtureSnapshot(t, s, vault, "trash-revision")
			var grant *ItemAuthorization
			if scenario == "reprompt" || scenario == "expired" {
				grant = &ItemAuthorization{session: s, scope: vault.Scope, revision: s.authorizationRevision, item: "item-org", document: sha256.Sum256(document.JSON), epoch: s.authorizationEpoch, expires: time.Now().Add(time.Minute)}
				if scenario == "expired" {
					grant.expires = time.Now().Add(-time.Second)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			consumed := false
			proof, err := s.DownloadAttachmentForBackup(ctx, vault, "item-org", "file-a", grant, nil, func(file *os.File, size int64) error {
				consumed = true
				got, _ := io.ReadAll(file)
				if !bytes.Equal(got, content) {
					t.Error("trash content mismatch")
				}
				if scenario == "revoke-after-staging" {
					cipher["viewPassword"] = false
				}
				return nil
			})
			accepted := scenario == "normal" || scenario == "readonly" || scenario == "reprompt"
			if accepted {
				if err != nil || !consumed || proof == nil {
					t.Fatal("authorized trash read failed", err)
				}
				if err = s.PublishAttachment(ctx, proof, grant, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || proof != nil {
				t.Fatal("unauthorized trash proof")
			}
			if scenario == "bad-mac" && consumed {
				t.Fatal("bad MAC exposed content")
			}
			if _, err = s.DownloadAttachment(context.Background(), vault, "item-org", "file-a", grant, nil, func(*os.File, int64) error { t.Error("ordinary trash consumer"); return nil }); err == nil {
				t.Fatal("ordinary read bypass")
			}
			if err = s.DeleteAttachment(context.Background(), vault, "item-org", "file-a", grant, nil); err == nil {
				t.Fatal("trash delete bypass")
			}
			file, err := os.CreateTemp("", "mygo-trash-write-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(file.Name())
			if _, err = s.UploadAttachment(context.Background(), vault, "item-org", "new.bin", file, grant, nil); err == nil {
				t.Fatal("trash upload bypass")
			}
			if mutations.Load() != 0 {
				t.Fatal("backup read issued mutation")
			}
		})
	}
}
