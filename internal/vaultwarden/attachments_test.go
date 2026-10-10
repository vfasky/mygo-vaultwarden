// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestAttachmentSessionUpload(t *testing.T) {
	for _, organization := range []bool{false, true} {
		for _, scenario := range []string{"success-empty", "success-large", "success-quarantine", "reject-metadata", "bad-url", "bad-type", "bad-id", "bad-cipher", "bad-size", "bad-key", "revoke-before-upload", "policy-before-upload", "server-conflict", "upload-failure", "cancel-after-metadata", "revoke-after-upload"} {
			t.Run(map[bool]string{false: "personal", true: "organization"}[organization]+"/"+scenario, func(t *testing.T) {
				var cipher map[string]any
				var cipherKey []byte
				var writes, uploads, syncs atomic.Int32
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				input := []byte{}
				if scenario == "success-large" {
					input = bytes.Repeat([]byte{0, 255, 9}, 3*1024*1024+1)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
						t.Error("missing session bearer")
					}
					if r.URL.Path == "/api/sync" {
						n := syncs.Add(1)
						data := emptyPolicySyncFixture()
						if organization {
							data = organizationPolicySyncFixture()
						}
						if (scenario == "revoke-before-upload" && n == 3) || (scenario == "revoke-after-upload" && n == 4) {
							cipher["edit"] = false
						}
						if scenario == "policy-before-upload" && n == 3 {
							data = policySyncFixture(2, 15, []int{1})
							if organization {
								data = organizationPolicySyncFixture()
								p := map[string]any{"id": "policy-a", "organizationId": "org-1", "type": 15, "enabled": true, "data": []int{1}}
								data["policies"], data["policiesNew"] = []any{p}, []any{p}
							}
						}
						data["ciphers"] = []any{cipher}
						_ = json.NewEncoder(w).Encode(data)
						return
					}
					if r.Method == "DELETE" {
						t.Error("automatic compensation DELETE")
						w.WriteHeader(500)
						return
					}
					if r.URL.Path == "/api/ciphers/item-org/attachment/v2" {
						writes.Add(1)
						if scenario == "reject-metadata" {
							w.WriteHeader(403)
							return
						}
						var body struct {
							FileName, Key string
							FileSize      int64
							AdminRequest  bool
						}
						if json.NewDecoder(r.Body).Decode(&body) != nil || body.AdminRequest {
							t.Error("metadata body")
						}
						key, err := vaultcrypto.DecryptString(body.Key, cipherKey)
						if err != nil || len(key) != 64 {
							t.Error("wrapped attachment key", err)
						}
						name, err := vaultcrypto.DecryptString(body.FileName, cipherKey)
						if err != nil || string(name) != "test.txt" {
							t.Error("encrypted filename", err)
						}
						cipher["attachments"] = []any{map[string]any{"id": "attachment-new", "key": body.Key, "fileName": body.FileName, "size": body.FileSize, "url": "https://download.invalid/old"}}
						response := map[string]any{"attachmentId": "attachment-new", "url": "/ciphers/item-org/attachment/attachment-new", "fileUploadType": 0, "cipherResponse": cipher}
						switch scenario {
						case "bad-url":
							response["url"] = "https://external.invalid/steal"
						case "bad-type":
							response["fileUploadType"] = 1
						case "bad-id":
							response["attachmentId"] = "../other"
						case "bad-cipher":
							cipher["id"] = "other"
						case "bad-size":
							cipher["attachments"].([]any)[0].(map[string]any)["size"] = 65 + 16
						case "bad-key":
							cipher["attachments"].([]any)[0].(map[string]any)["key"] = "bad"
						case "server-conflict":
							cipher["revisionDate"] = "changed"
						}
						_ = json.NewEncoder(w).Encode(response)
						if scenario == "cancel-after-metadata" {
							cancel()
						}
						return
					}
					if r.URL.Path == "/api/ciphers/item-org/attachment/attachment-new" {
						uploads.Add(1)
						if scenario == "upload-failure" {
							w.WriteHeader(500)
							return
						}
						a := cipher["attachments"].([]any)[0].(map[string]any)
						key, err := vaultcrypto.DecryptString(a["key"].(string), cipherKey)
						if err != nil {
							t.Error(err)
						}
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
						if part.FormName() != "data" {
							t.Error("field")
						}
						plain, err := vaultcrypto.DecryptAttachment(r.Context(), part, a["size"].(int64), key)
						if err != nil {
							t.Error("uploaded ciphertext", err)
							return
						}
						defer plain.Close()
						actual, err := io.ReadAll(plain.File)
						if err != nil || !bytes.Equal(actual, input) {
							t.Error("uploaded data mismatch")
						}
						cipher["revisionDate"] = "2026-07-01T00:00:00Z"
						// Fresh signed URLs must not make the subsequent sync look conflicting.
						a["url"] = "https://download.invalid/new"
						w.WriteHeader(200)
						return
					}
					t.Error("unexpected route", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}))
				defer server.Close()
				s, vault, orgKey, doc := organizationFixture(t, server.URL)
				defer s.Close()
				cipher, _ = documentObject(doc)
				if !organization {
					doc, _ = NewPersonalCipher(CipherFields{Type: 1, Name: "personal", Login: map[string]any{"password": "secret"}}, s.key, s.account)
					cipher, _ = documentObject(doc)
					cipher["id"], cipher["edit"], cipher["viewPassword"], cipher["revisionDate"] = "item-org", true, true, "2026-06-01T00:00:00Z"
					doc.JSON, _ = json.Marshal(cipher)
					var raw map[string]json.RawMessage
					_ = json.Unmarshal(vault.Sync, &raw)
					raw["ciphers"], _ = json.Marshal([]json.RawMessage{doc.JSON})
					vault.Sync, _ = json.Marshal(raw)
					if scenario == "success-quarantine" {
						vault.QuarantinedOrganizations = []string{"org-1"}
					}
					installFixtureSnapshot(t, s, vault, "revision-1")
					cipherKey, _ = cipherItemKey(cipher, s.key)
				} else {
					cipherKey, _ = cipherItemKey(cipher, orgKey)
				}
				defer clear(cipherKey)
				file, err := os.CreateTemp(t.TempDir(), "input-")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(input); err != nil {
					t.Fatal(err)
				}
				result, err := s.UploadAttachment(ctx, vault, "item-org", "test.txt", file, nil, nil)
				if _, e := file.Stat(); e == nil {
					t.Error("input not closed")
				}
				success := scenario == "success-empty" || scenario == "success-large" || scenario == "success-quarantine"
				if success {
					if err != nil || !result.Reconciled || !result.Uploaded || !result.MetadataCreated || result.AttachmentID != "attachment-new" || uploads.Load() != 1 || syncs.Load() != 4 {
						t.Fatalf("success %+v %v requests %d/%d/%d", result, err, syncs.Load(), writes.Load(), uploads.Load())
					}
				} else {
					if err == nil || result.Reconciled {
						t.Fatalf("unexpected success %+v", result)
					}
					if scenario == "reject-metadata" {
						if !errors.Is(err, ErrPermission) || result.MetadataCreated {
							t.Fatal(result, err)
						}
					} else {
						var uncertain *MutationUncertainError
						if !errors.As(err, &uncertain) {
							t.Errorf("missing uncertain outcome: %v", err)
						}
					}
					expectedUploads := int32(0)
					if scenario == "upload-failure" || scenario == "revoke-after-upload" {
						expectedUploads = 1
					}
					if uploads.Load() != expectedUploads {
						t.Error("unexpected upload dispatch", uploads.Load())
					}
				}
				if writes.Load() != 1 {
					t.Error("metadata retried", writes.Load())
				}
			})
		}
	}
}
