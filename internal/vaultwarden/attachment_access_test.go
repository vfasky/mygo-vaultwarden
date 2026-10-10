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
	"time"
)

func TestAttachmentDownloadAuthorizationAndPublication(t *testing.T) {
	for _, scenario := range []string{"normal", "legacy-key", "readonly", "hidden", "reprompt", "metadata-mismatch", "bad-mac", "truncated", "signature-expired", "revoke-during-download", "revoke-after-staging", "cancel", "lock", "epoch", "lease", "used", "expires"} {
		t.Run(scenario, func(t *testing.T) {
			var cipher map[string]any
			var record map[string]any
			var encoded []byte
			var calls, downloads, syncs atomic.Int32
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/file" {
					downloads.Add(1)
					if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Error("signed request leaked account credentials")
					}
					if scenario == "signature-expired" {
						w.WriteHeader(403)
						return
					}
					data := bytes.Clone(encoded)
					if scenario == "bad-mac" {
						data[len(data)-1] ^= 1
					}
					if scenario == "truncated" {
						data = data[:len(data)-1]
					}
					if scenario == "revoke-during-download" {
						cipher["viewPassword"] = false
					}
					_, _ = w.Write(data)
					return
				}
				if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
					t.Error("missing authenticated request")
				}
				if r.URL.Path == "/api/sync" {
					syncs.Add(1)
					data := organizationPolicySyncFixture()
					data["ciphers"] = []any{cipher}
					_ = json.NewEncoder(w).Encode(data)
					return
				}
				if r.URL.Path == "/api/ciphers/item-org/attachment/attachment-1" {
					if scenario == "metadata-mismatch" {
						record["key"] = "other"
					}
					_ = json.NewEncoder(w).Encode(record)
					return
				}
				t.Error("unexpected request", r.Method, r.URL.Path)
				w.WriteHeader(404)
			}))
			defer server.Close()
			s, vault, ownerKey, doc := organizationFixture(t, server.URL)
			defer s.Close()
			cipher, _ = documentObject(doc)
			cipherKey, _ := cipherItemKey(cipher, ownerKey)
			defer clear(cipherKey)
			fileKey := bytes.Repeat([]byte{42}, 64)
			wrapped, _ := vaultcrypto.EncryptString(fileKey, cipherKey)
			if scenario == "legacy-key" {
				fileKey = ownerKey
				wrapped = ""
			}
			name, _ := vaultcrypto.EncryptString([]byte("../../unsafe\\report.txt"), cipherKey)
			plain := []byte("authenticated file content")
			spool, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(plain), int64(len(plain)), fileKey)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ = io.ReadAll(spool.File)
			spool.Close()
			record = map[string]any{"id": "attachment-1", "fileName": name, "key": wrapped, "size": len(encoded), "url": server.URL + "/file?token=fixture"}
			cipher["attachments"] = []any{record}
			if scenario == "readonly" {
				cipher["edit"] = false
			}
			if scenario == "hidden" {
				cipher["viewPassword"] = false
			}
			if scenario == "reprompt" {
				cipher["reprompt"] = 1
			}
			doc.JSON, _ = json.Marshal(cipher)
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(vault.Sync, &raw)
			raw["ciphers"], _ = json.Marshal([]json.RawMessage{doc.JSON})
			vault.Sync, _ = json.Marshal(raw)
			installFixtureSnapshot(t, s, vault, "revision-1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			consumed := false
			proof, err := s.DownloadAttachment(ctx, vault, "item-org", "attachment-1", nil, nil, func(file *os.File, n int64) error {
				consumed = true
				got, e := io.ReadAll(file)
				if e != nil || !bytes.Equal(got, plain) || n != int64(len(plain)) {
					t.Error("plaintext mismatch", e)
				}
				if scenario == "revoke-after-staging" {
					cipher["viewPassword"] = false
				}
				return nil
			})
			rejected := scenario == "hidden" || scenario == "reprompt" || scenario == "metadata-mismatch" || scenario == "bad-mac" || scenario == "truncated" || scenario == "signature-expired" || scenario == "revoke-during-download" || scenario == "revoke-after-staging"
			if rejected {
				if err == nil || proof != nil {
					t.Fatal("unauthorized publication proof", err)
				}
				if (scenario == "hidden" || scenario == "reprompt") && calls.Load() != 0 {
					t.Error("unauthorized network request")
				}
				if (scenario == "bad-mac" || scenario == "truncated" || scenario == "signature-expired" || scenario == "metadata-mismatch") && consumed {
					t.Error("unverified plaintext exposed")
				}
				return
			}
			if err != nil || proof == nil || !consumed {
				t.Fatal("download", err)
			}
			switch scenario {
			case "cancel":
				cancel()
			case "lock":
				s.Close()
			case "epoch":
				s.RevokeItemAuthorizations()
			case "lease":
				s.offlinePolicies = nil
			case "expires":
				proof.expires = time.Now()
			}
			published := false
			err = s.PublishAttachment(ctx, proof, nil, func() error { published = true; return nil })
			denied := scenario == "cancel" || scenario == "lock" || scenario == "epoch" || scenario == "lease" || scenario == "expires"
			if denied {
				if err == nil || published {
					t.Fatal("revoked proof published", err)
				}
			} else {
				if err != nil || !published {
					t.Fatal("publication", err)
				}
				published = false
				if err := s.PublishAttachment(ctx, proof, nil, func() error { published = true; return nil }); !errors.Is(err, ErrPermission) || published {
					t.Fatal("reused proof", err)
				}
				rows, err := s.Attachments(context.Background(), vault, "item-org", nil, nil)
				if err != nil || len(rows) != 1 || rows[0].FileName != "report.txt" {
					t.Fatal("safe display filename", rows, err)
				}
				if scenario == "readonly" {
					if err := s.DeleteAttachment(context.Background(), vault, "item-org", "attachment-1", nil, nil); !errors.Is(err, ErrPermission) {
						t.Fatal("readonly deletion", err)
					}
				}
			}
		})
	}
}
