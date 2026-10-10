// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestLegacyShareRecoveryNontransactionalAttachments(t *testing.T) {
	for _, scenario := range []string{"attachments-first-failure", "response-lost", "new-cipher-mixed", "persist-failure", "cancel-after-persist", "external-edit", "missing-attachment", "attachment-changed", "unknown-null"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var current map[string]any
			shares, repairs := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/api/sync" {
					data := organizationPolicySyncFixture()
					data["ciphers"] = []any{current}
					json.NewEncoder(w).Encode(data)
					return
				}
				if r.URL.Path == "/api/ciphers/share-me/share" && r.Method == "PUT" {
					shares++
					var request struct {
						Cipher map[string]any `json:"cipher"`
					}
					decoder := json.NewDecoder(r.Body)
					decoder.UseNumber()
					if decoder.Decode(&request) != nil {
						t.Error("share body")
						w.WriteHeader(400)
						return
					}
					wrappers, ok := request.Cipher["attachments2"].(map[string]any)
					if !ok {
						t.Error("missing real attachments2 protocol")
					}
					rows := current["attachments"].([]any)
					for i, raw := range rows {
						if scenario == "new-cipher-mixed" && i == 1 {
							continue
						}
						row := raw.(map[string]any)
						desired := wrappers[row["id"].(string)].(map[string]any)
						row["key"], row["fileName"] = desired["key"], desired["fileName"]
					}
					if scenario == "response-lost" || scenario == "new-cipher-mixed" {
						current = request.Cipher
						current["attachments"] = rows
						current["collectionIds"] = []any{"collection-1"}
						delete(current, "attachments2")
						delete(current, "lastKnownRevisionDate")
						delete(current, "encryptedFor")
					}
					w.WriteHeader(500)
					return
				}
				if r.URL.Path == "/api/ciphers/share-me" && r.Method == "PUT" {
					repairs++
					var body map[string]any
					decoder := json.NewDecoder(r.Body)
					decoder.UseNumber()
					if decoder.Decode(&body) != nil {
						t.Error("repair body")
					}
					for _, raw := range current["attachments"].([]any) {
						row := raw.(map[string]any)
						desired := body["attachments2"].(map[string]any)[row["id"].(string)].(map[string]any)
						row["key"], row["fileName"] = desired["key"], desired["fileName"]
					}
					json.NewEncoder(w).Encode(current)
					return
				}
				t.Error("unexpected request", r.Method, r.URL.Path)
				w.WriteHeader(404)
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			ownerKey := bytes.Clone(s.key)
			defer clear(ownerKey)
			personal, err := NewPersonalCipher(CipherFields{Type: 1, Name: "legacy", Login: map[string]any{"password": "legacy password"}}, s.key, s.account)
			if err != nil {
				t.Fatal(err)
			}
			current, _ = documentObject(personal)
			itemKey, _ := cipherItemKey(current, s.key)
			if err = transformCipher(current, itemKey, false); err != nil {
				t.Fatal(err)
			}
			clear(itemKey)
			if err = transformCipher(current, s.key, true); err != nil {
				t.Fatal(err)
			}
			delete(current, "key")
			current["id"], current["edit"], current["viewPassword"], current["revisionDate"] = "share-me", true, true, "2026-06-01T00:00:00Z"
			attachments := []any{}
			for _, id := range []string{"file-a", "file-b"} {
				name, _ := vaultcrypto.EncryptString([]byte("same-name.txt"), s.key)
				key, _ := vaultcrypto.EncryptString(bytes.Repeat([]byte{7}, 64), s.key)
				attachments = append(attachments, map[string]any{"id": id, "fileName": name, "key": key, "size": 81})
			}
			current["attachments"] = attachments
			install := func(revision string) {
				mu.Lock()
				defer mu.Unlock()
				var sync map[string]json.RawMessage
				json.Unmarshal(vault.Sync, &sync)
				sync["ciphers"], _ = json.Marshal([]any{current})
				vault.Sync, _ = json.Marshal(sync)
				installFixtureSnapshot(t, s, vault, revision)
			}
			install("legacy-before")
			personal.JSON, _ = json.Marshal(current)
			fields, err := DecryptCipherDocument(personal, s.key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.SharePersonalCipher(context.Background(), vault, "org-1", "collection-1", personal, fields, nil, nil); err != ErrUnsupportedEdit || shares != 0 {
				t.Fatal("unprotected legacy attachment share", err)
			}
			var recovery []byte
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err = s.SharePersonalCipherWithRecovery(ctx, vault, "org-1", "collection-1", personal, fields, nil, nil, func(data []byte) error {
				recovery = bytes.Clone(data)
				if scenario == "persist-failure" {
					return errors.New("disk failure")
				}
				if scenario == "cancel-after-persist" {
					cancel()
				}
				return nil
			})
			if err == nil {
				t.Fatal("injected failure missing")
			}
			if scenario == "persist-failure" || scenario == "cancel-after-persist" {
				if shares != 0 {
					t.Fatal("share sent without durable recovery")
				}
				s.Close()
				clear(recovery)
				return
			}
			if shares != 1 || len(recovery) == 0 || bytes.Contains(recovery, []byte("legacy password")) {
				t.Fatal("missing encrypted recovery barrier")
			}
			// Rebuild the Session after dropping all migration-local keys. The only
			// source of the target key is now the account-bound encrypted file.
			s.Close()
			s, _ = resumableFixture(t, server.URL)
			s.key = bytes.Clone(ownerKey)
			defer s.Close()
			if scenario == "external-edit" {
				mu.Lock()
				current["name"], _ = vaultcrypto.EncryptString([]byte("external change"), s.key)
				mu.Unlock()
			}
			if scenario == "missing-attachment" {
				mu.Lock()
				current["attachments"] = current["attachments"].([]any)[:1]
				mu.Unlock()
			}
			if scenario == "attachment-changed" {
				mu.Lock()
				current["attachments"].([]any)[0].(map[string]any)["size"] = json.Number("97")
				mu.Unlock()
			}
			if scenario == "unknown-null" {
				mu.Lock()
				current["futureExtension"] = nil
				mu.Unlock()
			}
			install("after-restart")
			inspection, err := s.InspectCipherShareRecovery(context.Background(), vault, recovery, nil, nil)
			if err != nil {
				t.Fatal("inspect", err)
			}
			if scenario == "response-lost" {
				if inspection.CipherState != ShareRecoveryNewOrganization || inspection.CanRepair {
					t.Fatal("committed share misclassified", inspection)
				}
				return
			}
			if scenario == "external-edit" || scenario == "missing-attachment" || scenario == "attachment-changed" || scenario == "unknown-null" {
				if inspection.CanRepair {
					t.Fatal("unsafe repair offered")
				}
				if err = s.RepairCipherShareRecovery(context.Background(), vault, recovery, true, nil, nil); err == nil || repairs != 0 {
					t.Fatal("external data overwritten")
				}
				return
			}
			if !inspection.CanRepair {
				t.Fatal("mixed wrappers not repairable", inspection)
			}
			if err = s.RepairCipherShareRecovery(context.Background(), vault, recovery, true, nil, nil); err != nil {
				t.Fatal("repair", err)
			}
			install("after-repair")
			inspection, err = s.InspectCipherShareRecovery(context.Background(), vault, recovery, nil, nil)
			if err != nil || inspection.CanRepair || repairs != 1 {
				t.Fatal("repair not reconciled", inspection, err)
			}
			desired := ShareRecoveryOldPersonal
			if scenario == "new-cipher-mixed" {
				desired = ShareRecoveryNewOrganization
			}
			if inspection.CipherState != desired {
				t.Fatal("ownership changed during repair")
			}
			for _, alter := range []string{"header", "ciphertext", "wrong-key"} {
				var file cipherShareRecoveryFile
				json.Unmarshal(recovery, &file)
				key := ownerKey
				switch alter {
				case "header":
					file.CipherID = "other"
				case "ciphertext":
					file.Ciphertext = file.Ciphertext[:len(file.Ciphertext)-1] + "A"
				case "wrong-key":
					key = bytes.Repeat([]byte{99}, 64)
				}
				encoded, _ := json.Marshal(file)
				if _, err := decodeCipherShareRecovery(encoded, vault.Scope, key); err == nil {
					t.Fatal("tampered recovery accepted", alter)
				}
			}
			clear(recovery)
		})
	}
}
