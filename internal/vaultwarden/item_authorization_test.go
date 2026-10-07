// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func protectedItemFixture(t *testing.T, endpoint string) (*Session, *VaultData, CipherDocument) {
	t.Helper()
	s, config := resumableFixture(t, endpoint)
	doc, key := cipherDocumentFixture(t, 1)
	clear(s.key)
	s.key = key
	object, _ := documentObject(doc)
	object["reprompt"] = 1
	doc.JSON, _ = json.Marshal(object)
	clear(s.passwordUnlock.Key)
	s.passwordUnlock.Key, _ = DeriveSnapshotUnlockKey([]byte("test-master"), config)
	scope := Scope{Server: endpoint, Account: "account-a"}
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account}, "ciphers": []json.RawMessage{doc.JSON}})
	vault := &VaultData{Version: 1, Scope: scope, Sync: raw}
	if err := s.BindSnapshotRevision(scope, "local-revision"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, vault, doc
}
func TestItemAuthorizationPasswordAndScope(t *testing.T) {
	s, vault, doc := protectedItemFixture(t, "https://vault.example.invalid")
	if _, _, err := s.ReadPersonalCipherAuthorized(vault, "item-1", nil); err != ErrPermission {
		t.Fatal("reprompt bypass", err)
	}
	if _, err := s.AuthorizePersonalItem(context.Background(), vault, "local-revision", "item-1", []byte("wrong")); err != ErrPermission {
		t.Fatal("wrong password", err)
	}
	grant, err := s.AuthorizePersonalItem(context.Background(), vault, "local-revision", "item-1", []byte("test-master"))
	if err != nil {
		t.Fatal(err)
	}
	_, fields, err := s.ReadPersonalCipherAuthorized(vault, "item-1", grant)
	if err != nil || fields.Reprompt != 1 {
		t.Fatal("authorized read must retain reprompt", err)
	}
	if _, err := EncryptCipherDocument(doc, fields, s.key, s.account); err != ErrPermission {
		t.Fatal("public encrypt bypassed reprompt", err)
	}
	other, otherVault, _ := protectedItemFixture(t, "https://vault.example.invalid")
	if _, _, err := other.ReadPersonalCipherAuthorized(otherVault, "item-1", grant); err != ErrPermission {
		t.Fatal("cross-session grant accepted")
	}
	for _, change := range []func(map[string]any){func(o map[string]any) { o["viewPassword"] = false }, func(o map[string]any) { o["organizationId"] = "organization" }, func(o map[string]any) { o["revisionDate"] = "2026-06-01T00:00:00Z" }} {
		o, _ := documentObject(doc)
		change(o)
		changed, _ := json.Marshal(o)
		raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": vault.Scope.Account}, "ciphers": []json.RawMessage{changed}})
		altered := &VaultData{Version: 1, Scope: vault.Scope, Sync: raw}
		if _, _, err := s.ReadPersonalCipherAuthorized(altered, "item-1", grant); err != ErrPermission {
			t.Fatal("document substitution accepted", err)
		}
	}
	grant.expires = time.Now()
	if _, _, err := s.ReadPersonalCipherAuthorized(vault, "item-1", grant); err != ErrPermission {
		t.Fatal("expired grant accepted")
	}
}
func TestItemAuthorizationRevocation(t *testing.T) {
	for _, scenario := range []string{"revision", "revoke", "close", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			s, vault, _ := protectedItemFixture(t, "https://vault.example.invalid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			grant, err := s.AuthorizePersonalItem(ctx, vault, "local-revision", "item-1", []byte("test-master"))
			if scenario == "cancel" {
				if err != ErrCancelled {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "revision":
				_ = s.BindSnapshotRevision(vault.Scope, "new-revision")
			case "revoke":
				s.RevokeItemAuthorizations()
			case "close":
				s.Close()
			}
			if _, _, err := s.ReadPersonalCipherAuthorized(vault, "item-1", grant); err == nil {
				t.Fatal("revoked grant accepted")
			}
		})
	}
}
func TestAuthorizedWriteAndCheckpointExpiry(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "checkpoint-expiry"}[expire], func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				if r.Method != "PUT" || r.URL.Path != "/api/ciphers/item-1" {
					t.Error("wrong request")
				}
				var raw json.RawMessage
				_ = json.NewDecoder(r.Body).Decode(&raw)
				var metadata struct{ Reprompt int }
				_ = json.Unmarshal(raw, &metadata)
				if metadata.Reprompt != 1 {
					t.Error("reprompt removed")
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			s, vault, doc := protectedItemFixture(t, server.URL)
			grant, err := s.AuthorizePersonalItem(context.Background(), vault, "local-revision", "item-1", []byte("test-master"))
			if err != nil {
				t.Fatal(err)
			}
			_, fields, err := s.ReadPersonalCipherAuthorized(vault, "item-1", grant)
			if err != nil {
				t.Fatal(err)
			}
			fields.Name = "edited"
			if expire {
				s.checkpointPending = true
			}
			_, err = s.UpdatePersonalCipherAuthorized(context.Background(), vault.Scope, doc, fields, grant, func(SessionCheckpoint) error { grant.expires = time.Now(); return nil })
			if expire {
				if err != ErrPermission || writes.Load() != 0 {
					t.Fatal("expired grant dispatched", err)
				}
			} else if err != nil || writes.Load() != 1 {
				t.Fatal("authorized write failed", err)
			}
		})
	}
}
