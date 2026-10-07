// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestCipherUpdateRecognizesOnlyExactUpstreamConflict(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{400, `{"message":"The client copy of this cipher is out of date. Resync the client and try again."}`, ErrConflict},
		{400, `{"message":"secret server detail out of date"}`, ErrValidation},
		{400, `not json`, ErrValidation},
		{403, `{"message":"The client copy of this cipher is out of date. Resync the client and try again."}`, ErrPermission},
		{http.StatusConflict, `{}`, ErrConflict},
	} {
		if err := cipherUpdateStatusError(tc.status, []byte(tc.body)); !errors.Is(err, tc.want) {
			t.Fatal("wrong classification", err)
		}
	}
}

func rebaseVault(t *testing.T, s *Session, doc CipherDocument) *VaultData {
	t.Helper()
	scope := Scope{Server: s.client.base.String(), Account: s.account}
	raw, err := json.Marshal(map[string]any{"profile": map[string]any{"id": scope.Account}, "ciphers": []json.RawMessage{doc.JSON}})
	if err != nil {
		t.Fatal(err)
	}
	return &VaultData{Version: 1, Scope: scope, Sync: raw}
}
func rebaseRemote(t *testing.T, doc CipherDocument, key []byte, change func(map[string]any)) CipherDocument {
	t.Helper()
	object, err := documentObject(doc)
	if err != nil {
		t.Fatal(err)
	}
	itemKey, err := cipherItemKey(object, key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(itemKey)
	if err := transformCipher(object, itemKey, false); err != nil {
		t.Fatal(err)
	}
	object["revisionDate"] = "2026-01-02T00:00:00Z"
	change(object)
	if err := transformCipher(object, itemKey, true); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return CipherDocument{JSON: raw}
}
func TestCipherRebaseEightTypesPreserveRemoteOpaqueAndLocalChoice(t *testing.T) {
	for kind := 1; kind <= 8; kind++ {
		t.Run(cipherSections[kind], func(t *testing.T) {
			s, _, _ := protectedItemFixture(t, "https://vault.example.invalid")
			base, key := cipherDocumentFixture(t, kind)
			clear(s.key)
			s.key = key
			draft, err := DecryptCipherDocument(base, key)
			if err != nil {
				t.Fatal(err)
			}
			draft.Name = "local secret name"
			remote := rebaseRemote(t, base, key, func(o map[string]any) {
				o["notes"] = "remote secret notes"
				o["futureExtension"] = "NEW opaque encrypted"
				o[cipherSections[kind]].(map[string]any)["newOpaque"] = "NEW nested encrypted"
			})
			vault := rebaseVault(t, s, remote)
			installFixtureSnapshot(t, s, vault, "new")
			plan, changes, err := s.ComparePersonalCipher(vault, "new", base, draft, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(changes) != 2 || changes[0].Path != "name" || !changes[0].Local || changes[0].Remote || changes[1].Path != "notes" || !changes[1].Remote {
				t.Fatal(changes)
			}
			metadata, _ := json.Marshal(changes)
			if string(metadata) == "" {
				t.Fatal("metadata")
			}
			doc, result, err := s.ApplyPersonalCipherComparison(vault, "new", plan, []string{"name"})
			if err != nil {
				t.Fatal(err)
			}
			if result.Name != draft.Name || *result.Notes != "remote secret notes" || result.RevisionDate != "2026-01-02T00:00:00Z" {
				t.Fatal("wrong merge")
			}
			encrypted, err := EncryptCipherDocument(doc, result, key, s.account)
			if err != nil {
				t.Fatal(err)
			}
			object, _ := documentObject(encrypted)
			if object["futureExtension"] != "NEW opaque encrypted" || object[cipherSections[kind]].(map[string]any)["newOpaque"] != "NEW nested encrypted" {
				t.Fatal("unknown fields overwritten")
			}
			_, adopted, err := s.ApplyPersonalCipherComparison(vault, "new", plan, nil)
			if err != nil || adopted.Name == draft.Name {
				t.Fatal("remote choice did not discard local", err)
			}
		})
	}
}
func TestCipherRebaseHistoryRemovesOnlyObservedRecords(t *testing.T) {
	s, _, _ := protectedItemFixture(t, "https://vault.example.invalid")
	base, key := cipherDocumentFixture(t, 1)
	s.key = key
	draft, _ := DecryptCipherDocument(base, key)
	draft.PasswordHistory = nil
	draft.Login["password"] = "local replacement"
	remote := rebaseRemote(t, base, key, func(o map[string]any) {
		o["passwordHistory"] = append([]any{map[string]any{"password": "new remote history", "lastUsedDate": "2026-01-02T00:00:00Z", "extra": "remote extension"}}, o["passwordHistory"].([]any)...)
		o["login"].(map[string]any)["password"] = "remote current password"
	})
	vault := rebaseVault(t, s, remote)
	installFixtureSnapshot(t, s, vault, "new")
	plan, _, err := s.ComparePersonalCipher(vault, "new", base, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, fields, err := s.ApplyPersonalCipherComparison(vault, "new", plan, []string{"passwordHistory", "login.password"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fields.PasswordHistory) != 1 || fields.PasswordHistory[0]["password"] != "new remote history" || fields.PasswordHistory[0]["extra"] != "remote extension" {
		t.Fatal("remote history lost")
	}
	saved, err := EncryptCipherDocument(doc, fields, key, s.account)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := DecryptCipherDocument(saved, key)
	if len(result.PasswordHistory) != 2 || result.PasswordHistory[0]["password"] != "remote current password" {
		t.Fatal("did not record current remote password")
	}
}
func TestCipherRebaseRejectsUnsafeTransitionsAndStalePlans(t *testing.T) {
	for _, test := range []string{"deleted", "organization", "permission", "viewPassword", "key", "missing", "revision", "closed", "changedAgain"} {
		t.Run(test, func(t *testing.T) {
			s, _, _ := protectedItemFixture(t, "https://vault.example.invalid")
			base, key := cipherDocumentFixture(t, 1)
			s.key = key
			draft, _ := DecryptCipherDocument(base, key)
			draft.Name = "local"
			remote := rebaseRemote(t, base, key, func(o map[string]any) {
				switch test {
				case "deleted":
					o["deletedDate"] = "2026-01-02T00:00:00Z"
				case "organization":
					o["organizationId"] = "organization"
				case "permission":
					o["edit"] = false
				case "viewPassword":
					o["viewPassword"] = false
				case "key":
					o["key"], _ = EncryptString(make([]byte, 64), key)
				}
			})
			vault := rebaseVault(t, s, remote)
			installFixtureSnapshot(t, s, vault, "new")
			if test == "missing" {
				vault.Sync = json.RawMessage(`{"profile":{"id":"account-a"},"ciphers":[]}`)
			}
			plan, _, err := s.ComparePersonalCipher(vault, "new", base, draft, nil)
			if test == "revision" || test == "closed" || test == "changedAgain" {
				if err != nil {
					t.Fatal(err)
				}
				switch test {
				case "revision":
					_ = s.BindSnapshotRevision(vault.Scope, "newer")
				case "closed":
					s.Close()
				case "changedAgain":
					remote = rebaseRemote(t, remote, key, func(o map[string]any) { o["name"] = "newest" })
					vault = rebaseVault(t, s, remote)
				}
				_, _, err = s.ApplyPersonalCipherComparison(vault, "new", plan, []string{"name"})
			}
			if err == nil {
				t.Fatal("unsafe comparison accepted")
			}
		})
	}
}
func TestCipherRebaseFreshRepromptGrantAndExpiry(t *testing.T) {
	s, vault, base := protectedItemFixture(t, "https://vault.example.invalid")
	old, err := s.AuthorizePersonalItem(context.Background(), vault, "local-revision", "item-1", []byte("test-master"))
	if err != nil {
		t.Fatal(err)
	}
	_, draft, err := s.ReadPersonalCipherAuthorized(vault, "item-1", old)
	if err != nil {
		t.Fatal(err)
	}
	draft.Name = "local"
	remote := rebaseRemote(t, base, s.key, func(o map[string]any) { o["notes"] = "remote" })
	vault = rebaseVault(t, s, remote)
	installFixtureSnapshot(t, s, vault, "new")
	for _, grant := range []*ItemAuthorization{nil, old} {
		if _, _, err := s.ComparePersonalCipher(vault, "new", base, draft, grant); err != ErrPermission {
			t.Fatal("stale grant accepted", err)
		}
	}
	fresh, err := s.AuthorizePersonalItem(context.Background(), vault, "new", "item-1", []byte("test-master"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := s.ComparePersonalCipher(vault, "new", base, draft, fresh)
	if err != nil {
		t.Fatal(err)
	}
	fresh.expires = time.Now()
	if _, _, err := s.ApplyPersonalCipherComparison(vault, "new", plan, []string{"name"}); err != ErrPermission {
		t.Fatal("expired plan accepted", err)
	}
}
func TestCipherRebaseConcurrentArraysRetainRemoteExtensions(t *testing.T) {
	s, _, _ := protectedItemFixture(t, "https://vault.example.invalid")
	base, key := cipherDocumentFixture(t, 1)
	s.key = key
	draft, _ := DecryptCipherDocument(base, key)
	draft.Fields = nil
	draft.Login["uris"] = []any{}
	remote := rebaseRemote(t, base, key, func(o map[string]any) {
		o["fields"].([]any)[0].(map[string]any)["future"] = "opaque"
		uris := o["login"].(map[string]any)["uris"].([]any)
		uris[0].(map[string]any)["future"] = "opaque URI"
		o["login"].(map[string]any)["uris"] = append(uris, map[string]any{"uri": "https://remote-new.example.invalid", "future": "new opaque URI"})
		o["fields"] = append(o["fields"].([]any), map[string]any{"name": "remote-added", "value": "new secret", "type": json.Number("1"), "future": "new opaque field"})
	})
	vault := rebaseVault(t, s, remote)
	installFixtureSnapshot(t, s, vault, "new")
	plan, changes, err := s.ComparePersonalCipher(vault, "new", base, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if !c.Local || !c.Remote || c.CanApply {
			t.Fatal(c)
		}
	}
	for _, path := range []string{"fields", "login.uris"} {
		if _, _, err := s.ApplyPersonalCipherComparison(vault, "new", plan, []string{path}); !errors.Is(err, ErrUnsupportedEdit) {
			t.Fatal(err)
		}
	}
	_, adopted, err := s.ApplyPersonalCipherComparison(vault, "new", plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := DecryptCipherDocument(remote, key)
	if !reflect.DeepEqual(adopted.Fields, expected.Fields) || !reflect.DeepEqual(adopted.Login, expected.Login) {
		t.Fatal("remote array changed")
	}
}
