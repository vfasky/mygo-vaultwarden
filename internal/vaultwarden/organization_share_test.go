// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestOrganizationShareRewrapsIndependentKeyAndPreservesOpaqueData(t *testing.T) {
	var source map[string]any
	var orgKey, originalItemKey []byte
	var requests atomic.Int32
	server := newOrganizationPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "PUT" || r.URL.Path != "/api/ciphers/share-me/share" {
			t.Error("share route")
		}
		var body struct {
			Cipher        json.RawMessage
			CollectionIDs []string
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("share body")
		}
		object, err := documentObject(CipherDocument{JSON: body.Cipher})
		if err != nil {
			t.Error(err)
		}
		if len(body.CollectionIDs) != 1 || body.CollectionIDs[0] != "collection-1" || object["organizationId"] != "org-1" || object["encryptedFor"] != "account-a" {
			t.Error("share target")
		}
		rewrapped, err := cipherItemKey(object, orgKey)
		if err != nil || !bytes.Equal(rewrapped, originalItemKey) || object["key"] == source["key"] {
			t.Error("item key not rewrapped", err)
		}
		for _, field := range []string{"attachments", "opaque"} {
			if !reflect.DeepEqual(object[field], source[field]) {
				t.Error("opaque lost", field)
			}
		}
		if !reflect.DeepEqual(object["login"].(map[string]any)["fido2Credentials"], source["login"].(map[string]any)["fido2Credentials"]) {
			t.Error("FIDO2 opaque lost")
		}
		_, _ = w.Write(body.Cipher)
	}))
	defer server.Close()
	s, vault, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	orgKey = key
	personal, err := NewPersonalCipher(CipherFields{Type: 1, Name: "shared", Login: map[string]any{"password": "personal secret"}}, s.key, s.account)
	if err != nil {
		t.Fatal(err)
	}
	source, _ = documentObject(personal)
	source["id"], source["edit"], source["viewPassword"], source["revisionDate"] = "share-me", true, true, "2026-06-01T00:00:00Z"
	originalItemKey, err = cipherItemKey(source, s.key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(originalItemKey)
	attachmentKey, _ := vaultcrypto.EncryptString(bytes.Repeat([]byte{17}, 64), originalItemKey)
	filename, _ := vaultcrypto.EncryptString([]byte("fixture.txt"), originalItemKey)
	source["attachments"] = []any{map[string]any{"id": "attachment-1", "key": attachmentKey, "fileName": filename, "size": json.Number("96")}}
	source["login"].(map[string]any)["fido2Credentials"] = []any{map[string]any{"opaque": "encrypted-future-format"}}
	source["opaque"] = map[string]any{"large": json.Number("9007199254740993")}
	personal.JSON, _ = json.Marshal(source)
	// Avoid a float64 JSON roundtrip when testing preservation of large values.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(vault.Sync, &raw)
	raw["ciphers"], _ = json.Marshal([]json.RawMessage{personal.JSON})
	vault.Sync, _ = json.Marshal(raw)
	installFixtureSnapshot(t, s, vault, "revision-1")
	fields, err := DecryptCipherDocument(personal, s.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SharePersonalCipher(context.Background(), vault, "org-1", "collection-1", personal, fields, nil, nil); err != nil || requests.Load() != 1 {
		t.Fatal("share", err)
	}
	if _, err := s.SharePersonalCipher(context.Background(), vault, "org-other", "collection-1", personal, fields, nil, nil); err != ErrPermission || requests.Load() != 1 {
		t.Fatal("cross-org share", err)
	}
	// A legacy item encrypted with the account key cannot export that account key.
	if err := transformCipher(source, originalItemKey, false); err != nil {
		t.Fatal(err)
	}
	if err := transformCipher(source, s.key, true); err != nil {
		t.Fatal(err)
	}
	delete(source, "key")
	personal.JSON, _ = json.Marshal(source)
	raw["ciphers"], _ = json.Marshal([]json.RawMessage{personal.JSON})
	vault.Sync, _ = json.Marshal(raw)
	installFixtureSnapshot(t, s, vault, "revision-1")
	if _, err := s.SharePersonalCipher(context.Background(), vault, "org-1", "collection-1", personal, fields, nil, nil); err != ErrUnsupportedEdit || requests.Load() != 1 {
		t.Fatal("legacy shared account key", err)
	}
}

func TestOrganizationSharePartialFailureAndCreationPermissions(t *testing.T) {
	var requests atomic.Int32
	server := newOrganizationPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusBadRequest) }))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	fields := CipherFields{Type: 2, Name: "new organization note"}
	_, err := s.CreateOrganizationCipher(context.Background(), vault, "org-1", "collection-1", fields, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || requests.Load() != 1 {
		t.Fatal("nontransactional failure not uncertain", err)
	}
	for _, field := range []string{"ReadOnly", "HidePasswords"} {
		v := changeOrganizationFixture(t, vault, func(d map[string]any) { d["collections"].([]any)[0].(map[string]any)[field] = true })
		installFixtureSnapshot(t, s, v, "revision-1")
		if _, err := s.CreateOrganizationCipher(context.Background(), v, "org-1", "collection-1", fields, nil); err != ErrPermission || requests.Load() != 1 {
			t.Fatal("restricted destination", field, err)
		}
	}
}
