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
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func copyFixture(t *testing.T, kind int) (CipherDocument, []byte) {
	t.Helper()
	doc, key := cipherDocumentFixture(t, kind)
	object, _ := documentObject(doc)
	delete(object, "futureExtension")
	if kind == 1 {
		login := object["login"].(map[string]any)
		delete(login, "fido2Credentials")
		uri := login["uris"].([]any)[0].(map[string]any)
		checksum, err := vaultcrypto.EncryptString([]byte("fixture checksum"), key)
		if err != nil {
			t.Fatal(err)
		}
		uri["uriChecksum"] = checksum
		login["uri"] = uri["uri"]
	}
	object["folderId"], object["favorite"] = "folder-1", true
	object["archivedDate"], object["deletedDate"] = "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"
	doc.JSON, _ = json.Marshal(object)
	return doc, key
}
func TestCopyEightTypesRekeysEveryKnownSecret(t *testing.T) {
	for kind := 1; kind <= 8; kind++ {
		t.Run(cipherSections[kind], func(t *testing.T) {
			source, key := copyFixture(t, kind)
			before := append([]byte(nil), source.JSON...)
			copy, err := copyPersonalCipherDocument(source, key, "account-a")
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecryptCipherDocument(copy, key)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := DecryptCipherDocument(source, key)
			original.ID, original.RevisionDate = "", ""
			original.Edit, original.ViewPassword = false, false
			original.ArchivedDate, original.DeletedDate = nil, nil
			if !reflect.DeepEqual(original, got) {
				t.Fatalf("copy changed fields: %#v %#v", original, got)
			}
			a, _ := documentObject(source)
			b, _ := documentObject(copy)
			oldKey, _ := cipherItemKey(a, key)
			newKey, _ := cipherItemKey(b, key)
			if bytes.Equal(oldKey, newKey) || bytes.Equal(newKey, key) {
				t.Fatal("copy reused key")
			}
			if _, err := vaultcrypto.DecryptString(b["name"].(string), oldKey); err == nil {
				t.Fatal("copy still decrypts under source key")
			}
			if b["encryptedFor"] != "account-a" || !bytes.Equal(before, source.JSON) {
				t.Fatal("source changed or unbound copy")
			}
			if bytes.Contains(copy.JSON, []byte("old password")) {
				t.Fatal("history leaked")
			}
		})
	}
}
func TestCopyRefusesOpaqueDataWithoutMutation(t *testing.T) {
	for _, scenario := range []string{"top", "section", "uri", "custom", "history", "attachment", "fido", "keyID", "organization", "reprompt", "permission"} {
		t.Run(scenario, func(t *testing.T) {
			source, key := copyFixture(t, 1)
			o, _ := documentObject(source)
			switch scenario {
			case "top":
				o["future"] = nil
			case "section":
				o["login"].(map[string]any)["future"] = "opaque"
			case "uri":
				o["login"].(map[string]any)["uris"].([]any)[0].(map[string]any)["future"] = "opaque"
			case "custom":
				o["fields"].([]any)[0].(map[string]any)["future"] = "opaque"
			case "history":
				o["passwordHistory"].([]any)[0].(map[string]any)["future"] = "opaque"
			case "attachment":
				o["attachments"] = []any{map[string]any{"id": "file"}}
			case "fido":
				o["login"].(map[string]any)["fido2Credentials"] = []any{map[string]any{"keyValue": "opaque"}}
			case "keyID":
				o["encryptedByKeyId"] = "old-key"
			case "organization":
				o["organizationId"] = "org"
			case "reprompt":
				o["reprompt"] = 1
			case "permission":
				o["viewPassword"] = false
			}
			source.JSON, _ = json.Marshal(o)
			before := append([]byte(nil), source.JSON...)
			if _, err := copyPersonalCipherDocument(source, key, "account-a"); err == nil {
				t.Fatal("unsafe copy accepted")
			}
			if !bytes.Equal(before, source.JSON) {
				t.Fatal("source mutated")
			}
		})
	}
}
func TestCopySessionCheckpointAndUnknownResult(t *testing.T) {
	source, key := copyFixture(t, 1)
	fields, _ := DecryptCipherDocument(source, key)
	calls := 0
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/ciphers" {
			t.Error("wrong copy route")
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["id"] != nil || body["lastKnownRevisionDate"] != nil {
			t.Error("source identity copied")
		}
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = key
	scope := Scope{Server: server.URL, Account: "account-a"}
	s.checkpointPending = true
	if _, err := s.CopyPersonalCipher(context.Background(), scope, source, fields, nil); !errors.Is(err, ErrCheckpoint) {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("checkpoint bypass")
	}
	s.checkpointPending = false
	_, err := s.CopyPersonalCipher(context.Background(), scope, source, fields, nil)
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) || calls != 1 {
		t.Fatal("unknown copy retried", err, calls)
	}
}

func TestCopyDraftRekeysWrappedItemAndLegacyURI(t *testing.T) {
	source, ownerKey := copyFixture(t, 1)
	object, _ := documentObject(source)
	itemKey := bytes.Repeat([]byte{91}, 64)
	if err := transformCipher(object, ownerKey, false); err != nil {
		t.Fatal(err)
	}
	if err := transformCipher(object, itemKey, true); err != nil {
		t.Fatal(err)
	}
	object["key"], _ = vaultcrypto.EncryptString(itemKey, ownerKey)
	source.JSON, _ = json.Marshal(object)
	before := append([]byte(nil), source.JSON...)
	fields, err := DecryptCipherDocument(source, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	fields.Login["password"] = "draft password"
	fields.Login["uris"].([]any)[0].(map[string]any)["uri"] = "https://edited.example.invalid/"
	var sent CipherDocument
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.JSON, _ = io.ReadAll(r.Body)
		payload, err := documentObject(sent)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		payload["id"] = "copied-id"
		json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = ownerKey
	result, err := s.CopyPersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, source, fields, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptCipherDocument(result, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login["uri"] != "https://edited.example.invalid/" || got.Login["uris"].([]any)[0].(map[string]any)["uri"] != got.Login["uri"] || got.Login["password"] != "draft password" || len(got.PasswordHistory) != 2 || got.PasswordHistory[0]["password"] != "original password" {
		t.Fatal("draft/alias/history lost")
	}
	payload, _ := documentObject(sent)
	newKey, _ := cipherItemKey(payload, ownerKey)
	if bytes.Equal(newKey, itemKey) || bytes.Equal(newKey, ownerKey) {
		t.Fatal("key reused")
	}
	if _, err := vaultcrypto.DecryptString(payload["login"].(map[string]any)["uri"].(string), itemKey); err == nil {
		t.Fatal("legacy URI still under source key")
	}
	if !bytes.Equal(before, source.JSON) {
		t.Fatal("source modified")
	}
}

func TestCopyRefusesUnknownSourceBeforeRequestEvenIfDraftDropsIt(t *testing.T) {
	source, key := copyFixture(t, 1)
	object, _ := documentObject(source)
	object["fields"].([]any)[0].(map[string]any)["future"] = "opaque"
	source.JSON, _ = json.Marshal(object)
	fields, _ := DecryptCipherDocument(source, key)
	fields.Fields = nil
	var calls atomic.Int32
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = key
	scope := Scope{Server: server.URL, Account: "account-a"}
	if _, err := s.CopyPersonalCipher(context.Background(), scope, source, fields, nil); !errors.Is(err, ErrUnsupportedEdit) {
		t.Fatal(err)
	}
	scope.Account = "different-account"
	if _, err := s.CopyPersonalCipher(context.Background(), scope, source, fields, nil); !errors.Is(err, ErrIdentity) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe request sent")
	}
}

func TestCopyRejectsResponseWithSourceIdentity(t *testing.T) {
	source, key := copyFixture(t, 1)
	fields, _ := DecryptCipherDocument(source, key)
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(source.JSON) }))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = key
	_, err := s.CopyPersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, source, fields, nil)
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) || !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong response identity accepted", err)
	}
}

func TestCloseCancelsCopyWithoutDuplicateCreation(t *testing.T) {
	source, key := copyFixture(t, 1)
	fields, _ := DecryptCipherDocument(source, key)
	entered := make(chan struct{})
	var calls atomic.Int32
	server := newPersonalPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.key = key
	done := make(chan error, 1)
	go func() {
		_, err := s.CopyPersonalCipher(context.Background(), Scope{Server: server.URL, Account: "account-a"}, source, fields, nil)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request not sent")
	}
	s.Close()
	select {
	case err := <-done:
		var unknown *MutationUncertainError
		if !errors.As(err, &unknown) || !errors.Is(err, ErrCancelled) || calls.Load() != 1 {
			t.Fatal("cancelled write retried or reported definite failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("copy not cancelled")
	}
}
