// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestOrgCopyEightTypesAcrossKeys(t *testing.T) {
	targetKey := bytes.Repeat([]byte{73}, 64)
	for kind := 1; kind <= 8; kind++ {
		t.Run(cipherSections[kind], func(t *testing.T) {
			source, sourceKey := copyFixture(t, kind)
			object, _ := documentObject(source)
			object["organizationId"] = "org-source"
			object["collectionIds"] = []string{"collection-source"}
			source.JSON, _ = json.Marshal(object)
			before := append([]byte(nil), source.JSON...)
			copied, err := copyOrganizationDocument(source, sourceKey, targetKey, "account-a", "org-target", false)
			if err != nil {
				t.Fatal(err)
			}
			original, err := DecryptCipherDocument(source, sourceKey)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := DecryptCipherDocument(copied, targetKey)
			if err != nil {
				t.Fatal(err)
			}
			original.ID, original.RevisionDate = "", ""
			original.Edit, original.ViewPassword = false, false
			original.ArchivedDate, original.DeletedDate, original.FolderID = nil, nil, nil
			target := "org-target"
			original.OrganizationID = &target
			if !reflect.DeepEqual(original, actual) {
				t.Fatal("standard field lost")
			}
			obj, _ := documentObject(copied)
			oldKey, _ := cipherItemKey(object, sourceKey)
			newKey, _ := cipherItemKey(obj, targetKey)
			if bytes.Equal(oldKey, newKey) || bytes.Equal(targetKey, newKey) {
				t.Fatal("key reused")
			}
			clear(oldKey)
			clear(newKey)
			if !bytes.Equal(source.JSON, before) {
				t.Fatal("source mutated")
			}
		})
	}
}
func TestOrgCopyRejectsUnknownAndAttachmentBeforeHTTP(t *testing.T) {
	for _, name := range []string{"futureExtension", "attachments", "fido2Credentials"} {
		t.Run(name, func(t *testing.T) {
			source, key := copyFixture(t, 1)
			obj, _ := documentObject(source)
			obj["organizationId"] = "org-1"
			obj["collectionIds"] = []string{"collection-1"}
			switch name {
			case "futureExtension":
				obj[name] = json.Number("9007199254740993")
			case "attachments":
				obj[name] = []any{map[string]any{"id": "attachment-1"}}
			case "fido2Credentials":
				obj["login"].(map[string]any)[name] = []any{map[string]any{"credentialId": "opaque"}}
			}
			source.JSON, _ = json.Marshal(obj)
			if _, err := copyOrganizationDocument(source, key, key, "account-a", "org-2", false); err != ErrUnsupportedEdit {
				t.Fatal(err)
			}
		})
	}
}
func TestOrgCopyUsesOrganizationCreate(t *testing.T) {
	var live json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			data := organizationPolicySyncFixture()
			data["ciphers"] = []json.RawMessage{live}
			_ = json.NewEncoder(w).Encode(data)
			return
		}
		if r.URL.Path != "/api/ciphers/create" || r.Method != "POST" {
			t.Error("wrong copy route")
		}
		var body struct {
			Cipher        map[string]json.RawMessage
			CollectionIDs []string
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.CollectionIDs) != 1 || body.CollectionIDs[0] != "collection-1" {
			t.Error("copy target")
		}
		body.Cipher["id"] = json.RawMessage(`"new-item"`)
		_ = json.NewEncoder(w).Encode(body.Cipher)
	}))
	defer server.Close()
	s, v, _, doc := organizationFixture(t, server.URL)
	defer s.Close()
	live = doc.JSON
	result, err := s.CopyOrganizationCipher(context.Background(), v, "item-org", "org-1", "collection-1", nil, nil)
	if err != nil || len(result.JSON) == 0 {
		t.Fatal(err)
	}
}
