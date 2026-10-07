// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"testing"
)

func cipherDocumentFixture(t *testing.T, kind int) (CipherDocument, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{19}, 64)
	enc := func(s string) string {
		v, e := EncryptString([]byte(s), key)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	section := cipherSections[kind]
	detail := map[string]any{}
	for _, name := range cipherSecrets[section] {
		detail[name] = enc("original " + name)
	}
	if kind == 1 {
		detail["uris"] = []any{map[string]any{"uri": enc("https://example.invalid"), "match": 1.0}}
		detail["fido2Credentials"] = []any{map[string]any{"keyValue": "opaque future cipher text"}}
	}
	if kind == 2 {
		detail["type"] = 0
	}
	data, err := json.Marshal(map[string]any{"id": "item-1", "type": kind, "name": enc("原标题"), "notes": enc("笔记"), "edit": true, "viewPassword": true, "revisionDate": "2026-01-01T00:00:00Z", section: detail, "futureExtension": "opaque encrypted value", "fields": []any{map[string]any{"name": enc("custom"), "value": enc("secret"), "type": 0}}, "passwordHistory": []any{map[string]any{"password": enc("old password"), "lastUsedDate": "2025-01-01T00:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	return CipherDocument{JSON: data}, key
}
func TestCipherDocumentFiveTypesPreserveExtensions(t *testing.T) {
	for kind := 1; kind <= 5; kind++ {
		t.Run(cipherSections[kind], func(t *testing.T) {
			doc, key := cipherDocumentFixture(t, kind)
			fields, err := DecryptCipherDocument(doc, key)
			if err != nil {
				t.Fatal(err)
			}
			if fields.Name != "原标题" || fields.Notes == nil || *fields.Notes != "笔记" {
				t.Fatal("decryption lost fields")
			}
			fields.Name = "新标题"
			fields.Favorite = true
			updated, err := EncryptCipherDocument(doc, fields, key, "account-a")
			if err != nil {
				t.Fatal(err)
			}
			result, err := DecryptCipherDocument(updated, key)
			if err != nil {
				t.Fatal(err)
			}
			if result.Name != fields.Name || !result.Favorite {
				t.Fatal("update lost supported fields")
			}
			object, _ := documentObject(updated)
			if object["futureExtension"] != "opaque encrypted value" || object["lastKnownRevisionDate"] != fields.RevisionDate || object["encryptedFor"] != "account-a" {
				t.Fatal("metadata changed")
			}
			if kind == 1 {
				login := object["login"].(map[string]any)
				if login["fido2Credentials"].([]any)[0].(map[string]any)["keyValue"] != "opaque future cipher text" {
					t.Fatal("passkey extension lost")
				}
			}
			if bytes.Contains(updated.JSON, []byte("新标题")) || bytes.Contains(updated.JSON, []byte("old password")) {
				t.Fatal("plaintext transmitted")
			}
		})
	}
}
func TestCipherDocumentRejectsUnsafeChanges(t *testing.T) {
	for _, scenario := range []string{"identity", "type", "revision", "invalid-revision", "organization", "custom", "password", "uris", "permission", "reprompt", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			doc, key := cipherDocumentFixture(t, 1)
			object, _ := documentObject(doc)
			if scenario == "invalid-revision" {
				object["revisionDate"] = "invalid"
			}
			if scenario == "permission" {
				object["edit"] = false
			}
			if scenario == "reprompt" {
				object["reprompt"] = 1
			}
			if scenario == "corrupt" {
				object["notes"] = "7.unsupported"
			}
			doc.JSON, _ = json.Marshal(object)
			fields, err := DecryptCipherDocument(doc, key)
			if scenario == "corrupt" {
				if err == nil {
					t.Fatal("corrupt field accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "identity":
				fields.ID = "other"
			case "type":
				fields.Type = 3
			case "revision":
				fields.RevisionDate = "new"
			case "organization":
				id := "other"
				fields.OrganizationID = &id
			case "custom":
				fields.Fields = nil
			case "password":
				fields.Login["password"] = "new"
			case "uris":
				fields.Login["uris"] = nil
			}
			if _, err := EncryptCipherDocument(doc, fields, key, "account-a"); err == nil {
				t.Fatal("unsafe rewrite accepted")
			}
		})
	}
}
func TestCipherDocumentPreservesLargeUnknownNumbers(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 3)
	object, _ := documentObject(doc)
	object["futureNumericID"] = json.Number("9007199254740993")
	doc.JSON, _ = json.Marshal(object)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "Changed"
	updated, err := EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := documentObject(updated)
	if result["futureNumericID"] != json.Number("9007199254740993") {
		t.Fatal("unknown integer rounded during rewrite")
	}
}

func TestObjectIDRejectsPaths(t *testing.T) {
	for _, id := range []string{"", "..", "a/b", "a%2fb", "https://evil.invalid", "a?b", "a#b", "a\\b", "a\x00b"} {
		if validObjectID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
}
