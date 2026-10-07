// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestHistoryRemovalPreservesRetainedExtensionsAndDraft(t *testing.T) {
	doc, key := cipherDocumentFixture(t, 1)
	object, _ := documentObject(doc)
	first := object["passwordHistory"].([]any)[0].(map[string]any)
	first["futureID"] = json.Number("9007199254740993")
	second := map[string]any{"password": first["password"], "lastUsedDate": "2026-01-02T00:00:00Z"}
	object["passwordHistory"] = []any{first, second}
	doc.JSON, _ = json.Marshal(object)
	fields, err := DecryptCipherDocument(doc, key)
	if err != nil {
		t.Fatal(err)
	}
	fields.PasswordHistory = fields.PasswordHistory[:1]
	before, _ := json.Marshal(fields)
	updated, err := EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(fields)
	if !bytes.Equal(before, after) {
		t.Fatal("draft mutated")
	}
	result, err := DecryptCipherDocument(updated, key)
	if err != nil || len(result.PasswordHistory) != 1 || result.PasswordHistory[0]["futureID"] != json.Number("9007199254740993") {
		t.Fatal("history extension lost", err)
	}
	fields.PasswordHistory = nil
	updated, err = EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err = DecryptCipherDocument(updated, key)
	if err != nil || len(result.PasswordHistory) != 0 {
		t.Fatal("clear history failed", err)
	}
	fields.Login["password"] = "replacement"
	updated, err = EncryptCipherDocument(doc, fields, key, "account-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err = DecryptCipherDocument(updated, key)
	if err != nil || len(result.PasswordHistory) != 1 || result.PasswordHistory[0]["password"] != "original password" {
		t.Fatal("new password change history missing", err)
	}
}
func TestHistorySubsequenceRejectsForgeryReorderAndDuplicate(t *testing.T) {
	original := []map[string]any{{"password": "a"}, {"password": "b"}}
	for _, kept := range [][]map[string]any{
		{{"password": "b"}, {"password": "a"}},
		{{"password": "a"}, {"password": "a"}},
		{{"password": "a", "extra": "forged"}},
		{{"password": "changed"}},
	} {
		if historySubsequence(kept, original) {
			t.Fatal("forged history accepted")
		}
	}
}
