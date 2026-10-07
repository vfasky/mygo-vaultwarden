// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCipherRebaseExplicitRowsPreserveRemoteAdditions(t *testing.T) {
	s, _, _ := protectedItemFixture(t, "https://vault.example.invalid")
	defer s.Close()
	base, key := cipherDocumentFixture(t, 1)
	s.key = key
	draft, _ := DecryptCipherDocument(base, key)
	draft.Login["uris"].([]any)[0].(map[string]any)["uri"] = "https://local.invalid"
	draft.Fields[0]["value"] = "local value"
	remote := rebaseRemote(t, base, key, func(o map[string]any) {
		login := o["login"].(map[string]any)
		login["uris"] = append([]any{map[string]any{"uri": "https://remote-added.invalid", "match": json.Number("5"), "remoteOnly": "opaque"}}, login["uris"].([]any)...)
		login["uris"].([]any)[1].(map[string]any)["newOpaque"] = "keep"
		o["fields"] = append([]any{map[string]any{"name": "remote added", "value": "hidden", "type": json.Number("1"), "remoteOnly": "opaque"}}, o["fields"].([]any)...)
		o["fields"].([]any)[1].(map[string]any)["newOpaque"] = "keep"
	})
	vault := rebaseVault(t, s, remote)
	installFixtureSnapshot(t, s, vault, "row-revision")
	plan, changes, err := s.ComparePersonalCipher(vault, "row-revision", base, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range changes {
		if change.CanApply || len(change.LocalRows) == 0 || len(change.RemoteRows) < 2 {
			t.Fatal("missing explicit row preview")
		}
	}
	choices := []CipherRowChoice{{Path: "login.uris", Local: 0, Remote: 1}, {Path: "fields", Local: 0, Remote: 1}}
	doc, merged, err := s.ApplyPersonalCipherComparisonRows(vault, "row-revision", plan, nil, choices)
	if err != nil {
		t.Fatal(err)
	}
	uris := merged.Login["uris"].([]any)
	if len(uris) < 2 || uris[0].(map[string]any)["uri"] != "https://remote-added.invalid" || uris[1].(map[string]any)["uri"] != "https://local.invalid" || uris[1].(map[string]any)["newOpaque"] != "keep" {
		t.Fatal("URI mapping lost remote data")
	}
	if merged.Fields[0]["name"] != "remote added" || merged.Fields[1]["value"] != "local value" || merged.Fields[1]["newOpaque"] != "keep" {
		t.Fatal("custom mapping lost remote data")
	}
	encrypted, err := EncryptCipherDocument(doc, merged, key, s.account)
	if err != nil {
		t.Fatal(err)
	}
	roundtrip, err := DecryptCipherDocument(encrypted, key)
	if err != nil || !reflect.DeepEqual(roundtrip.Fields, merged.Fields) {
		t.Fatal("save lost mapped data", err)
	}
	// A plan can be reused without a previous returned draft mutating its state.
	merged.Fields[1]["newOpaque"] = "tampered"
	_, clean, err := s.ApplyPersonalCipherComparisonRows(vault, "row-revision", plan, nil, choices)
	if err != nil || clean.Fields[1]["newOpaque"] != "keep" {
		t.Fatal("mutable plan")
	}
	for _, invalid := range [][]CipherRowChoice{
		{{Path: "fields", Local: 0, Remote: 999}},
		{{Path: "fields", Local: -1, Remote: 0}},
		{{Path: "fields", Local: 0, Remote: 1}, {Path: "fields", Local: 0, Remote: -1}},
		{{Path: "name", Local: 0, Remote: 0}},
	} {
		if _, _, err := s.ApplyPersonalCipherComparisonRows(vault, "row-revision", plan, nil, invalid); err == nil {
			t.Fatal("invalid correspondence accepted")
		}
	}
	_, appended, err := s.ApplyPersonalCipherComparisonRows(vault, "row-revision", plan, nil, []CipherRowChoice{{Path: "fields", Local: 0, Remote: -1}})
	if err != nil || len(appended.Fields) != len(clean.Fields)+1 {
		t.Fatal("explicit append failed", err)
	}
	s.RevokeItemAuthorizations()
	if _, _, err := s.ApplyPersonalCipherComparisonRows(vault, "row-revision", plan, nil, choices); err == nil {
		t.Fatal("revoked comparison")
	}
}
