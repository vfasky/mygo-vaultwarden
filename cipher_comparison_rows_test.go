// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestCipherRowNativePreviewAndExplicitCorrespondence(t *testing.T) {
	a := writableUIFixture(t)
	a.openCipherEditor("card-1", 3)
	e := a.editor
	e.custom = []editorCustom{{source: map[string]any{"type": json.Number("1")}, name: "local-name", value: "local-row-secret", kind: "1", hidden: true, editable: true}}
	publishComparisonFixture(t, a, func(object map[string]any) {
		key, err := vaultwarden.DecryptString(object["key"].(string), bytes.Repeat([]byte{4}, 64))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		name, _ := vaultwarden.EncryptString([]byte("remote-name"), key)
		value, _ := vaultwarden.EncryptString([]byte("remote-row-secret"), key)
		added, _ := vaultwarden.EncryptString([]byte("remote-added"), key)
		object["fields"] = []any{map[string]any{"name": name, "value": value, "type": 1, "newOpaque": "preserved"}, map[string]any{"name": added, "value": value, "type": 1}}
	})
	a.compareCipher(nil)
	if e.comparison == nil || len(e.rowChoices["fields"]) != 1 || e.rowChoices["fields"][0] != -2 {
		t.Fatal("missing safe row defaults", a.status)
	}
	tester := ui.NewTester(func(c *ui.Context) { a.cipherComparisonView(c) }, 1000, 1000)
	if tester.HasText("local-row-secret") || tester.HasText("remote-row-secret") {
		t.Fatal("row preview bypassed authorization")
	}
	a.revealCipherRows("fields", func(request storageRequest) storageReply {
		if request.Operation != "authorizeSecretDisplay" || request.Secret != "" || len(request.UnlockKey) != 32 {
			t.Fatal("native row authorization")
		}
		return storageReply{OK: true}
	})
	tester.Frame()
	if !tester.HasText("local-row-secret") || !tester.HasText("remote-row-secret") {
		t.Fatal("authorized row values not shown")
	}
	e.rowPreview.expires = time.Now().Add(-time.Second)
	tester.Frame()
	if tester.HasText("local-row-secret") || e.rowPreview != nil {
		t.Fatal("expired row preview")
	}
	clickUI(t, tester, "保留远端，不应用此本地行")
	if e.rowChoices["fields"][0] != -1 {
		t.Fatal("explicit append missing")
	}
	clickUI(t, tester, "作为独立新增行")
	if e.rowChoices["fields"][0] != 0 {
		t.Fatal("explicit remote mapping missing")
	}
	a.applyCipherComparison(true)
	if len(e.fields.Fields) != 2 || e.fields.Fields[0]["value"] != "local-row-secret" || e.fields.Fields[0]["newOpaque"] != "preserved" || e.fields.Fields[1]["name"] != "remote-added" {
		t.Fatal("explicit mapping lost remote data")
	}
	if e.fields.Fields[0]["type"] != json.Number("1") {
		t.Fatal("custom type lost")
	}
}
