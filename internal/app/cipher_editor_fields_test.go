// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"reflect"
	"testing"
)

func TestCustomFieldControlsAndLosslessMerge(t *testing.T) {
	a := &app{}
	source := map[string]any{"type": json.Number("2"), "name": "checked", "value": "false", "future": "opaque"}
	f := editorCustom{source: source, name: "checked", value: "false", kind: "2", editable: true}
	e := &cipherEditor{fields: vaultwarden.CipherFields{Type: 1}, custom: []editorCustom{f}}
	tt := ui.NewTester(func(c *ui.Context) { a.customValueEditor(c, e, &e.custom[0]) }, 500, 400)
	clickUI(t, tt, "布尔值：否")
	e.applyInputs()
	if e.fields.Fields[0]["value"] != "true" || e.fields.Fields[0]["future"] != "opaque" || source["value"] != "false" {
		t.Fatal("boolean merge changed source/extension")
	}
	linked := map[string]any{"type": json.Number("3"), "name": "linked", "value": nil, "linkedId": json.Number("100"), "future": "opaque"}
	e.custom = []editorCustom{{source: linked, name: "linked", kind: "3", linkedID: "100", editable: true}}
	tt = ui.NewTester(func(c *ui.Context) { a.customValueEditor(c, e, &e.custom[0]) }, 500, 400)
	clickUI(t, tt, "关联到：用户名")
	clickUI(t, tt, "密码")
	e.applyInputs()
	if e.fields.Fields[0]["linkedId"] != json.Number("101") || e.fields.Fields[0]["value"] != nil || linked["linkedId"] != json.Number("100") {
		t.Fatal("linked merge")
	}
	// Unknown IDs and null fields survive without synthesizing a new value.
	linked["linkedId"] = json.Number("999")
	e.custom = []editorCustom{{source: linked, name: "linked", kind: "3", linkedID: "999", editable: true}, {source: map[string]any{"type": json.Number("0"), "name": nil, "value": nil}, kind: "0", editable: true}}
	e.applyInputs()
	if !reflect.DeepEqual(e.fields.Fields[0], linked) || e.fields.Fields[1]["name"] != nil || e.fields.Fields[1]["value"] != nil {
		t.Fatal("no-op lost null/unknown")
	}
}

func TestURIMatchPickerKeepsSourceAndUnsupportedStrategy(t *testing.T) {
	a := &app{}
	source := map[string]any{"uri": "https://example.invalid/", "match": json.Number("4"), "future": "opaque"}
	u := editorURI{source: source, value: "https://example.invalid/"}
	tt := ui.NewTester(func(c *ui.Context) { a.uriMatchPicker(c, &u, false) }, 650, 600)
	clickUI(t, tt, "匹配方式：正则表达式")
	clickUI(t, tt, "完全匹配")
	if u.source["match"] != json.Number("3") || source["match"] != json.Number("4") || u.source["future"] != "opaque" {
		t.Fatal("URI strategy lost/changed original")
	}
	e := &cipherEditor{fields: vaultwarden.CipherFields{Type: 1, Login: map[string]any{}}, uris: []editorURI{u}}
	e.applyInputs()
	if e.fields.Login["uris"].([]any)[0].(map[string]any)["match"] != json.Number("3") {
		t.Fatal("match not submitted")
	}
}

func TestHistoryIsHiddenUntilExplicitReveal(t *testing.T) {
	a := &app{}
	e := &cipherEditor{fields: vaultwarden.CipherFields{PasswordHistory: []map[string]any{{"password": "historical-secret", "lastUsedDate": "2026-01-01"}}}}
	tt := ui.NewTester(func(c *ui.Context) { a.passwordHistoryView(c, e) }, 650, 500)
	if tt.HasText("historical-secret") {
		t.Fatal("history shown without reveal")
	}
	clickUI(t, tt, "显示已保存密码历史明文（1）")
	if tt.HasText("historical-secret") {
		t.Fatal("history revealed without current snapshot/native authorization")
	}
}
