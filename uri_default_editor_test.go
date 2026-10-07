// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"testing"
)

func TestNativeEditorShowsPolicyDefaultWithoutFreezingInheritedRule(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	v := *a.vault
	var data map[string]any
	_ = json.Unmarshal(v.Sync, &data)
	p := []any{map[string]any{"id": "uri-policy", "organizationId": "organization-1", "type": 16, "enabled": true, "data": map[string]any{"uriMatchDetection": 3}}}
	data["policies"], data["policiesNew"] = p, p
	v.Sync, _ = json.Marshal(data)
	acceptUIReceipt(t, a, &v)
	if err := a.adoptVault(&v); err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{"all", "collection:collection-1"} {
		a.category = category
		a.openCipherEditor("", 1)
		if a.editor == nil || a.editor.defaultURIMatch != 3 {
			t.Fatal("default not installed", category)
		}
		u := editorURI{source: map[string]any{"match": nil}, value: "https://example.invalid/"}
		tt := ui.NewTester(func(c *ui.Context) { a.uriMatchPicker(c, &u, false) }, 800, 600)
		if !tt.HasText("当前默认：完全匹配；保留默认会随组织策略更新。显式规则保持不变。") {
			t.Fatal("missing effective default", category)
		}
		if u.source["match"] != nil {
			t.Fatal("inherited default frozen")
		}
		clickUI(t, tt, "匹配方式：默认")
		clickUI(t, tt, "基本域名")
		if u.source["match"] != json.Number("0") {
			t.Fatal("explicit selection overridden")
		}
		a.editor = nil
	}
}
