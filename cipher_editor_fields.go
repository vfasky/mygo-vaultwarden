// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"fmt"
	"github.com/egoist/mygo/ui"
	"time"
)

// Bitwarden clients 5983f56ce0cf924eea56c7d8f066f7885825a7ce:
// libs/common/src/vault/enums/linked-id-type.enum.ts.
var linkedFields = map[int][]struct {
	id    json.Number
	label string
}{
	1: {{"100", "用户名"}, {"101", "密码"}},
	3: {{"300", "持卡人"}, {"301", "到期月"}, {"302", "到期年"}, {"303", "安全码"}, {"304", "卡组织"}, {"305", "卡号"}},
	4: {{"400", "称谓"}, {"401", "中间名"}, {"402", "地址一"}, {"403", "地址二"}, {"404", "地址三"}, {"405", "城市"}, {"406", "省/州"}, {"407", "邮编"}, {"408", "国家"}, {"409", "公司"}, {"410", "邮箱"}, {"411", "电话"}, {"412", "社会保障号码"}, {"413", "用户名"}, {"414", "护照号码"}, {"415", "驾驶证号码"}, {"416", "名"}, {"417", "姓"}, {"418", "全名"}},
}

// The match numbers are from the same commit's
// libs/common/src/models/domain/domain-service.ts.
var uriMatches = []struct {
	value any
	label string
}{
	{nil, "默认"}, {json.Number("0"), "基本域名"}, {json.Number("1"), "主机"}, {json.Number("2"), "起始部分"}, {json.Number("3"), "完全匹配"}, {json.Number("4"), "正则表达式"}, {json.Number("5"), "从不填充"},
}

func (a *app) uriMatchPicker(c *ui.Context, u *editorURI, disabled bool) {
	label := "未知策略（保留）"
	for _, m := range uriMatches {
		if u.source["match"] == m.value {
			label = m.label
		}
	}
	if u.source["match"] == nil && a.editor != nil {
		for _, m := range uriMatches[1:] {
			if m.value == json.Number(fmt.Sprint(a.editor.defaultURIMatch)) {
				ui.Text(c, "当前默认："+m.label+"；保留默认会随组织策略更新。显式规则保持不变。").FontSize(11).MaxLines(3)
			}
		}
	}
	if action(c, "匹配方式："+label, "", false, disabled).Clicked() {
		u.showMatch = !u.showMatch
	}
	if u.showMatch {
		for _, m := range uriMatches {
			if navItem(c, m.label, "globe", "", u.source["match"] == m.value, disabled).Clicked() {
				copy := map[string]any{}
				for key, value := range u.source {
					copy[key] = value
				}
				copy["match"] = m.value
				u.source = copy
				u.showMatch = false
			}
		}
		ui.Text(c, "起始部分仅在系统提供完整网址时按原字符串匹配，不进入快捷建议；正则表达式会保留，但不用于当前系统填充。").FontSize(11).MaxLines(3)
	}
}
func (a *app) customValueEditor(c *ui.Context, e *cipherEditor, f *editorCustom) {
	disabled := a.pending != 0 || e.uncertain || !f.editable
	switch f.kind {
	case "2":
		label := "布尔值：否"
		if f.value == "true" {
			label = "布尔值：是"
		} else if f.value != "false" {
			label = "布尔值：未知（保留）"
		}
		if action(c, label, "", false, disabled).Clicked() {
			if f.value == "true" {
				f.value = "false"
			} else {
				f.value = "true"
			}
		}
	case "3":
		label := "未知关联（保留）"
		for _, linked := range linkedFields[e.fields.Type] {
			if linked.id == f.linkedID {
				label = linked.label
			}
		}
		if action(c, "关联到："+label, "", false, disabled).Clicked() {
			f.showLinks = !f.showLinks
		}
		if f.showLinks {
			for _, linked := range linkedFields[e.fields.Type] {
				if navItem(c, linked.label, "key", "", linked.id == f.linkedID, disabled).Clicked() {
					f.linkedID = linked.id
					f.showLinks = false
				}
			}
		}
	default:
		value := ui.TextInput(c, &f.value).Label("字段内容").Disabled(disabled)
		if f.hidden {
			value.Password()
		}
	}
}
func (a *app) passwordHistoryView(c *ui.Context, e *cipherEditor) {
	if e.showHistory && (!time.Now().Before(e.historyExpires) || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision) {
		e.showHistory = false
		clear(e.shownHistory)
		e.shownHistory = nil
	}
	if e.showHistory {
		c.After(time.Until(e.historyExpires))
	}
	if len(e.fields.PasswordHistory) == 0 {
		return
	}
	if e.confirmHistoryDelete {
		ui.Text(c, "确认清除全部密码历史？仅在保存项目后提交；同时修改密码仍会记录本次替换的旧密码。").FontSize(12)
		ui.Row(c).Gap(8).Children(func() {
			if action(c, "确认清除历史", "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.fields.PasswordHistory = nil
				e.confirmHistoryDelete, e.showHistory = false, false
				clear(e.shownHistory)
				e.shownHistory = nil
			}
			if action(c, "保留历史", "", false, a.pending != 0).Clicked() {
				e.confirmHistoryDelete = false
			}
		})
		return
	}
	if action(c, "清除密码历史", "", false, a.pending != 0 || e.uncertain).Clicked() {
		e.confirmHistoryDelete = true
	}
	label := fmt.Sprintf("显示已保存密码历史明文（%d）", len(e.fields.PasswordHistory))
	if e.showHistory {
		label = "隐藏密码历史"
	}
	if action(c, label, "key", false, a.pending != 0 || e.uncertain).Clicked() {
		if e.showHistory {
			e.showHistory = false
			clear(e.shownHistory)
			e.shownHistory = nil
		} else {
			a.showCipherHistory(callStorage)
		}
	}
	if e.showHistory {
		ui.Scroll(c).Height(160).Children(func() {
			ui.Column(c).Gap(8).Children(func() {
				for _, entry := range e.shownHistory {
					ui.Text(c, entry.LastUsedDate).FontSize(11)
					ui.Text(c, entry.Password).FontSize(12).MaxLines(3)
				}
			})
		})
	}
}
