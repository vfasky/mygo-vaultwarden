// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) compareCipher(grant *vaultwarden.ItemAuthorization) {
	e := a.editor
	if e == nil || e.fields.ID == "" || a.pending != 0 || !a.sessionOwnsSnapshot() || e.revision == a.sessionRevision {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	e.applyInputs()
	e.shownSecret = ""
	clearCipherRowReveal(e)
	if err := s.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = err.Error()
		return
	}
	plan, changes, err := s.ComparePersonalCipher(a.vault, a.sessionRevision, e.document, e.fields, grant)
	if err != nil {
		if errors.Is(err, vaultwarden.ErrPermission) && grant == nil && s.PersonalItemRequiresPassword(a.vault, e.fields.ID) {
			e.compareAuthorization = true
			e.repromptID = e.fields.ID
			e.authorization = nil
			a.secretInputVersion++
		}
		a.status = "暂时无法比较：" + err.Error() + " 项目已删除、归属、密钥或权限变化时，请取消草稿并重新打开最新项目。"
		return
	}
	e.repromptID, e.repromptPassword = "", ""
	e.compareAuthorization = false
	e.authorization = grant
	if grant != nil {
		e.authorizationExpires = grant.ExpiresAt()
	}
	e.comparison, e.changes = plan, changes
	e.localChoices = map[string]bool{}
	e.rowChoices = map[string][]int{}
	for _, change := range changes {
		choices := make([]int, len(change.LocalRows))
		for i := range choices {
			choices[i] = -2
		}
		e.rowChoices[change.Path] = choices
	}
	a.status = "请核对双方改动，明确选择要重新应用的字段；继续后还需要再次保存。"
	a.secretInputVersion++
}

func comparisonFieldLabel(path string) string {
	switch path {
	case "name":
		return "标题"
	case "notes":
		return "备注"
	case "folderId":
		return "文件夹"
	case "favorite":
		return "收藏"
	case "fields":
		return "自定义字段"
	case "passwordHistory":
		return "密码历史（仅删除原先观察到的记录）"
	case "login.uris":
		return "网站及匹配规则"
	case "secureNote.type":
		return "笔记类型"
	}
	key := path[strings.Index(path, ".")+1:]
	for _, specs := range editorSpecs {
		for _, spec := range specs {
			if spec.key == key {
				return spec.label
			}
		}
	}
	return "项目内容"
}

func (a *app) cipherComparisonView(c *ui.Context) {
	e := a.editor
	if e.rowPreview != nil {
		if !time.Now().Before(e.rowPreview.expires) || !a.sessionOwnsSnapshot() || e.rowPreview.revision != a.sessionRevision {
			clearCipherRowReveal(e)
		} else {
			c.After(time.Until(e.rowPreview.expires))
		}
	}
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Gap(12).Padding(18).Children(func() {
			ui.Text(c, "比较本地与远端改动").FontSize(23).FontWeight(600)
			ui.Text(c, "默认隐藏秘密内容，可经认证短时显示逐行对照。默认采用远端值；选中的本地改动会重新应用到最新项目，其他内容保持最新版本。")
			if e.uncertain {
				ui.Text(c, "上次写入结果未知。下表是同步核实后的状态；若远端已包含你的更改，请采用远端版本，避免重复提交。")
			}
			if len(e.changes) == 0 {
				ui.Text(c, "未发现可编辑字段的差异，可以采用远端版本。")
			}
			for _, change := range e.changes {
				text := comparisonFieldLabel(change.Path) + "：本地未改；远端已改"
				if change.Local {
					text = comparisonFieldLabel(change.Path) + "：本地已改；远端未改"
					if change.Remote {
						text = comparisonFieldLabel(change.Path) + "：双方均已改"
					}
				}
				if change.SameValue {
					text += "（双方当前值相同）"
				}
				ui.Text(c, text)
				if change.Local && change.CanApply {
					label := "采用我的修改"
					if e.localChoices[change.Path] {
						label = "✓ 采用我的修改（点击改用远端）"
					}
					if action(c, label, "", false, a.pending != 0).Clicked() {
						e.localChoices[change.Path] = !e.localChoices[change.Path]
					}
				} else if change.Local {
					a.cipherRowPreviewView(c, e, change.Path)
					ui.Text(c, "列表没有固定行 ID。逐行明确选择对应关系；未选择的远端行及其扩展始终保留。点击选择按钮循环：保留远端、作为新增、对应远端各行。删除请继续后在新表单中确认。")
					for _, label := range change.RemoteRows {
						ui.Text(c, "远端 · "+label).FontSize(12)
					}
					for i, label := range change.LocalRows {
						ui.Text(c, "本地 · "+label).FontSize(12)
						choices := e.rowChoices[change.Path]
						if i >= len(choices) {
							continue
						}
						label := "保留远端，不应用此本地行"
						if choices[i] == -1 {
							label = "作为独立新增行"
						} else if choices[i] >= 0 {
							label = fmt.Sprintf("明确对应远端第 %d 行", choices[i]+1)
						}
						if action(c, label, "", false, a.pending != 0).Clicked() {
							choices[i]++
							if choices[i] >= len(change.RemoteRows) {
								choices[i] = -2
							}
						}
					}
				}
			}
			ui.Text(c, "服务器按整秒差值大于 1 检测旧版本（不足两秒可能不拒绝），无法保证比较后没有其他客户端再次修改。保存若再次冲突，会保留草稿供重新比较。")
			if action(c, "采用远端版本，放弃本地修改", "", false, a.pending != 0).Clicked() {
				a.applyCipherComparison(false)
			}
			if action(c, "按以上选择重新应用到草稿", "", true, a.pending != 0).Clicked() {
				a.applyCipherComparison(true)
			}
			if action(c, "返回，保留原草稿", "", false, a.pending != 0).Clicked() {
				clearCipherRowReveal(e)
				e.comparison = nil
				e.changes = nil
				e.localChoices = nil
				a.secretInputVersion++
			}
		})
	})
}

func (a *app) applyCipherComparison(useChoices bool) {
	e := a.editor
	if e == nil || e.comparison == nil || a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	s, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	clearCipherRowReveal(e)
	choices := []string{}
	if useChoices {
		for path, selected := range e.localChoices {
			if selected {
				choices = append(choices, path)
			}
		}
	}
	rows := []vaultwarden.CipherRowChoice{}
	if useChoices {
		for path, choices := range e.rowChoices {
			for local, remote := range choices {
				if remote >= -1 {
					rows = append(rows, vaultwarden.CipherRowChoice{Path: path, Local: local, Remote: remote})
				}
			}
		}
	}
	document, fields, err := s.ApplyPersonalCipherComparisonRows(a.vault, a.sessionRevision, e.comparison, choices, rows)
	if err != nil {
		a.status = "比较版本已失效，请重新同步和比较：" + err.Error()
		e.comparison = nil
		e.changes = nil
		e.localChoices = nil
		return
	}
	grant, expires := e.authorization, e.authorizationExpires
	*e = cipherEditor{document: document, fields: fields, revision: a.sessionRevision, authorization: grant, authorizationExpires: expires}
	populateCipherEditor(e)
	a.secretInputVersion++
	a.status = "已采用最新版本并保留所选修改，请检查表单后明确保存。"
}
