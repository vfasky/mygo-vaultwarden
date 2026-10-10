// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"errors"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
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
		a.status = i18n.Tf("暂时无法比较：%s 项目已删除、归属、密钥或权限变化时，请取消草稿并重新打开最新项目。", err.Error())
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
	a.status = i18n.T("请核对双方改动，明确选择要重新应用的字段；继续后还需要再次保存。")
	a.secretInputVersion++
}

func comparisonFieldLabel(path string) string {
	switch path {
	case "name":
		return i18n.T("标题")
	case "notes":
		return i18n.T("备注")
	case "folderId":
		return i18n.T("文件夹")
	case "favorite":
		return i18n.T("收藏")
	case "fields":
		return i18n.T("自定义字段")
	case "passwordHistory":
		return i18n.T("密码历史（仅删除原先观察到的记录）")
	case "login.uris":
		return i18n.T("网站及匹配规则")
	case "secureNote.type":
		return i18n.T("笔记类型")
	}
	key := path[strings.Index(path, ".")+1:]
	for _, specs := range editorSpecs {
		for _, spec := range specs {
			if spec.key == key {
				return spec.label
			}
		}
	}
	return i18n.T("项目内容")
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
			ui.Text(c, i18n.T("比较本地与远端改动")).FontSize(23).FontWeight(600)
			ui.Text(c, i18n.T("默认隐藏秘密内容，可经认证短时显示逐行对照。默认采用远端值；选中的本地改动会重新应用到最新项目，其他内容保持最新版本。"))
			if e.uncertain {
				ui.Text(c, i18n.T("上次写入结果未知。下表是同步核实后的状态；若远端已包含你的更改，请采用远端版本，避免重复提交。"))
			}
			if len(e.changes) == 0 {
				ui.Text(c, i18n.T("未发现可编辑字段的差异，可以采用远端版本。"))
			}
			for _, change := range e.changes {
				text := i18n.Tf("%s：本地未改；远端已改", comparisonFieldLabel(change.Path))
				if change.Local {
					text = i18n.Tf("%s：本地已改；远端未改", comparisonFieldLabel(change.Path))
					if change.Remote {
						text = i18n.Tf("%s：双方均已改", comparisonFieldLabel(change.Path))
					}
				}
				if change.SameValue {
					text = i18n.Tf("%s（双方当前值相同）", text)
				}
				ui.Text(c, text)
				if change.Local && change.CanApply {
					label := i18n.T("采用我的修改")
					if e.localChoices[change.Path] {
						label = i18n.T("✓ 采用我的修改（点击改用远端）")
					}
					if kit.Action(c, label, "", false, a.pending != 0).Clicked() {
						e.localChoices[change.Path] = !e.localChoices[change.Path]
					}
				} else if change.Local {
					a.cipherRowPreviewView(c, e, change.Path)
					ui.Text(c, i18n.T("列表没有固定行 ID。逐行明确选择对应关系；未选择的远端行及其扩展始终保留。点击选择按钮循环：保留远端、作为新增、对应远端各行。删除请继续后在新表单中确认。"))
					for _, label := range change.RemoteRows {
						ui.Text(c, i18n.Tf("远端 · %s", label)).FontSize(12)
					}
					for i, label := range change.LocalRows {
						ui.Text(c, i18n.Tf("本地 · %s", label)).FontSize(12)
						choices := e.rowChoices[change.Path]
						if i >= len(choices) {
							continue
						}
						label := i18n.T("保留远端，不应用此本地行")
						if choices[i] == -1 {
							label = i18n.T("作为独立新增行")
						} else if choices[i] >= 0 {
							label = i18n.Tf("明确对应远端第 %d 行", choices[i]+1)
						}
						if kit.Action(c, label, "", false, a.pending != 0).Clicked() {
							choices[i]++
							if choices[i] >= len(change.RemoteRows) {
								choices[i] = -2
							}
						}
					}
				}
			}
			ui.Text(c, i18n.T("服务器按整秒差值大于 1 检测旧版本（不足两秒可能不拒绝），无法保证比较后没有其他客户端再次修改。保存若再次冲突，会保留草稿供重新比较。"))
			if kit.Action(c, i18n.T("采用远端版本，放弃本地修改"), "", false, a.pending != 0).Clicked() {
				a.applyCipherComparison(false)
			}
			if kit.Action(c, i18n.T("按以上选择重新应用到草稿"), "", true, a.pending != 0).Clicked() {
				a.applyCipherComparison(true)
			}
			if kit.Action(c, i18n.T("返回，保留原草稿"), "", false, a.pending != 0).Clicked() {
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
		a.status = i18n.Tf("比较版本已失效，请重新同步和比较：%s", err.Error())
		e.comparison = nil
		e.changes = nil
		e.localChoices = nil
		return
	}
	grant, expires := e.authorization, e.authorizationExpires
	*e = cipherEditor{document: document, fields: fields, revision: a.sessionRevision, authorization: grant, authorizationExpires: expires}
	populateCipherEditor(e)
	a.secretInputVersion++
	a.status = i18n.T("已采用最新版本并保留所选修改，请检查表单后明确保存。")
}
