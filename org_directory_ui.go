// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type orgAPIKeyPanel struct {
	flow                    orgBusinessFlow
	allowed, rotate, reveal bool
	password, key, clientID string
	expires                 time.Time
	execute                 func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error
}

func newOrgAPIKeyPanel(owner bool, execute func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error, dispatch func(func())) *orgAPIKeyPanel {
	return &orgAPIKeyPanel{flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, execute: execute}
}
func (p *orgAPIKeyPanel) Close() {
	p.flow.close()
	p.password = ""
	p.key = ""
	p.clientID = ""
	p.reveal = false
}
func (p *orgAPIKeyPanel) start() {
	if !p.allowed || p.execute == nil || p.password == "" || p.flow.dispatch == nil || p.flow.blocked() || !p.flow.confirm {
		return
	}
	password := []byte(p.password)
	p.password = ""
	rotate, execute, dispatch := p.rotate, p.execute, p.flow.dispatch
	ctx, cancel := context.WithCancel(context.Background())
	p.flow.cancel = cancel
	p.flow.running = true
	if p.flow.busy != nil {
		p.flow.busy(true)
	}
	p.flow.confirm = false
	generation := p.flow.generation
	go func() {
		var secret []byte
		var clientID string
		var expires time.Time
		err := execute(ctx, password, rotate, func(id string, key []byte, date time.Time) error {
			clientID = id
			secret = append([]byte(nil), key...)
			expires = date
			return nil
		})
		clear(password)
		cancel()
		dispatch(func() {
			if p.flow.busy != nil {
				p.flow.busy(false)
			}
			defer clear(secret)
			if p.flow.closed || p.flow.generation != generation {
				return
			}
			p.flow.running = false
			p.flow.terminal = true
			p.flow.cancel = nil
			if err != nil {
				p.flow.status = "API key 请求未完整完成；轮换可能已生效，请重新读取核对。"
				return
			}
			p.key = string(secret)
			p.clientID = clientID
			p.expires = expires
			p.flow.status = "仅本窗口临时显示；关闭或锁定即清除。"
		})
	}()
}
func (p *orgAPIKeyPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "组织 API key").FontSize(22)
	if !p.allowed {
		ui.Text(c, "仅组织所有者可读取或轮换 API key。")
	}
	disabled := p.flow.blocked() || p.flow.confirm || !p.allowed
	ui.TextInput(c, &p.password).Label("当前主密码").Password().Disabled(disabled)
	if action(c, "读取现有 key（首次可能创建）", "", !p.rotate, disabled).Key("org-key-read").Clicked() {
		p.rotate = false
	}
	if action(c, "轮换 key（旧 key 立即失效）", "", p.rotate, disabled).Key("org-key-rotate").Clicked() {
		p.rotate = true
	}
	p.flow.footer(c, "org-key", "确认读取或轮换组织密钥？轮换会使使用旧 key 的目录同步失效。", p.allowed && p.execute != nil && p.password != "", p.start)
	if p.key != "" {
		ui.Text(c, "Client ID："+p.clientID)
		field := ui.TextInput(c, &p.key).Label("组织 API key").Disabled(true)
		if !p.reveal {
			field.Password()
		}
		if action(c, "显示 / 隐藏密钥", "", p.reveal, false).Key("org-key-reveal").Clicked() {
			p.reveal = !p.reveal
		}
		if action(c, "清除密钥", "", false, false).Key("org-key-clear").Clicked() {
			p.key = ""
			p.clientID = ""
			p.reveal = false
		}
	}
}

type orgDirectoryPanel struct {
	flow                                         orgBusinessFlow
	allowed, useGroups, overwrite                bool
	secret, email, external, name, groupExternal string
	deleted                                      bool
	members                                      []vaultwarden.OrganizationDirectoryMember
	groups                                       []vaultwarden.OrganizationDirectoryGroup
	groupMembers                                 map[string]bool
	execute                                      func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error)
}

func newOrgDirectoryPanel(owner, useGroups bool, execute func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error), dispatch func(func())) *orgDirectoryPanel {
	return &orgDirectoryPanel{flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, useGroups: useGroups, groupMembers: map[string]bool{}, execute: execute}
}
func (p *orgDirectoryPanel) Close() {
	p.flow.close()
	p.secret = ""
	p.email = ""
	p.external = ""
	p.name = ""
	p.groupExternal = ""
	p.members = nil
	p.groups = nil
	p.groupMembers = nil
}
func (p *orgDirectoryPanel) addMember() {
	if p.flow.blocked() || p.flow.confirm || !p.allowed {
		return
	}
	email := strings.ToLower(strings.TrimSpace(p.email))
	external := strings.TrimSpace(p.external)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 320 || external == "" || len(external) > 1024 {
		p.flow.status = "请输入有效邮箱及不重复的目录外部 ID。"
		return
	}
	for _, m := range p.members {
		if m.Email == email || m.ExternalID == external {
			p.flow.status = "邮箱或外部 ID 重复，请修改。"
			return
		}
	}
	p.members = append(p.members, vaultwarden.OrganizationDirectoryMember{Email: email, ExternalID: external, Deleted: p.deleted})
	p.email = ""
	p.external = ""
	p.deleted = false
	p.flow.status = ""
}
func (p *orgDirectoryPanel) addGroup() {
	if p.flow.blocked() || p.flow.confirm || !p.allowed || !p.useGroups {
		return
	}
	name, external := strings.TrimSpace(p.name), strings.TrimSpace(p.groupExternal)
	if name == "" || external == "" {
		return
	}
	for _, g := range p.groups {
		if g.ExternalID == external {
			p.flow.status = "群组外部 ID 重复。"
			return
		}
	}
	members := []string{}
	for _, m := range p.members {
		if p.groupMembers[m.ExternalID] {
			members = append(members, m.ExternalID)
		}
	}
	p.groups = append(p.groups, vaultwarden.OrganizationDirectoryGroup{Name: name, ExternalID: external, MemberExternalIDs: members})
	p.name = ""
	p.groupExternal = ""
	p.groupMembers = map[string]bool{}
}
func (p *orgDirectoryPanel) start() {
	if !p.allowed || p.execute == nil || p.secret == "" || len(p.members)+len(p.groups) == 0 || p.flow.blocked() || !p.flow.confirm || p.flow.dispatch == nil {
		return
	}
	secret := []byte(p.secret)
	p.secret = ""
	execute := p.execute
	input := vaultwarden.OrganizationDirectoryImport{Members: append([]vaultwarden.OrganizationDirectoryMember(nil), p.members...), Groups: append([]vaultwarden.OrganizationDirectoryGroup(nil), p.groups...), OverwriteExisting: p.overwrite}
	for i := range input.Groups {
		input.Groups[i].MemberExternalIDs = append([]string(nil), input.Groups[i].MemberExternalIDs...)
	}
	p.flow.run(func(ctx context.Context) ([]string, error) {
		defer clear(secret)
		result, err := execute(ctx, secret, input)
		rows := []string{"组织仍处于持久隔离状态，需重新验证权限。"}
		if r := result.Reconciliation; r != nil {
			for _, row := range r.Rows {
				state := "未知 / 待核对"
				if row.Verified {
					state = "新读取已确认"
				}
				rows = append(rows, row.Kind+" · "+row.ExternalID+"："+state+"；"+row.Reason)
			}
		} else {
			rows = append(rows, "未获得逐项结果，不能推断全部失败或全部成功。")
		}
		return rows, err
	})
}
func (p *orgDirectoryPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "Public 目录导入").FontSize(22)
	ui.Text(c, "以组织 API key 同步外部目录成员和群组。提交后不能自动重发。")
	disabled := p.flow.blocked() || p.flow.confirm || !p.allowed
	ui.TextInput(c, &p.secret).Label("组织 API key（临时使用）").Password().Disabled(disabled)
	ui.TextInput(c, &p.email).Label("成员邮箱").Disabled(disabled)
	ui.TextInput(c, &p.external).Label("目录成员外部 ID").Disabled(disabled)
	if action(c, "标记此成员已删除 / 撤权", "", p.deleted, disabled).Key("org-dir-deleted").Clicked() {
		p.deleted = !p.deleted
	}
	if action(c, "加入预览", "", true, disabled).Key("org-dir-add").Clicked() {
		p.addMember()
	}
	for i, m := range p.members {
		label := m.Email + " · " + m.ExternalID
		if m.Deleted {
			label += " · 撤权"
		}
		ui.Text(c, label)
		if action(c, "移除此行", "", false, disabled || len(p.groups) > 0).Key("org-dir-remove-" + m.ExternalID).Clicked() {
			p.members = append(p.members[:i], p.members[i+1:]...)
			delete(p.groupMembers, m.ExternalID)
			break
		}
	}
	if p.useGroups {
		ui.TextInput(c, &p.name).Label("群组名称").Disabled(disabled)
		ui.TextInput(c, &p.groupExternal).Label("群组外部 ID").Disabled(disabled)
		for _, m := range p.members {
			if action(c, m.Email, "", p.groupMembers[m.ExternalID], disabled).Key("org-dir-group-member-" + m.ExternalID).Clicked() {
				p.groupMembers[m.ExternalID] = !p.groupMembers[m.ExternalID]
			}
		}
		if action(c, "加入群组预览", "", true, disabled).Key("org-dir-add-group").Clicked() {
			p.addGroup()
		}
		for i, g := range p.groups {
			ui.Text(c, g.Name+" · "+g.ExternalID+" · "+strings.Join(g.MemberExternalIDs, ", "))
			if action(c, "移除此群组", "", false, disabled).Key("org-dir-remove-group-" + g.ExternalID).Clicked() {
				p.groups = append(p.groups[:i], p.groups[i+1:]...)
				break
			}
		}
	}
	if action(c, "撤权未出现在本次目录中的现有外部成员", "", p.overwrite, disabled).Key("org-dir-overwrite").Clicked() {
		p.overwrite = !p.overwrite
	}
	p.flow.footer(c, "org-dir", "确认目录预览及缺席成员撤权选项？组织将先持久隔离；服务器可能仅完成部分成员/群组。", p.allowed && p.execute != nil && p.secret != "" && len(p.members)+len(p.groups) > 0, p.start)
}
