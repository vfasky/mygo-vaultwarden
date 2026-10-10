// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type APIKeyPanel struct {
	Flow                    orgBusinessFlow
	allowed, rotate, reveal bool
	password, key, clientID string
	expires                 time.Time
	execute                 func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error
}

func NewAPIKeyPanel(owner bool, execute func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error, dispatch func(func())) *APIKeyPanel {
	return &APIKeyPanel{Flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, execute: execute}
}
func (p *APIKeyPanel) Close() {
	p.Flow.close()
	p.password = ""
	p.key = ""
	p.clientID = ""
	p.reveal = false
}
func (p *APIKeyPanel) start() {
	if !p.allowed || p.execute == nil || p.password == "" || p.Flow.dispatch == nil || p.Flow.blocked() || !p.Flow.confirm {
		return
	}
	password := []byte(p.password)
	p.password = ""
	rotate, execute, dispatch := p.rotate, p.execute, p.Flow.dispatch
	ctx, cancel := context.WithCancel(context.Background())
	p.Flow.cancel = cancel
	p.Flow.running = true
	if p.Flow.Busy != nil {
		p.Flow.Busy(true)
	}
	p.Flow.confirm = false
	generation := p.Flow.generation
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
			if p.Flow.Busy != nil {
				p.Flow.Busy(false)
			}
			defer clear(secret)
			if p.Flow.closed || p.Flow.generation != generation {
				return
			}
			p.Flow.running = false
			p.Flow.terminal = true
			p.Flow.cancel = nil
			if err != nil {
				p.Flow.status = i18n.T("API key 请求未完整完成；轮换可能已生效，请重新读取核对。")
				return
			}
			p.key = string(secret)
			p.clientID = clientID
			p.expires = expires
			p.Flow.status = i18n.T("仅本窗口临时显示；关闭或锁定即清除。")
		})
	}()
}
func (p *APIKeyPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("组织 API key")).FontSize(22)
	if !p.allowed {
		ui.Text(c, i18n.T("仅组织所有者可读取或轮换 API key。"))
	}
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.password).Label(i18n.T("当前主密码")).Password().Disabled(disabled)
	if kit.Action(c, i18n.T("读取现有 key（首次可能创建）"), "", !p.rotate, disabled).Key("org-key-read").Clicked() {
		p.rotate = false
	}
	if kit.Action(c, i18n.T("轮换 key（旧 key 立即失效）"), "", p.rotate, disabled).Key("org-key-rotate").Clicked() {
		p.rotate = true
	}
	p.Flow.footer(c, "org-key", i18n.T("确认读取或轮换组织密钥？轮换会使使用旧 key 的目录同步失效。"), p.allowed && p.execute != nil && p.password != "", p.start)
	if p.key != "" {
		ui.Text(c, fmt.Sprintf("Client ID: %s", p.clientID))
		field := ui.TextInput(c, &p.key).Label(i18n.T("组织 API key")).Disabled(true)
		if !p.reveal {
			field.Password()
		}
		if kit.Action(c, i18n.T("显示 / 隐藏密钥"), "", p.reveal, false).Key("org-key-reveal").Clicked() {
			p.reveal = !p.reveal
		}
		if kit.Action(c, i18n.T("清除密钥"), "", false, false).Key("org-key-clear").Clicked() {
			p.key = ""
			p.clientID = ""
			p.reveal = false
		}
	}
}

type DirectoryPanel struct {
	Flow                                         orgBusinessFlow
	allowed, useGroups, overwrite                bool
	secret, email, external, name, groupExternal string
	deleted                                      bool
	members                                      []vaultwarden.OrganizationDirectoryMember
	groups                                       []vaultwarden.OrganizationDirectoryGroup
	groupMembers                                 map[string]bool
	execute                                      func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error)
}

func NewDirectoryPanel(owner, useGroups bool, execute func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error), dispatch func(func())) *DirectoryPanel {
	return &DirectoryPanel{Flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, useGroups: useGroups, groupMembers: map[string]bool{}, execute: execute}
}
func (p *DirectoryPanel) Close() {
	p.Flow.close()
	p.secret = ""
	p.email = ""
	p.external = ""
	p.name = ""
	p.groupExternal = ""
	p.members = nil
	p.groups = nil
	p.groupMembers = nil
}
func (p *DirectoryPanel) addMember() {
	if p.Flow.blocked() || p.Flow.confirm || !p.allowed {
		return
	}
	email := strings.ToLower(strings.TrimSpace(p.email))
	external := strings.TrimSpace(p.external)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 320 || external == "" || len(external) > 1024 {
		p.Flow.status = i18n.T("请输入有效邮箱及不重复的目录外部 ID。")
		return
	}
	for _, m := range p.members {
		if m.Email == email || m.ExternalID == external {
			p.Flow.status = i18n.T("邮箱或外部 ID 重复，请修改。")
			return
		}
	}
	p.members = append(p.members, vaultwarden.OrganizationDirectoryMember{Email: email, ExternalID: external, Deleted: p.deleted})
	p.email = ""
	p.external = ""
	p.deleted = false
	p.Flow.status = ""
}
func (p *DirectoryPanel) addGroup() {
	if p.Flow.blocked() || p.Flow.confirm || !p.allowed || !p.useGroups {
		return
	}
	name, external := strings.TrimSpace(p.name), strings.TrimSpace(p.groupExternal)
	if name == "" || external == "" {
		return
	}
	for _, g := range p.groups {
		if g.ExternalID == external {
			p.Flow.status = i18n.T("群组外部 ID 重复。")
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
func (p *DirectoryPanel) start() {
	if !p.allowed || p.execute == nil || p.secret == "" || len(p.members)+len(p.groups) == 0 || p.Flow.blocked() || !p.Flow.confirm || p.Flow.dispatch == nil {
		return
	}
	secret := []byte(p.secret)
	p.secret = ""
	execute := p.execute
	input := vaultwarden.OrganizationDirectoryImport{Members: append([]vaultwarden.OrganizationDirectoryMember(nil), p.members...), Groups: append([]vaultwarden.OrganizationDirectoryGroup(nil), p.groups...), OverwriteExisting: p.overwrite}
	for i := range input.Groups {
		input.Groups[i].MemberExternalIDs = append([]string(nil), input.Groups[i].MemberExternalIDs...)
	}
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		defer clear(secret)
		result, err := execute(ctx, secret, input)
		rows := []string{i18n.T("组织仍处于持久隔离状态，需重新验证权限。")}
		if r := result.Reconciliation; r != nil {
			for _, row := range r.Rows {
				state := i18n.T("未知 / 待核对")
				if row.Verified {
					state = i18n.T("新读取已确认")
				}
				rows = append(rows, fmt.Sprintf("%s · %s: %s; %s", i18n.T(row.Kind), row.ExternalID, state, row.Reason))
			}
		} else {
			rows = append(rows, i18n.T("未获得逐项结果，不能推断全部失败或全部成功。"))
		}
		return rows, err
	})
}
func (p *DirectoryPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("Public 目录导入")).FontSize(22)
	ui.Text(c, i18n.T("以组织 API key 同步外部目录成员和群组。提交后不能自动重发。"))
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.secret).Label(i18n.T("组织 API key（临时使用）")).Password().Disabled(disabled)
	ui.TextInput(c, &p.email).Label(i18n.T("成员邮箱")).Disabled(disabled)
	ui.TextInput(c, &p.external).Label(i18n.T("目录成员外部 ID")).Disabled(disabled)
	if kit.Action(c, i18n.T("标记此成员已删除 / 撤权"), "", p.deleted, disabled).Key("org-dir-deleted").Clicked() {
		p.deleted = !p.deleted
	}
	if kit.Action(c, i18n.T("加入预览"), "", true, disabled).Key("org-dir-add").Clicked() {
		p.addMember()
	}
	for i, m := range p.members {
		label := m.Email + " · " + m.ExternalID
		if m.Deleted {
			label = i18n.Tf("%s · 撤权", label)
		}
		ui.Text(c, label)
		if kit.Action(c, i18n.T("移除此行"), "", false, disabled || len(p.groups) > 0).Key("org-dir-remove-" + m.ExternalID).Clicked() {
			p.members = append(p.members[:i], p.members[i+1:]...)
			delete(p.groupMembers, m.ExternalID)
			break
		}
	}
	if p.useGroups {
		ui.TextInput(c, &p.name).Label(i18n.T("群组名称")).Disabled(disabled)
		ui.TextInput(c, &p.groupExternal).Label(i18n.T("群组外部 ID")).Disabled(disabled)
		for _, m := range p.members {
			if kit.Action(c, m.Email, "", p.groupMembers[m.ExternalID], disabled).Key("org-dir-group-member-" + m.ExternalID).Clicked() {
				p.groupMembers[m.ExternalID] = !p.groupMembers[m.ExternalID]
			}
		}
		if kit.Action(c, i18n.T("加入群组预览"), "", true, disabled).Key("org-dir-add-group").Clicked() {
			p.addGroup()
		}
		for i, g := range p.groups {
			ui.Text(c, g.Name+" · "+g.ExternalID+" · "+strings.Join(g.MemberExternalIDs, ", "))
			if kit.Action(c, i18n.T("移除此群组"), "", false, disabled).Key("org-dir-remove-group-" + g.ExternalID).Clicked() {
				p.groups = append(p.groups[:i], p.groups[i+1:]...)
				break
			}
		}
	}
	if kit.Action(c, i18n.T("撤权未出现在本次目录中的现有外部成员"), "", p.overwrite, disabled).Key("org-dir-overwrite").Clicked() {
		p.overwrite = !p.overwrite
	}
	p.Flow.footer(c, "org-dir", i18n.T("确认目录预览及缺席成员撤权选项？组织将先持久隔离；服务器可能仅完成部分成员/群组。"), p.allowed && p.execute != nil && p.secret != "" && len(p.members)+len(p.groups) > 0, p.start)
}
