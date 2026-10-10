// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"context"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// orgOperationsPanel is an independent native component. The host supplies an
// executor bound to one authenticated scope/revision, including per-item grants,
// and a dispatcher onto its UI thread. Close it on lock, sync or scope change.
// A completed operation always needs sync before constructing another panel.
type OperationsPanel struct {
	orgID                                   string
	entries                                 []vaultwarden.VaultEntry
	Selected                                map[string]bool
	action                                  vaultwarden.CipherAction
	Confirmation, running, terminal, Closed bool
	generation                              uint64
	cancel                                  context.CancelFunc
	status                                  string
	execute                                 func(context.Context, string, []string, vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error)
	dispatch                                func(func())
	Busy                                    func(bool)
}

func NewOperationsPanel(orgID string, entries []vaultwarden.VaultEntry, execute func(context.Context, string, []string, vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error), dispatch func(func())) *OperationsPanel {
	p := &OperationsPanel{orgID: orgID, Selected: map[string]bool{}, action: vaultwarden.CipherTrash, execute: execute, dispatch: dispatch}
	for _, entry := range entries {
		if entry.OrganizationID == orgID {
			p.entries = append(p.entries, entry)
		}
	}
	return p
}
func (p *OperationsPanel) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.generation++
	p.Closed = true
	p.entries = nil
	p.Selected = nil
	p.status = ""
	p.Confirmation = false
}
func (p *OperationsPanel) ids() []string {
	var ids []string
	for _, entry := range p.entries {
		if p.Selected[entry.ID] {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}
func (p *OperationsPanel) selectItem(id string) {
	if p.Closed || p.running || p.terminal {
		return
	}
	for _, entry := range p.entries {
		if entry.ID == id && entry.Editable && entry.Readable && !entry.RequiresPassword {
			p.Selected[id] = !p.Selected[id]
			p.Confirmation = false
			return
		}
	}
}
func (p *OperationsPanel) Start() {
	if p.Closed || p.running || p.terminal || !p.Confirmation || len(p.ids()) == 0 || p.execute == nil || p.dispatch == nil {
		return
	}
	ids := p.ids()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	if p.Busy != nil {
		p.Busy(true)
	}
	p.Confirmation = false
	p.status = i18n.T("正在处理组织条目…")
	generation := p.generation
	orgID, operation, execute, dispatch := p.orgID, p.action, p.execute, p.dispatch
	go func() {
		result, err := execute(ctx, orgID, ids, operation)
		cancel()
		dispatch(func() {
			if p.Busy != nil {
				p.Busy(false)
			}
			if p.Closed || generation != p.generation {
				return
			}
			p.running = false
			p.terminal = true
			p.cancel = nil
			switch {
			case result.ReconcileRequired:
				p.status = i18n.T("服务器可能已处理部分条目。请同步逐项核对，勿直接重试。")
			case err != nil:
				p.status = i18n.Tf("请求未完成：%s。请重新同步核对。", err.Error())
			case result.Applied:
				p.status = i18n.Tf("服务器已确认 %d 项操作，请同步更新列表。", len(result.IDs))
			default:
				p.status = i18n.T("未获得可靠结果，请同步核对。")
			}
		})
	}()
}
func (p *OperationsPanel) View(c *ui.Context) {
	if p.Closed {
		return
	}
	ui.Text(c, i18n.T("组织条目操作")).FontSize(22)
	ui.Text(c, i18n.T("批量操作可能部分完成；发生错误或取消后必须同步核对。需要主密码的条目请从单项授权入口处理。"))
	for _, entry := range p.entries {
		blocked := p.running || p.terminal || !entry.Editable || !entry.Readable || entry.RequiresPassword
		if kit.Action(c, entry.Title, "", p.Selected[entry.ID], blocked).Key("org-operation-item-" + entry.ID).Clicked() {
			p.selectItem(entry.ID)
		}
	}
	for _, option := range []struct {
		label  string
		action vaultwarden.CipherAction
	}{{i18n.T("移到回收站"), vaultwarden.CipherTrash}, {i18n.T("恢复"), vaultwarden.CipherRestore}, {i18n.T("归档"), vaultwarden.CipherArchive}, {i18n.T("取消归档"), vaultwarden.CipherUnarchive}, {i18n.T("永久删除"), vaultwarden.CipherDeletePermanently}} {
		if kit.Action(c, option.label, "", p.action == option.action, p.running || p.terminal).Key("org-operation-" + string(option.action)).Clicked() {
			p.action = option.action
			p.Confirmation = false
		}
	}
	if p.Confirmation {
		ui.Text(c, i18n.Tf("确认对 %d 个组织条目执行所选操作？永久删除无法撤销。", len(p.ids())))
		if kit.Action(c, i18n.T("确认执行"), "", true, p.running).Key("org-operation-confirm").Clicked() {
			p.Start()
		}
		if kit.Action(c, i18n.T("返回选择"), "", false, p.running).Key("org-operation-back").Clicked() {
			p.Confirmation = false
		}
	} else if kit.Action(c, i18n.T("核对所选操作"), "", true, p.running || p.terminal || len(p.ids()) == 0 || p.execute == nil || p.dispatch == nil).Key("org-operation-review").Clicked() {
		p.Confirmation = true
	}
	if p.running && kit.Action(c, i18n.T("取消请求并核对结果"), "", false, false).Key("org-operation-cancel").Clicked() {
		if p.cancel != nil {
			p.cancel()
		}
		p.status = i18n.T("正在取消；已发送请求可能已部分执行。")
	}
	if p.status != "" {
		ui.Text(c, p.status)
	}
}
