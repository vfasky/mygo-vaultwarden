// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// orgOperationsPanel is an independent native component. The host supplies an
// executor bound to one authenticated scope/revision, including per-item grants,
// and a dispatcher onto its UI thread. Close it on lock, sync or scope change.
// A completed operation always needs sync before constructing another panel.
type orgOperationsPanel struct {
	orgID                                   string
	entries                                 []vaultwarden.VaultEntry
	selected                                map[string]bool
	action                                  vaultwarden.CipherAction
	confirmation, running, terminal, closed bool
	generation                              uint64
	cancel                                  context.CancelFunc
	status                                  string
	execute                                 func(context.Context, string, []string, vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error)
	dispatch                                func(func())
	busy                                    func(bool)
}

func newOrgOperationsPanel(orgID string, entries []vaultwarden.VaultEntry, execute func(context.Context, string, []string, vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error), dispatch func(func())) *orgOperationsPanel {
	p := &orgOperationsPanel{orgID: orgID, selected: map[string]bool{}, action: vaultwarden.CipherTrash, execute: execute, dispatch: dispatch}
	for _, entry := range entries {
		if entry.OrganizationID == orgID {
			p.entries = append(p.entries, entry)
		}
	}
	return p
}
func (p *orgOperationsPanel) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.generation++
	p.closed = true
	p.entries = nil
	p.selected = nil
	p.status = ""
	p.confirmation = false
}
func (p *orgOperationsPanel) ids() []string {
	var ids []string
	for _, entry := range p.entries {
		if p.selected[entry.ID] {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}
func (p *orgOperationsPanel) selectItem(id string) {
	if p.closed || p.running || p.terminal {
		return
	}
	for _, entry := range p.entries {
		if entry.ID == id && entry.Editable && entry.Readable && !entry.RequiresPassword {
			p.selected[id] = !p.selected[id]
			p.confirmation = false
			return
		}
	}
}
func (p *orgOperationsPanel) start() {
	if p.closed || p.running || p.terminal || !p.confirmation || len(p.ids()) == 0 || p.execute == nil || p.dispatch == nil {
		return
	}
	ids := p.ids()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	if p.busy != nil {
		p.busy(true)
	}
	p.confirmation = false
	p.status = "正在处理组织条目…"
	generation := p.generation
	orgID, operation, execute, dispatch := p.orgID, p.action, p.execute, p.dispatch
	go func() {
		result, err := execute(ctx, orgID, ids, operation)
		cancel()
		dispatch(func() {
			if p.busy != nil {
				p.busy(false)
			}
			if p.closed || generation != p.generation {
				return
			}
			p.running = false
			p.terminal = true
			p.cancel = nil
			switch {
			case result.ReconcileRequired:
				p.status = "服务器可能已处理部分条目。请同步逐项核对，勿直接重试。"
			case err != nil:
				p.status = "请求未完成：" + err.Error() + "。请重新同步核对。"
			case result.Applied:
				p.status = fmt.Sprintf("服务器已确认 %d 项操作，请同步更新列表。", len(result.IDs))
			default:
				p.status = "未获得可靠结果，请同步核对。"
			}
		})
	}()
}
func (p *orgOperationsPanel) View(c *ui.Context) {
	if p.closed {
		return
	}
	ui.Text(c, "组织条目操作").FontSize(22)
	ui.Text(c, "批量操作可能部分完成；发生错误或取消后必须同步核对。需要主密码的条目请从单项授权入口处理。")
	for _, entry := range p.entries {
		blocked := p.running || p.terminal || !entry.Editable || !entry.Readable || entry.RequiresPassword
		if action(c, entry.Title, "", p.selected[entry.ID], blocked).Key("org-operation-item-" + entry.ID).Clicked() {
			p.selectItem(entry.ID)
		}
	}
	for _, option := range []struct {
		label  string
		action vaultwarden.CipherAction
	}{{"移到回收站", vaultwarden.CipherTrash}, {"恢复", vaultwarden.CipherRestore}, {"归档", vaultwarden.CipherArchive}, {"取消归档", vaultwarden.CipherUnarchive}, {"永久删除", vaultwarden.CipherDeletePermanently}} {
		if action(c, option.label, "", p.action == option.action, p.running || p.terminal).Key("org-operation-" + string(option.action)).Clicked() {
			p.action = option.action
			p.confirmation = false
		}
	}
	if p.confirmation {
		ui.Text(c, fmt.Sprintf("确认对 %d 个组织条目执行所选操作？永久删除无法撤销。", len(p.ids())))
		if action(c, "确认执行", "", true, p.running).Key("org-operation-confirm").Clicked() {
			p.start()
		}
		if action(c, "返回选择", "", false, p.running).Key("org-operation-back").Clicked() {
			p.confirmation = false
		}
	} else if action(c, "核对所选操作", "", true, p.running || p.terminal || len(p.ids()) == 0 || p.execute == nil || p.dispatch == nil).Key("org-operation-review").Clicked() {
		p.confirmation = true
	}
	if p.running && action(c, "取消请求并核对结果", "", false, false).Key("org-operation-cancel").Clicked() {
		if p.cancel != nil {
			p.cancel()
		}
		p.status = "正在取消；已发送请求可能已部分执行。"
	}
	if p.status != "" {
		ui.Text(c, p.status)
	}
}
