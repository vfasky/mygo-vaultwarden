// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// All callbacks are bound by the host to one authenticated scope/revision and
// must enforce live permissions, reprompt and checkpoint persistence. UI controls
// never grant authority. dispatch must enqueue onto the native UI thread.
type orgBusinessFlow struct {
	running, terminal, closed, confirm bool
	cancel                             context.CancelFunc
	generation                         uint64
	status                             string
	rows                               []string
	dispatch                           func(func())
}

func (f *orgBusinessFlow) blocked() bool { return f.running || f.terminal || f.closed }
func (f *orgBusinessFlow) close() {
	if f.cancel != nil {
		f.cancel()
	}
	f.generation++
	f.closed = true
	f.confirm = false
	f.status = ""
	f.rows = nil
}
func (f *orgBusinessFlow) run(work func(context.Context) ([]string, error)) {
	if f.blocked() || !f.confirm || f.dispatch == nil || work == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.running = true
	f.confirm = false
	f.status = "正在执行；取消不会回滚已发送的请求。"
	generation := f.generation
	dispatch := f.dispatch
	go func() {
		rows, err := work(ctx)
		cancel()
		dispatch(func() {
			if f.closed || generation != f.generation {
				return
			}
			f.running = false
			f.terminal = true
			f.cancel = nil
			f.rows = rows
			if err != nil {
				f.status = "请求未完整完成，请检查逐项结果并重新读取；不要自动重发。"
			} else {
				f.status = "本次请求已结束，请核对下列结果。"
			}
		})
	}()
}
func (f *orgBusinessFlow) footer(c *ui.Context, key, warning string, ready bool, start func()) {
	if f.confirm {
		ui.Text(c, warning)
		if action(c, "确认执行", "", true, f.blocked() || !ready).Key(key + "-confirm").Clicked() {
			start()
		}
		if action(c, "返回修改", "", false, f.blocked()).Key(key + "-back").Clicked() {
			f.confirm = false
		}
	} else if action(c, "核对并继续", "", true, f.blocked() || !ready || f.dispatch == nil).Key(key + "-review").Clicked() {
		f.confirm = true
	}
	if f.running && action(c, "取消请求并核对", "", false, false).Key(key+"-cancel").Clicked() {
		f.cancel()
		f.status = "正在取消；服务器可能已部分执行。"
	}
	if f.status != "" {
		ui.Text(c, f.status)
	}
	for _, row := range f.rows {
		ui.Text(c, row)
	}
}

type orgCollectionChoice struct {
	ID, OrganizationID, Name string
	Writable                 bool
}
type orgCopyPanel struct {
	flow    orgBusinessFlow
	source  vaultwarden.VaultEntry
	choices []orgCollectionChoice
	target  int
	execute func(context.Context, string, string, string) (vaultwarden.CipherDocument, error)
}

func newOrgCopyPanel(source vaultwarden.VaultEntry, choices []orgCollectionChoice, execute func(context.Context, string, string, string) (vaultwarden.CipherDocument, error), dispatch func(func())) *orgCopyPanel {
	return &orgCopyPanel{flow: orgBusinessFlow{dispatch: dispatch}, source: source, choices: append([]orgCollectionChoice(nil), choices...), target: -1, execute: execute}
}
func (p *orgCopyPanel) Close() { p.flow.close(); p.source = vaultwarden.VaultEntry{}; p.choices = nil }
func (p *orgCopyPanel) ready() bool {
	return p.execute != nil && p.source.Readable && p.source.Editable && p.target >= 0 && p.target < len(p.choices) && p.choices[p.target].Writable
}
func (p *orgCopyPanel) start() {
	if !p.ready() {
		return
	}
	source, target, execute := p.source.ID, p.choices[p.target], p.execute
	p.flow.run(func(ctx context.Context) ([]string, error) {
		_, err := execute(ctx, source, target.OrganizationID, target.ID)
		if err != nil {
			return nil, err
		}
		return []string{"服务器已返回新副本；请重新读取目标集合。原条目保持原位置。"}, nil
	})
}
func (p *orgCopyPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "复制组织条目").FontSize(22)
	ui.Text(c, p.source.Title)
	if p.source.RequiresPassword {
		ui.Text(c, "执行时需通过主密码再次验证；取消验证不会提交。")
	}
	for i, choice := range p.choices {
		if action(c, choice.Name, "", p.target == i, p.flow.blocked() || p.flow.confirm || !choice.Writable).Key("org-copy-" + choice.ID).Clicked() {
			p.target = i
		}
	}
	p.flow.footer(c, "org-copy", "确认在所选组织集合新建独立副本？不支持的附件或字段将中止复制。", p.ready(), p.start)
}

type orgCollectionPanel struct {
	flow     orgBusinessFlow
	item     vaultwarden.VaultEntry
	choices  []orgCollectionChoice
	selected map[string]bool
	execute  func(context.Context, string, []string) error
}

func newOrgCollectionPanel(item vaultwarden.VaultEntry, choices []orgCollectionChoice, current []string, execute func(context.Context, string, []string) error, dispatch func(func())) *orgCollectionPanel {
	p := &orgCollectionPanel{flow: orgBusinessFlow{dispatch: dispatch}, item: item, selected: map[string]bool{}, execute: execute}
	for _, choice := range choices {
		if choice.OrganizationID == item.OrganizationID {
			p.choices = append(p.choices, choice)
		}
	}
	for _, id := range current {
		p.selected[id] = true
	}
	return p
}
func (p *orgCollectionPanel) Close() {
	p.flow.close()
	p.item = vaultwarden.VaultEntry{}
	p.choices = nil
	p.selected = nil
}
func (p *orgCollectionPanel) start() {
	if p.execute == nil || !p.item.Readable || !p.item.Editable {
		return
	}
	ids := []string{}
	for _, choice := range p.choices {
		if p.selected[choice.ID] {
			ids = append(ids, choice.ID)
		}
	}
	id, execute := p.item.ID, p.execute
	p.flow.run(func(ctx context.Context) ([]string, error) {
		err := execute(ctx, id, ids)
		return []string{"集合关联变更可能撤回自身访问。组织保持隔离，需重新验证权限后恢复。"}, err
	})
}
func (p *orgCollectionPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "调整组织集合").FontSize(22)
	ui.Text(c, p.item.Title)
	for _, choice := range p.choices {
		if action(c, choice.Name, "", p.selected[choice.ID], p.flow.blocked() || p.flow.confirm || !choice.Writable).Key("org-assign-" + choice.ID).Clicked() {
			p.selected[choice.ID] = !p.selected[choice.ID]
		}
	}
	p.flow.footer(c, "org-assign", "确认调整所选集合？提交前将持久隔离组织；失去访问后不会自动恢复。", p.execute != nil && p.item.Readable && p.item.Editable, p.start)
}

type orgImportPanel struct {
	flow          orgBusinessFlow
	plan          *vaultwarden.OrganizationImportPlan
	format        string
	choices       []orgCollectionChoice
	mappings      map[string]string
	createAllowed bool
	execute       func(context.Context, *vaultwarden.OrganizationImportPlan, map[string]string) (vaultwarden.OrganizationOperationResult, error)
}

func newOrgImportPanel(plan *vaultwarden.OrganizationImportPlan, format string, choices []orgCollectionChoice, createAllowed bool, execute func(context.Context, *vaultwarden.OrganizationImportPlan, map[string]string) (vaultwarden.OrganizationOperationResult, error), dispatch func(func())) *orgImportPanel {
	return &orgImportPanel{flow: orgBusinessFlow{dispatch: dispatch}, plan: plan, format: format, choices: append([]orgCollectionChoice(nil), choices...), mappings: map[string]string{}, createAllowed: createAllowed, execute: execute}
}
func (p *orgImportPanel) Close() {
	running := p.flow.running
	p.flow.close()
	if !running && p.plan != nil {
		p.plan.Clear()
	}
	p.plan = nil
	p.mappings = nil
	p.choices = nil
}
func (p *orgImportPanel) ready() bool {
	if p.plan == nil || p.execute == nil {
		return false
	}
	for _, item := range p.plan.PreviewItems() {
		if item.Archived || item.Deleted {
			return false
		}
	}
	for _, c := range p.plan.Collections() {
		if _, ok := p.mappings[c.ID]; !ok {
			return false
		}
	}
	return true
}
func (p *orgImportPanel) start() {
	if p.flow.blocked() || !p.flow.confirm || p.flow.dispatch == nil || !p.ready() {
		return
	}
	plan, execute := p.plan, p.execute
	preview := plan.PreviewItems()
	mappings := map[string]string{}
	for k, v := range p.mappings {
		mappings[k] = v
	}
	p.flow.run(func(ctx context.Context) ([]string, error) {
		defer plan.Clear()
		result, err := execute(ctx, plan, mappings)
		rows := []string{}
		if r := result.ImportReconciliation; r != nil {
			rows = append(rows, fmt.Sprintf("读取前 %d 项，读取后 %d 项，新增 %d 项", len(r.BeforeIDs), len(r.AfterIDs), len(r.AddedIDs)))
			for i, item := range r.Items {
				label := item.SourceID
				if i < len(preview) {
					label = preview[i].Name
				}
				state := "待人工核对"
				if item.Verified {
					state = "新读取已确认"
				}
				rows = append(rows, label+"："+state+"；"+item.Reason)
			}
		} else {
			rows = append(rows, "尚无逐项核对结果；请求可能部分完成，请勿重发。")
		}
		return rows, err
	})
}
func (p *orgImportPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "组织导入预览与集合映射").FontSize(22)
	ui.Text(c, p.format)
	// The worker owns and clears the plaintext plan while running. Never read it
	// from the UI after dispatch.
	if !p.flow.running && !p.flow.terminal && p.plan != nil {
		for i, item := range p.plan.PreviewItems() {
			ui.Text(c, fmt.Sprintf("%d. %s（类型 %d）", i+1, item.Name, item.Type))
			if item.Archived || item.Deleted {
				ui.Text(c, "此条目有归档或回收站状态，官方组织导入端点不能保留，已阻止提交。")
			}
		}
		for _, source := range p.plan.Collections() {
			ui.Text(c, "源集合："+source.Name)
			value, set := p.mappings[source.ID]
			if action(c, "创建同名新集合", "", set && value == "", p.flow.confirm || !p.createAllowed).Key("org-map-new-" + source.ID).Clicked() {
				p.mappings[source.ID] = ""
			}
			for _, target := range p.choices {
				if action(c, target.Name, "", set && value == target.ID, p.flow.confirm || !target.Writable).Key("org-map-" + source.ID + "-" + target.ID).Clicked() {
					p.mappings[source.ID] = target.ID
				}
			}
		}
	}
	ready := false
	if !p.flow.blocked() {
		ready = p.ready()
	}
	p.flow.footer(c, "org-import", "确认导入预览条目及集合映射？此操作非事务，部分成功不能自动重发。", ready, p.start)
}

type orgExportPanel struct {
	flow                   orgBusinessFlow
	organizationName, path string
	official               bool
	allowed                bool
	execute                func(context.Context, string, bool) error
}

func newOrgExportPanel(name string, allowed bool, execute func(context.Context, string, bool) error, dispatch func(func())) *orgExportPanel {
	return &orgExportPanel{flow: orgBusinessFlow{dispatch: dispatch}, organizationName: name, allowed: allowed, execute: execute}
}
func (p *orgExportPanel) Close() { p.flow.close(); p.path = "" }
func (p *orgExportPanel) start() {
	if !p.allowed || p.execute == nil || strings.TrimSpace(p.path) == "" {
		return
	}
	path, official, execute := p.path, p.official, p.execute
	p.flow.run(func(ctx context.Context) ([]string, error) {
		err := execute(ctx, path, official)
		if err != nil {
			return nil, err
		}
		return []string{"已安全保存明文组织文件；请妥善保管并在使用后移除。"}, nil
	})
}
func (p *orgExportPanel) View(c *ui.Context) {
	if p.flow.closed {
		return
	}
	ui.Text(c, "导出组织："+p.organizationName).FontSize(22)
	disabled := p.flow.blocked() || p.flow.confirm || !p.allowed
	ui.TextInput(c, &p.path).Label("保存到新文件（禁止覆盖已有文件）").Disabled(disabled)
	if action(c, "MyGo 组织备份 v1", "", !p.official, disabled).Key("org-export-mygo").Clicked() {
		p.official = false
	}
	if action(c, "Bitwarden 官方明文 JSON", "", p.official, disabled).Key("org-export-official").Clicked() {
		p.official = true
	}
	p.flow.footer(c, "org-export", "此文件包含明文密码。确认组织、路径和格式，并允许安全保存？无法完整保留的字段将阻止导出。", p.allowed && p.execute != nil && strings.TrimSpace(p.path) != "", p.start)
}
