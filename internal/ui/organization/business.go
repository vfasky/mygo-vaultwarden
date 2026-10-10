// SPDX-License-Identifier: GPL-3.0-only
// Package organization provides organization business and resource panels.
package organization

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
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
	Busy                               func(bool)
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
	if f.Busy != nil {
		f.Busy(true)
	}
	f.confirm = false
	f.status = "正在执行；取消不会回滚已发送的请求。"
	generation := f.generation
	dispatch := f.dispatch
	go func() {
		rows, err := work(ctx)
		cancel()
		dispatch(func() {
			if f.Busy != nil {
				f.Busy(false)
			}
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
		if kit.Action(c, "确认执行", "", true, f.blocked() || !ready).Key(key + "-confirm").Clicked() {
			start()
		}
		if kit.Action(c, "返回修改", "", false, f.blocked()).Key(key + "-back").Clicked() {
			f.confirm = false
		}
	} else if kit.Action(c, "核对并继续", "", true, f.blocked() || !ready || f.dispatch == nil).Key(key + "-review").Clicked() {
		f.confirm = true
	}
	if f.running && kit.Action(c, "取消请求并核对", "", false, false).Key(key+"-cancel").Clicked() {
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

type CollectionChoice struct {
	ID, OrganizationID, Name string
	Writable                 bool
}
type CopyPanel struct {
	Flow             orgBusinessFlow
	source           vaultwarden.VaultEntry
	choices          []CollectionChoice
	target           int
	execute          func(context.Context, string, string, string) (vaultwarden.CipherDocument, error)
	resources        bool
	prepareResources func(context.Context, string, string, string) (*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error)
	resourcesReady   func(*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error)
}

func NewCopyPanel(source vaultwarden.VaultEntry, choices []CollectionChoice, execute func(context.Context, string, string, string) (vaultwarden.CipherDocument, error), dispatch func(func())) *CopyPanel {
	return &CopyPanel{Flow: orgBusinessFlow{dispatch: dispatch}, source: source, choices: append([]CollectionChoice(nil), choices...), target: -1, execute: execute}
}
func NewCopyPanelWithResources(source vaultwarden.VaultEntry, choices []CollectionChoice, execute func(context.Context, string, string, string) (vaultwarden.CipherDocument, error), prepare func(context.Context, string, string, string) (*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error), ready func(*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error), dispatch func(func())) *CopyPanel {
	panel := NewCopyPanel(source, choices, execute, dispatch)
	panel.prepareResources, panel.resourcesReady = prepare, ready
	return panel
}
func (p *CopyPanel) Close() { p.Flow.close(); p.source = vaultwarden.VaultEntry{}; p.choices = nil }
func (p *CopyPanel) ready() bool {
	return ((!p.resources && p.execute != nil) || (p.resources && p.prepareResources != nil && p.resourcesReady != nil)) && p.source.Readable && p.source.Editable && p.target >= 0 && p.target < len(p.choices) && p.choices[p.target].Writable
}
func (p *CopyPanel) start() {
	if !p.ready() {
		return
	}
	source, target, execute := p.source.ID, p.choices[p.target], p.execute
	if p.resources {
		prepare, ready, dispatch := p.prepareResources, p.resourcesReady, p.Flow.dispatch
		p.Flow.run(func(ctx context.Context) ([]string, error) {
			plan, document, err := prepare(ctx, source, target.OrganizationID, target.ID)
			if plan != nil {
				dispatch(func() {
					if p.Flow.closed {
						plan.Clear()
						return
					}
					ready(plan, document, err)
				})
			}
			return []string{"副本元数据步骤结束，附件仍需逐项恢复、同步和下载核验；原件保留。结果未知不能再次创建。"}, err
		})
		return
	}
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		_, err := execute(ctx, source, target.OrganizationID, target.ID)
		if err != nil {
			return nil, err
		}
		return []string{"服务器已返回新副本；请重新读取目标集合。原条目保持原位置。"}, nil
	})
}
func (p *CopyPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, "复制组织条目").FontSize(22)
	ui.Text(c, p.source.Title)
	if p.source.RequiresPassword {
		ui.Text(c, "执行时需通过主密码再次验证；取消验证不会提交。")
	}
	for i, choice := range p.choices {
		if kit.Action(c, choice.Name, "", p.target == i, p.Flow.blocked() || p.Flow.confirm || !choice.Writable).Key("org-copy-" + choice.ID).Clicked() {
			p.target = i
		}
	}
	if kit.Action(c, "完整资源复制（含附件，先验证所有源文件）", "", p.resources, p.Flow.blocked() || p.Flow.confirm || p.prepareResources == nil || p.resourcesReady == nil).Key("org-copy-resources").Clicked() {
		p.resources = !p.resources
	}
	p.Flow.footer(c, "org-copy", "确认在所选组织集合新建独立副本？完整资源复制会先验证源文件，再创建元数据并进入逐文件恢复核验；中途失败不自动重试或删除原件。普通复制不支持附件。", p.ready(), p.start)
}

type CollectionPanel struct {
	Flow     orgBusinessFlow
	item     vaultwarden.VaultEntry
	choices  []CollectionChoice
	selected map[string]bool
	execute  func(context.Context, string, []string) error
}

func NewCollectionPanel(item vaultwarden.VaultEntry, choices []CollectionChoice, current []string, execute func(context.Context, string, []string) error, dispatch func(func())) *CollectionPanel {
	p := &CollectionPanel{Flow: orgBusinessFlow{dispatch: dispatch}, item: item, selected: map[string]bool{}, execute: execute}
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
func (p *CollectionPanel) Close() {
	p.Flow.close()
	p.item = vaultwarden.VaultEntry{}
	p.choices = nil
	p.selected = nil
}
func (p *CollectionPanel) start() {
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
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		err := execute(ctx, id, ids)
		return []string{"集合关联变更可能撤回自身访问。组织保持隔离，需重新验证权限后恢复。"}, err
	})
}
func (p *CollectionPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, "调整组织集合").FontSize(22)
	ui.Text(c, p.item.Title)
	for _, choice := range p.choices {
		if kit.Action(c, choice.Name, "", p.selected[choice.ID], p.Flow.blocked() || p.Flow.confirm || !choice.Writable).Key("org-assign-" + choice.ID).Clicked() {
			p.selected[choice.ID] = !p.selected[choice.ID]
		}
	}
	p.Flow.footer(c, "org-assign", "确认调整所选集合？提交前将持久隔离组织；失去访问后不会自动恢复。", p.execute != nil && p.item.Readable && p.item.Editable, p.start)
}

type ImportPanel struct {
	Flow            orgBusinessFlow
	plan            *vaultwarden.OrganizationImportPlan
	format          string
	choices         []CollectionChoice
	mappings        map[string]string
	createAllowed   bool
	resourcePlan    *vaultwarden.ResourceImportPlan
	resourcePreview []vaultwarden.BackupResource
	resourceStates  []vaultwarden.ResourceItemState
	resourcesReady  func(*vaultwarden.ResourceImportPlan, vaultwarden.OrganizationOperationResult, error)
	execute         func(context.Context, *vaultwarden.OrganizationImportPlan, map[string]string) (vaultwarden.OrganizationOperationResult, error)
}

func NewImportPanel(plan *vaultwarden.OrganizationImportPlan, format string, choices []CollectionChoice, createAllowed bool, execute func(context.Context, *vaultwarden.OrganizationImportPlan, map[string]string) (vaultwarden.OrganizationOperationResult, error), dispatch func(func())) *ImportPanel {
	return &ImportPanel{Flow: orgBusinessFlow{dispatch: dispatch}, plan: plan, format: format, choices: append([]CollectionChoice(nil), choices...), mappings: map[string]string{}, createAllowed: createAllowed, execute: execute}
}
func NewResourceImportPanel(resources *vaultwarden.ResourceImportPlan, choices []CollectionChoice, createAllowed bool, execute func(context.Context, *vaultwarden.OrganizationImportPlan, map[string]string) (vaultwarden.OrganizationOperationResult, error), ready func(*vaultwarden.ResourceImportPlan, vaultwarden.OrganizationOperationResult, error), dispatch func(func())) (*ImportPanel, error) {
	metadata, err := resources.OrganizationRestoreMetadata()
	if err != nil {
		return nil, err
	}
	boundedExecute := execute
	if execute != nil {
		boundedExecute = func(ctx context.Context, plan *vaultwarden.OrganizationImportPlan, mappings map[string]string) (vaultwarden.OrganizationOperationResult, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			return execute(ctx, plan, mappings)
		}
	}
	panel := NewImportPanel(metadata, "MyGo 完整组织资源备份（非官方格式）", choices, createAllowed, boundedExecute, dispatch)
	panel.resourcePlan, panel.resourcePreview, panel.resourceStates, panel.resourcesReady = resources, resources.Resources(), resources.ItemStates(), ready
	return panel, nil
}
func (p *ImportPanel) Close() {
	running := p.Flow.running
	p.Flow.close()
	if !running && p.plan != nil {
		p.plan.Clear()
	}
	if !running {
		p.resourcePlan.Clear()
	}
	p.resourcePlan = nil
	p.plan = nil
	p.mappings = nil
	p.choices = nil
}
func (p *ImportPanel) ready() bool {
	if p.plan == nil || p.execute == nil || (p.resourcePlan != nil && p.resourcesReady == nil) {
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
func (p *ImportPanel) start() {
	if p.Flow.blocked() || !p.Flow.confirm || p.Flow.dispatch == nil || !p.ready() {
		return
	}
	plan, execute := p.plan, p.execute
	resources, resourcesReady, dispatch := p.resourcePlan, p.resourcesReady, p.Flow.dispatch
	preview := plan.PreviewItems()
	mappings := map[string]string{}
	for k, v := range p.mappings {
		mappings[k] = v
	}
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		defer plan.Clear()
		result, err := execute(ctx, plan, mappings)
		if resources != nil {
			dispatch(func() {
				if p.Flow.closed {
					resources.Clear()
					return
				}
				p.resourcePlan = nil
				resourcesReady(resources, result, err)
			})
		}
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
func (p *ImportPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, "组织导入预览与集合映射").FontSize(22)
	ui.Text(c, p.format)
	if len(p.resourcePreview) > 0 {
		ui.Text(c, "此步只创建元数据；附件尚未恢复。后续必须明确映射目标编号、上传、同步和逐文件下载核验。").MaxLines(4)
	}
	for _, resource := range p.resourcePreview {
		ui.Text(c, fmt.Sprintf("附件：%s · %s/%s · %d 字节", resource.FileName, resource.CipherID, resource.AttachmentID, resource.Size)).FontSize(12)
	}
	for _, state := range p.resourceStates {
		if state.Archived || state.Deleted || state.FolderID != nil {
			ui.Text(c, fmt.Sprintf("%s：文件核验后需恢复归档=%t、回收站=%t，并明确映射原文件夹引用。", state.SourceID, state.Archived, state.Deleted)).MaxLines(3)
		}
	}
	// The worker owns and clears the plaintext plan while running. Never read it
	// from the UI after dispatch.
	if !p.Flow.running && !p.Flow.terminal && p.plan != nil {
		for i, item := range p.plan.PreviewItems() {
			ui.Text(c, fmt.Sprintf("%d. %s（类型 %d）", i+1, item.Name, item.Type))
			if item.Archived || item.Deleted {
				ui.Text(c, "此条目有归档或回收站状态，官方组织导入端点不能保留，已阻止提交。")
			}
		}
		for _, source := range p.plan.Collections() {
			ui.Text(c, "源集合："+source.Name)
			value, set := p.mappings[source.ID]
			if kit.Action(c, "创建同名新集合", "", set && value == "", p.Flow.confirm || !p.createAllowed).Key("org-map-new-" + source.ID).Clicked() {
				p.mappings[source.ID] = ""
			}
			for _, target := range p.choices {
				if kit.Action(c, target.Name, "", set && value == target.ID, p.Flow.confirm || !target.Writable).Key("org-map-" + source.ID + "-" + target.ID).Clicked() {
					p.mappings[source.ID] = target.ID
				}
			}
		}
	}
	ready := false
	if !p.Flow.blocked() {
		ready = p.ready()
	}
	p.Flow.footer(c, "org-import", "确认导入预览条目及集合映射？此操作非事务，部分成功不能自动重发。", ready, p.start)
}

type ExportPanel struct {
	Flow                   orgBusinessFlow
	organizationName, path string
	official               bool
	resources              bool
	executeResources       func(context.Context, string) error
	allowed                bool
	execute                func(context.Context, string, bool) error
}

func NewExportPanel(name string, allowed bool, execute func(context.Context, string, bool) error, dispatch func(func())) *ExportPanel {
	return &ExportPanel{Flow: orgBusinessFlow{dispatch: dispatch}, organizationName: name, allowed: allowed, execute: execute}
}
func NewExportPanelWithResources(name string, allowed bool, execute func(context.Context, string, bool) error, resources func(context.Context, string) error, dispatch func(func())) *ExportPanel {
	panel := NewExportPanel(name, allowed, execute, dispatch)
	panel.executeResources = resources
	return panel
}
func (p *ExportPanel) Close() { p.Flow.close(); p.path = "" }
func (p *ExportPanel) start() {
	if !p.allowed || (!p.resources && p.execute == nil) || (p.resources && p.executeResources == nil) || strings.TrimSpace(p.path) == "" {
		return
	}
	path, official, execute, resources, executeResources := p.path, p.official, p.execute, p.resources, p.executeResources
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		var err error
		if resources {
			err = executeResources(ctx, path)
		} else {
			err = execute(ctx, path, official)
		}
		if err != nil {
			return nil, err
		}
		return []string{"已安全保存明文组织文件；请妥善保管并在使用后移除。"}, nil
	})
}
func (p *ExportPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, "导出组织："+p.organizationName).FontSize(22)
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.path).Label("保存到新文件（禁止覆盖已有文件）").Disabled(disabled)
	if kit.Action(c, "MyGo 组织备份 v1", "", !p.official && !p.resources, disabled).Key("org-export-mygo").Clicked() {
		p.official, p.resources = false, false
	}
	if kit.Action(c, "Bitwarden 官方明文 JSON", "", p.official && !p.resources, disabled).Key("org-export-official").Clicked() {
		p.official, p.resources = true, false
	}
	if kit.Action(c, "MyGo 完整组织资源备份（附件与通行密钥，非官方格式）", "", p.resources, disabled || p.executeResources == nil).Key("org-export-resources").Clicked() {
		p.resources = true
		p.official = false
	}
	p.Flow.footer(c, "org-export", "此文件包含明文密码和所选格式支持的文件。完整资源格式最多 1 GiB 文件及 32 MiB 元数据，不是官方 JSON。确认组织、路径和格式，并允许安全保存？无法完整保留的字段将阻止导出。", p.allowed && ((!p.resources && p.execute != nil) || (p.resources && p.executeResources != nil)) && strings.TrimSpace(p.path) != "", p.start)
}
