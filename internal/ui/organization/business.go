// SPDX-License-Identifier: GPL-3.0-only
// Package organization provides organization business and resource panels.
package organization

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
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
	f.status = i18n.T("org.services.status_running")
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
				f.status = i18n.T("org.services.status_incomplete")
			} else {
				f.status = i18n.T("org.services.status_finished")
			}
		})
	}()
}
func (f *orgBusinessFlow) footer(c *ui.Context, key, warning string, ready bool, start func()) {
	if f.confirm {
		ui.Text(c, warning)
		if kit.Action(c, i18n.T("org.services.confirm_execute"), "", true, f.blocked() || !ready).Key(key + "-confirm").Clicked() {
			start()
		}
		if kit.Action(c, i18n.T("org.services.back_edit"), "", false, f.blocked()).Key(key + "-back").Clicked() {
			f.confirm = false
		}
	} else if kit.Action(c, i18n.T("org.services.review_continue"), "", true, f.blocked() || !ready || f.dispatch == nil).Key(key + "-review").Clicked() {
		f.confirm = true
	}
	if f.running && kit.Action(c, i18n.T("org.services.cancel_review"), "", false, false).Key(key+"-cancel").Clicked() {
		f.cancel()
		f.status = i18n.T("org.services.status_cancelling")
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
			return []string{i18n.T("org.transfer.status_copy_metadata_finished")}, err
		})
		return
	}
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		_, err := execute(ctx, source, target.OrganizationID, target.ID)
		if err != nil {
			return nil, err
		}
		return []string{i18n.T("org.transfer.status_copy_created")}, nil
	})
}
func (p *CopyPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("org.transfer.copy_title")).FontSize(22)
	ui.Text(c, p.source.Title)
	if p.source.RequiresPassword {
		ui.Text(c, i18n.T("org.transfer.copy_reprompt_hint"))
	}
	for i, choice := range p.choices {
		if kit.Action(c, choice.Name, "", p.target == i, p.Flow.blocked() || p.Flow.confirm || !choice.Writable).Key("org-copy-" + choice.ID).Clicked() {
			p.target = i
		}
	}
	if kit.Action(c, i18n.T("org.transfer.copy_resources"), "", p.resources, p.Flow.blocked() || p.Flow.confirm || p.prepareResources == nil || p.resourcesReady == nil).Key("org-copy-resources").Clicked() {
		p.resources = !p.resources
	}
	p.Flow.footer(c, "org-copy", i18n.T("org.transfer.confirm_copy"), p.ready(), p.start)
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
		return []string{i18n.T("org.transfer.status_collections_quarantined")}, err
	})
}
func (p *CollectionPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("org.transfer.collections_title")).FontSize(22)
	ui.Text(c, p.item.Title)
	for _, choice := range p.choices {
		if kit.Action(c, choice.Name, "", p.selected[choice.ID], p.Flow.blocked() || p.Flow.confirm || !choice.Writable).Key("org-assign-" + choice.ID).Clicked() {
			p.selected[choice.ID] = !p.selected[choice.ID]
		}
	}
	p.Flow.footer(c, "org-assign", i18n.T("org.transfer.confirm_collections"), p.execute != nil && p.item.Readable && p.item.Editable, p.start)
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
	panel := NewImportPanel(metadata, i18n.T("org.transfer.format_resources_import"), choices, createAllowed, boundedExecute, dispatch)
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
			rows = append(rows, i18n.Tf("org.transfer.import_counts", len(r.BeforeIDs), len(r.AfterIDs), len(r.AddedIDs)))
			for i, item := range r.Items {
				label := item.SourceID
				if i < len(preview) {
					label = preview[i].Name
				}
				state := i18n.T("org.transfer.status_manual_review")
				if item.Verified {
					state = i18n.T("org.services.status_reread_verified")
				}
				rows = append(rows, fmt.Sprintf("%s: %s; %s", label, state, item.Reason))
			}
		} else {
			rows = append(rows, i18n.T("org.transfer.status_import_unverified"))
		}
		return rows, err
	})
}
func (p *ImportPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("org.transfer.import_title")).FontSize(22)
	ui.Text(c, p.format)
	if len(p.resourcePreview) > 0 {
		ui.Text(c, i18n.T("org.transfer.import_metadata_hint")).MaxLines(4)
	}
	for _, resource := range p.resourcePreview {
		ui.Text(c, i18n.Tf("org.transfer.attachment_summary", resource.FileName, resource.CipherID, resource.AttachmentID, resource.Size)).FontSize(12)
	}
	for _, state := range p.resourceStates {
		if state.Archived || state.Deleted || state.FolderID != nil {
			ui.Text(c, i18n.Tf("org.transfer.restore_state_hint", state.SourceID, state.Archived, state.Deleted)).MaxLines(3)
		}
	}
	// The worker owns and clears the plaintext plan while running. Never read it
	// from the UI after dispatch.
	if !p.Flow.running && !p.Flow.terminal && p.plan != nil {
		for i, item := range p.plan.PreviewItems() {
			ui.Text(c, i18n.Tf("org.transfer.preview_item", i+1, item.Name, item.Type))
			if item.Archived || item.Deleted {
				ui.Text(c, i18n.T("org.transfer.err_import_state_unsupported"))
			}
		}
		for _, source := range p.plan.Collections() {
			ui.Text(c, i18n.Tf("org.transfer.source_collection", source.Name))
			value, set := p.mappings[source.ID]
			if kit.Action(c, i18n.T("org.transfer.create_matching_collection"), "", set && value == "", p.Flow.confirm || !p.createAllowed).Key("org-map-new-" + source.ID).Clicked() {
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
	p.Flow.footer(c, "org-import", i18n.T("org.transfer.confirm_import"), ready, p.start)
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
		return []string{i18n.T("org.transfer.status_export_saved")}, nil
	})
}
func (p *ExportPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.Tf("org.transfer.export_title", p.organizationName)).FontSize(22)
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.path).Label(i18n.T("org.transfer.export_path")).Disabled(disabled)
	if kit.Action(c, i18n.T("org.transfer.format_mygo_v1"), "", !p.official && !p.resources, disabled).Key("org-export-mygo").Clicked() {
		p.official, p.resources = false, false
	}
	if kit.Action(c, i18n.T("org.transfer.format_official"), "", p.official && !p.resources, disabled).Key("org-export-official").Clicked() {
		p.official, p.resources = true, false
	}
	if kit.Action(c, i18n.T("org.transfer.format_resources_export"), "", p.resources, disabled || p.executeResources == nil).Key("org-export-resources").Clicked() {
		p.resources = true
		p.official = false
	}
	p.Flow.footer(c, "org-export", i18n.T("org.transfer.confirm_export"), p.allowed && ((!p.resources && p.execute != nil) || (p.resources && p.executeResources != nil)) && strings.TrimSpace(p.path) != "", p.start)
}
