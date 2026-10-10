// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// A host binds each callback to its current authenticated snapshot, obtains any
// fresh reprompt grant, persists checkpoints, and performs normal authenticated
// sync/publication in refresh. No callback may use the file as write authority.
type ResourceCallbacks struct {
	File     func(context.Context, *vaultwarden.ResourceImportPlan, int, string, string, bool) (vaultwarden.AttachmentUploadResult, error)
	State    func(context.Context, vaultwarden.ResourceItemState, string, string, string) error
	Refresh  func(context.Context) error
	Dispatch func(func())
	Busy     func(bool)
}
type orgResourceStateRow struct {
	source         vaultwarden.ResourceItemState
	target, folder string
	steps          map[string]string
}
type ResourceRestorePanel struct {
	plan                          *vaultwarden.ResourceImportPlan
	rows                          []ResourceRow
	states                        []orgResourceStateRow
	Callbacks                     ResourceCallbacks
	running, Closed, NeedsRefresh bool
	cancel                        context.CancelFunc
	status                        string
}

func NewResourceRestorePanel(plan *vaultwarden.ResourceImportPlan, targets map[string]string, copyOnly bool, callbacks ResourceCallbacks) *ResourceRestorePanel {
	panel := &ResourceRestorePanel{plan: plan, Callbacks: callbacks}
	for _, resource := range plan.Resources() {
		panel.rows = append(panel.rows, ResourceRow{Resource: resource, Target: targets[resource.CipherID], State: ResourceNotStarted})
	}
	if !copyOnly {
		for _, state := range plan.ItemStates() {
			if state.FolderID != nil || state.Archived || state.Deleted {
				row := orgResourceStateRow{source: state, target: targets[state.SourceID], steps: map[string]string{}}
				if state.FolderID != nil {
					row.folder = *state.FolderID
				}
				panel.states = append(panel.states, row)
			}
		}
	}
	return panel
}
func (p *ResourceRestorePanel) Close() {
	p.Closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if !p.running {
		p.plan.Clear()
		p.plan = nil
	}
	p.status = ""
}
func (p *ResourceRestorePanel) Run(work func(context.Context) (func(), error)) {
	if p.Closed || p.running || p.Callbacks.Dispatch == nil || work == nil {
		return
	}
	p.running = true
	if p.Callbacks.Busy != nil {
		p.Callbacks.Busy(true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	p.cancel = cancel
	go func() {
		apply, err := work(ctx)
		cancel()
		p.Callbacks.Dispatch(func() {
			if p.Callbacks.Busy != nil {
				p.Callbacks.Busy(false)
			}
			p.running = false
			p.cancel = nil
			if p.Closed {
				p.plan.Clear()
				p.plan = nil
				return
			}
			if apply != nil {
				apply()
			}
			p.status = i18n.T("org.resource.status_step_finished")
			if err != nil {
				var preparation *ResourcePreparationError
				if errors.As(err, &preparation) {
					p.status = i18n.Tf("org.resource.err_preparation", vaultwarden.ErrorMessage(err))
				} else {
					p.status = i18n.Tf("org.resource.err_unconfirmed", vaultwarden.ErrorMessage(err))
				}
			}
		})
	}()
}
func (p *ResourceRestorePanel) filesVerified(source, target string) bool {
	for _, row := range p.rows {
		if row.Resource.CipherID == source && (row.State != ResourceVerified || row.Target != target) {
			return false
		}
	}
	return target != ""
}
func (p *ResourceRestorePanel) View(c *ui.Context) {
	if p.Closed {
		return
	}
	ui.Text(c, i18n.T("org.resource.title")).FontSize(22)
	ui.Text(c, i18n.T("org.resource.description")).MaxLines(7)
	busy := p.running
	for i := range p.rows {
		row := &p.rows[i]
		ui.Text(c, i18n.Tf("org.resource.file_source_status", row.Resource.FileName, row.Resource.CipherID, row.Resource.AttachmentID, ResourceStateText(row.State))).MaxLines(3)
		ui.TextInput(c, &row.Target).Label(i18n.T("org.resource.target_item")).Disabled(busy || row.State == ResourceVerified)
		ui.TextInput(c, &row.AttachmentID).Label(i18n.T("org.resource.target_attachment")).Disabled(busy || row.State == ResourceVerified)
		if kit.Action(c, i18n.T("org.resource.confirm_upload_once"), "", false, busy || p.NeedsRefresh || row.Target == "" || row.State != ResourceNotStarted || p.Callbacks.File == nil).Key(fmt.Sprintf("org-resource-upload-%d", i)).Clicked() {
			index, target := i, row.Target
			plan, execute := p.plan, p.Callbacks.File
			p.Run(func(ctx context.Context) (func(), error) {
				result, err := execute(ctx, plan, index, target, "", false)
				return func() {
					var preparation *ResourcePreparationError
					if errors.As(err, &preparation) {
						return
					}
					p.rows[index].AttachmentID = result.AttachmentID
					p.rows[index].State = ResourcePendingVerify
					p.NeedsRefresh = true
				}, err
			})
		}
		if kit.Action(c, i18n.T("org.resource.download_verify"), "", false, busy || p.NeedsRefresh || row.Target == "" || row.AttachmentID == "" || row.State == ResourceVerified || p.Callbacks.File == nil).Key(fmt.Sprintf("org-resource-verify-%d", i)).Clicked() {
			index, target, id := i, row.Target, row.AttachmentID
			plan, execute := p.plan, p.Callbacks.File
			p.Run(func(ctx context.Context) (func(), error) {
				_, err := execute(ctx, plan, index, target, id, true)
				return func() {
					if err == nil {
						p.rows[index].State = ResourceVerified
					}
				}, err
			})
		}
	}
	for i := range p.states {
		row := &p.states[i]
		ui.Text(c, i18n.Tf("org.resource.restore_source_state", row.source.SourceID))
		ui.TextInput(c, &row.target).Label(i18n.T("org.resource.mapped_target_item")).Disabled(busy)
		if row.source.FolderID != nil {
			ui.Text(c, i18n.Tf("org.resource.source_folder_hint", *row.source.FolderID)).MaxLines(3)
			ui.TextInput(c, &row.folder).Label(i18n.T("org.resource.target_folder")).Disabled(busy)
		}
		for _, step := range []string{"folder", "archive", "trash"} {
			needed := (step == "folder" && row.source.FolderID != nil) || (step == "archive" && row.source.Archived) || (step == "trash" && row.source.Deleted)
			if !needed {
				continue
			}
			labels := map[string]string{"folder": i18n.T("org.resource.folder_mapping"), "archive": i18n.T("org.resource.archive_state"), "trash": i18n.T("org.resource.trash_state")}
			ui.Text(c, fmt.Sprintf("%s: %s", labels[step], ResourceStateText(row.steps[step])))
			disabled := busy || p.NeedsRefresh || !p.filesVerified(row.source.SourceID, row.target) || p.Callbacks.State == nil || (step == "folder" && row.folder == "")
			if kit.Action(c, i18n.Tf("org.resource.confirm_restore_state", labels[step]), "", false, disabled || row.steps[step] != "").Clicked() {
				index, source, target, folder, operation := i, row.source, row.target, row.folder, step
				execute, fileExecute, plan := p.Callbacks.State, p.Callbacks.File, p.plan
				files := []struct {
					index int
					id    string
				}{}
				for j, file := range p.rows {
					if file.Resource.CipherID == source.SourceID {
						files = append(files, struct {
							index int
							id    string
						}{j, file.AttachmentID})
					}
				}
				p.Run(func(ctx context.Context) (func(), error) {
					var err error
					for _, file := range files {
						if fileExecute == nil {
							err = vaultwarden.ErrPermission
							break
						}
						if _, err = fileExecute(ctx, plan, file.index, target, file.id, true); err != nil {
							break
						}
					}
					if err != nil {
						return nil, &ResourcePreparationError{err}
					}
					err = execute(ctx, source, target, folder, operation)
					return func() {
						var preparation *ResourcePreparationError
						if errors.As(err, &preparation) {
							return
						}
						p.states[index].steps[operation] = ResourcePendingSync
						p.NeedsRefresh = true
					}, err
				})
			}
			if kit.Action(c, i18n.Tf("org.resource.verify_state", labels[step]), "", false, disabled || row.steps[step] == ResourceVerified).Clicked() {
				index, source, target, folder, operation := i, row.source, row.target, row.folder, step
				execute := p.Callbacks.State
				p.Run(func(ctx context.Context) (func(), error) {
					err := execute(ctx, source, target, folder, "check-"+operation)
					return func() {
						if err == nil {
							p.states[index].steps[operation] = ResourceVerified
						}
					}, err
				})
			}
		}
	}
	if kit.Action(c, i18n.T("org.resource.sync_refresh"), "sync", false, busy || p.Callbacks.Refresh == nil).Key("org-resource-refresh").Clicked() {
		execute := p.Callbacks.Refresh
		p.Run(func(ctx context.Context) (func(), error) {
			err := execute(ctx)
			return func() {
				if err == nil {
					p.NeedsRefresh = false
				}
			}, err
		})
	}
	if p.running && kit.Action(c, i18n.T("org.resource.cancel_step_verify"), "", false, false).Clicked() {
		p.cancel()
	}
	if p.status != "" {
		ui.Text(c, p.status).MaxLines(6)
	}
}

func ExecuteResourceFile(
	ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData,
	plan *vaultwarden.ResourceImportPlan, index int, targetOrgID, target, attachment string,
	verify bool, grant *vaultwarden.ItemAuthorization, persist func(vaultwarden.SessionCheckpoint) error,
) (vaultwarden.AttachmentUploadResult, error) {
	if session == nil {
		return vaultwarden.AttachmentUploadResult{}, vaultwarden.ErrExpired
	}
	_, fields, err := session.ReadOrganizationCipher(vault, target, grant)
	if err != nil {
		return vaultwarden.AttachmentUploadResult{}, err
	}
	if targetOrgID == "" || fields.OrganizationID == nil || *fields.OrganizationID != targetOrgID {
		return vaultwarden.AttachmentUploadResult{}, vaultwarden.ErrPermission
	}
	if verify {
		return vaultwarden.AttachmentUploadResult{}, session.VerifyRestoredResource(ctx, vault, target, attachment, plan, index, grant, persist)
	}
	return session.UploadResource(ctx, vault, target, plan, index, true, grant, persist)
}
func ExecuteResourceState(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, source vaultwarden.ResourceItemState, targetOrgID, target, folder, operation string, grant *vaultwarden.ItemAuthorization, persist func(vaultwarden.SessionCheckpoint) error) error {
	if session == nil {
		return vaultwarden.ErrExpired
	}
	document, fields, err := session.ReadOrganizationCipher(vault, target, grant)
	if err != nil {
		return err
	}
	if targetOrgID == "" || fields.OrganizationID == nil || *fields.OrganizationID != targetOrgID {
		return vaultwarden.ErrIdentity
	}
	switch operation {
	case "check-folder":
		if source.FolderID == nil || fields.FolderID == nil || *fields.FolderID != folder {
			return vaultwarden.ErrConflict
		}
		return nil
	case "check-archive":
		if !source.Archived || fields.ArchivedDate == nil {
			return vaultwarden.ErrConflict
		}
		return nil
	case "check-trash":
		if !source.Deleted || fields.DeletedDate == nil {
			return vaultwarden.ErrConflict
		}
		return nil
	case "folder":
		if source.FolderID == nil || folder == "" {
			return vaultwarden.ErrValidation
		}
		fields.FolderID = &folder
		_, err = session.UpdateOrganizationCipher(ctx, vault, document, fields, grant, persist)
		return err
	case "archive", "trash":
		action := vaultwarden.CipherArchive
		if operation == "trash" {
			if !source.Deleted {
				return vaultwarden.ErrValidation
			}
			action = vaultwarden.CipherTrash
		} else if !source.Archived {
			return vaultwarden.ErrValidation
		}
		_, err = session.ChangeOrganizationCiphers(ctx, vault, *fields.OrganizationID, []string{target}, action, map[string]*vaultwarden.ItemAuthorization{target: grant}, persist)
		return err
	default:
		return vaultwarden.ErrValidation
	}
}
