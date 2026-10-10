// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"

	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/organization"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (c *orgServicesController) openCopy(entry vaultwarden.VaultEntry) {
	sourceOrg := entry.OrganizationID
	panel := organization.NewCopyPanelWithResources(entry, c.choices(""), func(ctx context.Context, source, targetOrg, targetCollection string) (vaultwarden.CipherDocument, error) {
		ctx, done, env, err := c.operation(ctx)
		defer done()
		if err != nil {
			return vaultwarden.CipherDocument{}, err
		}
		grant, err := c.grantFor(ctx, env, sourceOrg, source)
		if err != nil {
			return vaultwarden.CipherDocument{}, err
		}
		return env.session.CopyOrganizationCipher(ctx, env.vault, source, targetOrg, targetCollection, grant, c.checkpoint(env))
	}, func(ctx context.Context, source, targetOrg, targetCollection string) (*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error) {
		ctx, done, env, err := c.operation(ctx)
		defer done()
		if err != nil {
			return nil, vaultwarden.CipherDocument{}, err
		}
		grant, err := c.grantFor(ctx, env, sourceOrg, source)
		if err != nil {
			return nil, vaultwarden.CipherDocument{}, err
		}
		c.mu.Lock()
		c.resourceTarget = targetOrg
		c.mu.Unlock()
		return fileio.PrepareOrgResourceCopy(ctx, env.session, env.vault, source, targetOrg, targetCollection, grant, func() error { return env.lease.check(env.storage) }, c.checkpoint(env))
	}, func(plan *vaultwarden.ResourceImportPlan, document vaultwarden.CipherDocument, err error) {
		c.mu.Lock()
		targetOrg := c.resourceTarget
		c.mu.Unlock()
		c.installResources(plan, map[string]string{entry.ID: resourceDocumentID(document)}, targetOrg, true)
		if err != nil {
			c.status = i18n.T("复制元数据结果需核对；请先同步并核对已创建目标编号，不会再次创建。")
		}
	}, c.deliver)
	c.replacePanel(panel)
}
func (c *orgServicesController) openImport() { c.openImportMode(false) }
func (c *orgServicesController) openImportMode(continuing bool) {
	orgID, path, official, resources := c.selectedOrg, c.path, c.official, c.resources
	choices := c.choices(orgID)
	allowed := false
	for _, org := range c.organizations {
		if org.ID == orgID {
			allowed = org.CanCreateCollections()
		}
	}
	c.busy(true)
	go func() {
		ctx, done, env, err := c.operation(c.ctx)
		defer done()
		var plan *vaultwarden.OrganizationImportPlan
		var resourcePlan *vaultwarden.ResourceImportPlan
		if err == nil {
			if resources {
				resourcePlan, plan, err = fileio.ReadOrgResourceImportPlan(ctx, path)
			} else {
				plan, err = fileio.ReadOrgImportFormatPlan(ctx, path, official)
			}
		}
		c.deliver(func() {
			c.busy(false)
			if c.owner.orgServices != c || c.owner.epoch != env.epoch {
				if plan != nil {
					plan.Clear()
				}
				if resourcePlan != nil {
					resourcePlan.Clear()
				}
				return
			}
			if err != nil {
				c.status = err.Error()
				return
			}
			execute := func(ctx context.Context, plan *vaultwarden.OrganizationImportPlan, mappings map[string]string) (vaultwarden.OrganizationOperationResult, error) {
				ctx, finish, current, e := c.operation(ctx)
				defer finish()
				if e != nil {
					return vaultwarden.OrganizationOperationResult{}, e
				}
				return current.session.ImportOrganizationBackup(ctx, current.vault, orgID, plan, mappings, true, c.checkpoint(current))
			}
			if resourcePlan != nil {
				plan.Clear()
				if continuing {
					c.installResources(resourcePlan, map[string]string{}, orgID, false)
					return
				}
				panel, e := organization.NewResourceImportPanel(resourcePlan, choices, allowed, execute, func(resources *vaultwarden.ResourceImportPlan, result vaultwarden.OrganizationOperationResult, err error) {
					targets := map[string]string{}
					if result.ImportReconciliation != nil {
						for _, item := range result.ImportReconciliation.Items {
							if item.Verified && item.SourceID != "" && item.ServerID != "" {
								targets[item.SourceID] = item.ServerID
							}
						}
					}
					c.installResources(resources, targets, orgID, false)
					if err != nil {
						c.status = i18n.T("导入结果需核对；未核实的目标编号保持空白，不会重发元数据。")
					}
				}, c.deliver)
				if e != nil {
					resourcePlan.Clear()
					c.status = e.Error()
					return
				}
				c.replacePanel(panel)
			} else {
				format := i18n.T("MyGo 组织备份")
				if official {
					format = i18n.T("官方明文组织 JSON")
				}
				c.replacePanel(organization.NewImportPanel(plan, format, choices, allowed, execute, c.deliver))
			}
		})
	}()
}
func (c *orgServicesController) installResources(plan *vaultwarden.ResourceImportPlan, targets map[string]string, orgID string, copyOnly bool) {
	callbacks := organization.ResourceCallbacks{Dispatch: c.deliver, Busy: c.busy}
	callbacks.File = func(ctx context.Context, plan *vaultwarden.ResourceImportPlan, index int, target, attachment string, verify bool) (vaultwarden.AttachmentUploadResult, error) {
		ctx, done, env, err := c.operation(ctx)
		defer done()
		if err != nil {
			return vaultwarden.AttachmentUploadResult{}, &organization.ResourcePreparationError{Cause: err}
		}
		grant, err := c.grantFor(ctx, env, orgID, target)
		if err != nil {
			return vaultwarden.AttachmentUploadResult{}, &organization.ResourcePreparationError{Cause: err}
		}
		return organization.ExecuteResourceFile(ctx, env.session, env.vault, plan, index, orgID, target, attachment, verify, grant, c.checkpoint(env))
	}
	callbacks.State = func(ctx context.Context, source vaultwarden.ResourceItemState, target, folder, operation string) error {
		ctx, done, env, err := c.operation(ctx)
		defer done()
		if err != nil {
			return &organization.ResourcePreparationError{Cause: err}
		}
		grant, err := c.grantFor(ctx, env, orgID, target)
		if err != nil {
			return &organization.ResourcePreparationError{Cause: err}
		}
		return organization.ExecuteResourceState(ctx, env.session, env.vault, source, orgID, target, folder, operation, grant, c.checkpoint(env))
	}
	callbacks.Refresh = c.refreshResources
	panel := organization.NewResourceRestorePanel(plan, targets, copyOnly, callbacks)
	panel.NeedsRefresh = true
	c.replacePanel(panel)
	c.mu.Lock()
	c.resourceTarget = orgID
	c.mu.Unlock()
	c.status = i18n.Tf("目标组织：%s。先正常同步并采用认证回执，再逐文件操作；不会自动创建、上传或重放。", orgID)
}

// Called by the resource component's worker. Only the UI installation of a
// normal authenticated publication can advance this plan to another revision.
// UI never waits for the worker or holds a lease mutex across Session/storage.
func (c *orgServicesController) refreshResources(ctx context.Context) error {
	ctx, done, env, err := c.operation(ctx)
	defer done()
	if err != nil {
		return err
	}
	original, active := env.lease.state()
	if !active {
		return vaultwarden.ErrCancelled
	}
	fresh, err := env.session.SyncWithCheckpoint(ctx, c.checkpoint(env))
	defer clearSyncSecrets(&fresh)
	var reply localstore.Reply
	if err == nil {
		prior, valid := env.lease.state()
		if !valid {
			err = vaultwarden.ErrCancelled
		} else {
			reply = env.storage(localstore.Request{Operation: "publishVault", ExpectedRevision: prior.Revision, Scope: &fresh.Scope, Credentials: fresh.Credentials, PasswordUnlock: fresh.PasswordUnlock, Session: fresh.Session, Vault: fresh.Vault})
			if !reply.OK {
				err = reply.Failure()
			} else if reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != fresh.Scope || fresh.Scope != *original.Scope || !reply.State.Available || reply.State.Revision == "" || reply.State.Revision == prior.Revision || reply.State.SnapshotID == "" || reply.Vault == nil || !reply.Vault.PreservesPendingPolicies(env.vault) {
				err = vaultwarden.ErrIdentity
			}
			if err == nil {
				for _, id := range env.vault.QuarantinedOrganizations {
					found := false
					for _, next := range reply.Vault.QuarantinedOrganizations {
						if next == id {
							found = true
						}
					}
					if !found {
						err = vaultwarden.ErrIdentity
					}
				}
			}
		}
	}
	clear(reply.Session)
	reply.Session = nil
	completed := make(chan error, 1)
	c.dispatch(func() {
		a := c.owner
		if a.orgServices != c || a.epoch != env.epoch || a.session != env.session || a.snapshot == nil || a.snapshot.Scope == nil || *a.snapshot.Scope != *original.Scope || a.snapshot.Revision != original.Revision || a.snapshot.SnapshotID != original.SnapshotID || ctx.Err() != nil {
			completed <- vaultwarden.ErrCancelled
			return
		}
		if cp := env.lease.takeCheckpoint(); cp != nil {
			if !a.adoptSessionCheckpoint(cp) {
				a.stopNetwork()
				completed <- vaultwarden.ErrIdentity
				return
			}
		}
		if err != nil {
			a.syncFailed(reply, err)
			completed <- err
			return
		}
		if !env.runtime {
			if e := env.session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); e != nil {
				a.stopNetwork()
				completed <- e
				return
			}
		}
		// Detach exactly this owned continuation while all other drafts are revoked.
		a.orgServices = nil
		a.componentCancel = nil
		a.advanceEpoch()
		a.snapshot = reply.State
		a.sessionRevision = reply.State.Revision
		if e := a.adoptVault(reply.Vault); e != nil {
			c.Close()
			a.stopNetwork()
			completed <- e
			return
		}
		a.itemsRevision = reply.State.Revision
		lease := a.newControllerLease()
		if lease == nil {
			c.Close()
			a.stopNetwork()
			completed <- vaultwarden.ErrIdentity
			return
		}
		c.mu.Lock()
		c.snapshot = orgServiceSnapshot{env.session, reply.Vault, lease, a.epoch, env.runtime, a.routeStorage(c.baseStorage, a.epoch)}
		c.grant = nil
		c.grantContext = nil
		targetOrg := c.resourceTarget
		c.mu.Unlock()
		c.organizations = append([]vaultwarden.Organization(nil), a.organizations...)
		c.collections = append([]vaultwarden.Collection(nil), a.collections...)
		c.entries, _ = env.session.OrganizationEntries(reply.Vault)
		a.orgServices = c
		a.componentCancel = c.cancel
		authorized := false
		for _, org := range c.organizations {
			if org.ID == targetOrg {
				authorized = true
			}
		}
		if !authorized {
			if c.panel != nil {
				c.panel.Close()
				c.panel = nil
			}
			c.status = i18n.T("目标组织权限已变化，资源表单已关闭；原文件与服务器数据保留。")
			completed <- vaultwarden.ErrPermission
			return
		}
		c.status = i18n.T("已采用完整认证同步；请继续显式文件核验，不会自动重放操作。")
		a.startNotifications(c.dispatch, c.baseStorage)
		completed <- nil
	})
	select {
	case err := <-completed:
		return err
	case <-ctx.Done():
		return vaultwarden.ErrCancelled
	}
}
