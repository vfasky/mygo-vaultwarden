// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type connectedPanel interface {
	View(*ui.Context)
	Close()
}
type orgServiceContextKey struct{}

type orgServiceSnapshot struct {
	session *vaultwarden.Session
	vault   *vaultwarden.VaultData
	lease   *controllerLease
	epoch   uint64
	runtime bool
	storage func(localstore.Request) localstore.Reply
}
type orgServicesController struct {
	mu                                                      sync.Mutex
	snapshot                                                orgServiceSnapshot
	closed                                                  bool
	isolation                                               *localstore.Reply
	isolationOrg                                            string
	resourceTarget                                          string
	grantContext                                            context.Context
	grantTarget                                             string
	grant                                                   *vaultwarden.ItemAuthorization
	ctx                                                     context.Context
	cancel                                                  context.CancelFunc
	dispatch                                                func(func())
	baseStorage                                             func(localstore.Request) localstore.Reply
	busy                                                    func(bool)
	panel                                                   connectedPanel
	organizations                                           []vaultwarden.Organization
	collections                                             []vaultwarden.Collection
	entries                                                 []vaultwarden.VaultEntry
	members                                                 []recoveryMemberChoice
	emergencyContacts                                       []vaultwarden.EmergencyContact
	emergencyTrusted                                        bool
	emergencyOnly                                           bool
	selectedOrg, selectedItem, selectedMember, path, status string
	official, resources                                     bool
	prompt                                                  *servicePasswordPrompt
	owner                                                   *app // used only by UI dispatches and View
	runtime                                                 *runtimeVault
}
type servicePasswordPrompt struct {
	challenge       *loginChallenge
	password, label string
}

func (c *orgServicesController) environment() (orgServiceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return orgServiceSnapshot{}, vaultwarden.ErrCancelled
	}
	return c.snapshot, nil
}
func (c *orgServicesController) Close() {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	c.snapshot.lease.revoke()
	c.mu.Unlock()
	if c.prompt != nil {
		c.prompt.challenge.cancel()
		c.prompt.password = ""
		c.prompt = nil
	}
	if c.panel != nil {
		c.panel.Close()
		c.panel = nil
	}
	c.entries = nil
	c.members = nil
}
func (c *orgServicesController) operation(ctx context.Context) (context.Context, func(), orgServiceSnapshot, error) {
	env, err := c.environment()
	if err != nil {
		return nil, func() {}, env, err
	}
	linked, cancel := context.WithTimeout(context.WithValue(ctx, orgServiceContextKey{}, ctx), 5*time.Minute)
	detach := context.AfterFunc(c.ctx, cancel)
	finish := func() { detach(); cancel() }
	if err = env.lease.check(env.storage); err != nil {
		finish()
		return nil, func() {}, env, err
	}
	return linked, finish, env, nil
}
func (c *orgServicesController) checkpoint(env orgServiceSnapshot) func(vaultwarden.SessionCheckpoint) error {
	return func(cp vaultwarden.SessionCheckpoint) error { return env.lease.persist(cp, env.storage) }
}
func (c *orgServicesController) deliver(f func()) {
	c.dispatch(func() {
		a := c.owner
		env, err := c.environment()
		if err == nil && a.orgServices == c && a.epoch == env.epoch && a.session == env.session {
			c.mu.Lock()
			isolation, id := c.isolation, c.isolationOrg
			c.isolation = nil
			c.mu.Unlock()
			if isolation != nil {
				if !a.adoptOrganizationIsolation(isolation.State, isolation.Vault, id) {
					a.stopNetwork()
					a.status = vaultwarden.ErrIdentity.Error()
				} else {
					a.advanceEpoch()
					a.status = "组织操作已进入持久隔离；请在侧栏重新核验，未知结果不会自动重放。"
				}
			} else if cp := env.lease.takeCheckpoint(); cp != nil {
				if !a.adoptSessionCheckpoint(cp) {
					a.stopNetwork()
					a.status = vaultwarden.ErrIdentity.Error()
				} else {
					a.advanceEpoch()
					a.status = "认证凭据已更新，请重新打开组织业务页面。"
				}
			}
		}
		f() // always let the component clean an in-flight result
	})
}
func (c *orgServicesController) isolate(env orgServiceSnapshot, orgID string) func(vaultwarden.SessionCheckpoint) error {
	return func(cp vaultwarden.SessionCheckpoint) error {
		prior, active := env.lease.state()
		if !active || cp.Scope != *prior.Scope {
			return vaultwarden.ErrCancelled
		}
		reply := env.storage(localstore.Request{Operation: "quarantineOrganization", ExpectedRevision: prior.Revision, Scope: &cp.Scope, OrganizationID: orgID, UnlockKey: cp.UnlockKey, Session: cp.Session})
		if !reply.OK {
			return reply.Failure()
		}
		if reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != cp.Scope || !reply.State.Available || reply.State.Revision == prior.Revision || reply.State.Revision == "" || reply.State.SnapshotID == prior.SnapshotID || reply.State.SnapshotID == "" || reply.Vault == nil || reply.Vault.Scope != cp.Scope || !reply.Vault.PreservesPendingPolicies(env.vault) {
			return vaultwarden.ErrIdentity
		}
		found := false
		for _, id := range reply.Vault.QuarantinedOrganizations {
			if id == orgID {
				found = true
			}
		}
		if !found {
			return vaultwarden.ErrIdentity
		}
		env.lease.mu.Lock()
		if !env.lease.active || env.lease.clock.Load() != env.epoch {
			env.lease.mu.Unlock()
			return vaultwarden.ErrCancelled
		}
		env.lease.revision = reply.State.Revision
		env.lease.snapshotID = reply.State.SnapshotID
		env.lease.mu.Unlock()
		c.mu.Lock()
		c.isolation = &reply
		c.isolationOrg = orgID
		c.mu.Unlock()
		return nil
	}
}
func (c *orgServicesController) password(ctx context.Context, label string, env orgServiceSnapshot) ([]byte, error) {
	challenge := newLoginChallenge(ctx, env.epoch)
	c.dispatch(func() {
		if c.owner.orgServices != c || c.owner.epoch != env.epoch || ctx.Err() != nil {
			challenge.cancel()
			return
		}
		if c.prompt != nil {
			c.prompt.challenge.cancel()
			c.prompt.password = ""
		}
		c.prompt = &servicePasswordPrompt{challenge: challenge, label: label}
	})
	return challenge.wait()
}
func (c *orgServicesController) grantFor(ctx context.Context, env orgServiceSnapshot, orgID, id string) (*vaultwarden.ItemAuthorization, error) {
	entries, err := env.session.OrganizationEntries(env.vault)
	if err != nil {
		return nil, err
	}
	var entry *vaultwarden.VaultEntry
	for i := range entries {
		if entries[i].ID == id && entries[i].OrganizationID == orgID {
			entry = &entries[i]
			break
		}
	}
	if entry == nil || !entry.Readable {
		return nil, vaultwarden.ErrPermission
	}
	if !entry.RequiresPassword {
		return nil, nil
	}
	operationContext, _ := ctx.Value(orgServiceContextKey{}).(context.Context)
	if operationContext == nil {
		operationContext = ctx
	}
	c.mu.Lock()
	if c.grantContext == operationContext && c.grantTarget == id && c.grant != nil && time.Now().Before(c.grant.ExpiresAt()) {
		grant := c.grant
		c.mu.Unlock()
		return grant, nil
	}
	c.mu.Unlock()
	password, err := c.password(ctx, "再次验证组织项目 "+id, env)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	grant, err := env.session.AuthorizeOrganizationItem(ctx, env.vault, env.leaseRevision(), id, password)
	if err == nil {
		c.mu.Lock()
		c.grantContext, c.grantTarget, c.grant = operationContext, id, grant
		c.mu.Unlock()
	}
	return grant, err
}
func (s orgServiceSnapshot) leaseRevision() string {
	state, _ := s.lease.state()
	return state.Revision
}
func (c *orgServicesController) allGrants(ctx context.Context, env orgServiceSnapshot, orgID string) (map[string]*vaultwarden.ItemAuthorization, error) {
	entries, err := env.session.OrganizationEntries(env.vault)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, entry := range entries {
		if entry.OrganizationID == orgID && entry.RequiresPassword {
			ids = append(ids, entry.ID)
		}
	}
	grants := map[string]*vaultwarden.ItemAuthorization{}
	if len(ids) == 0 {
		return grants, nil
	}
	password, err := c.password(ctx, "再次验证此组织导出中的受保护项目（每项授权最多30秒）", env)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	for _, id := range ids {
		grant, err := env.session.AuthorizeOrganizationItem(ctx, env.vault, env.leaseRevision(), id, password)
		if err != nil {
			return nil, err
		}
		grants[id] = grant
	}
	return grants, nil
}
func (a *app) openOrgServices()       { a.openOrgServicesWith(a.dispatchUI, a.storageCall) }
func (a *app) openEmergencyServices() { a.openOrgServicesWith(a.dispatchUI, a.storageCall, true) }
func (a *app) openOrgServicesWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply, emergencyMode ...bool) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	a.advanceEpoch()
	baseStorage := storage
	storage = a.routeStorage(storage, a.epoch)
	lease := a.newControllerLease()
	if lease == nil {
		return
	}
	emergencyOnly := len(emergencyMode) > 0 && emergencyMode[0]
	var entries []vaultwarden.VaultEntry
	if !emergencyOnly {
		var err error
		entries, err = session.OrganizationEntries(a.vault)
		if err != nil {
			a.status = err.Error()
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &orgServicesController{emergencyOnly: emergencyOnly, snapshot: orgServiceSnapshot{session, a.vault, lease, a.epoch, a.runtimeVault != nil, storage}, ctx: ctx, cancel: cancel, dispatch: dispatch, baseStorage: baseStorage, busy: a.componentBusy, owner: a, runtime: a.runtimeVault, organizations: append([]vaultwarden.Organization(nil), a.organizations...), collections: append([]vaultwarden.Collection(nil), a.collections...), entries: entries}
	if len(c.organizations) > 0 {
		c.selectedOrg = c.organizations[0].ID
	}
	a.orgServices = c
	a.componentCancel = cancel
	a.category, a.showSettings = "org-services", false
}
func (c *orgServicesController) replacePanel(panel connectedPanel) {
	if c.panel != nil {
		c.panel.Close()
	}
	c.panel = panel
	switch p := panel.(type) {
	case *recoveryPanel:
		p.busy = c.busy
	case *emergencyViewer:
		p.busy = c.busy
	case *orgOperationsPanel:
		p.busy = c.busy
	case *orgEventsPanel:
		p.busy = c.busy
	case *orgCopyPanel:
		p.flow.busy = c.busy
	case *orgCollectionPanel:
		p.flow.busy = c.busy
	case *orgImportPanel:
		p.flow.busy = c.busy
	case *orgExportPanel:
		p.flow.busy = c.busy
	case *orgAPIKeyPanel:
		p.flow.busy = c.busy
	case *orgDirectoryPanel:
		p.flow.busy = c.busy
	}
}
func (c *orgServicesController) choices(orgID string) []orgCollectionChoice {
	out := []orgCollectionChoice{}
	for _, collection := range c.collections {
		if orgID == "" || collection.OrganizationID == orgID {
			out = append(out, orgCollectionChoice{ID: collection.ID, OrganizationID: collection.OrganizationID, Name: collection.Name, Writable: !collection.ReadOnly && !collection.HidePasswords})
		}
	}
	return out
}
func (c *orgServicesController) selectedEntry() vaultwarden.VaultEntry {
	for _, entry := range c.entries {
		if entry.ID == c.selectedItem && entry.OrganizationID == c.selectedOrg {
			return entry
		}
	}
	return vaultwarden.VaultEntry{}
}
func (c *orgServicesController) selectAction(action string) {
	orgID, entry := c.selectedOrg, c.selectedEntry()
	var org vaultwarden.Organization
	for _, row := range c.organizations {
		if row.ID == orgID {
			org = row
		}
	}
	switch action {
	case "state":
		p := newOrgOperationsPanel(orgID, c.entries, func(ctx context.Context, id string, ids []string, action vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error) {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return vaultwarden.OrganizationOperationResult{}, err
			}
			return env.session.ChangeOrganizationCiphers(ctx, env.vault, id, ids, action, nil, c.checkpoint(env))
		}, c.deliver)
		c.replacePanel(p)
	case "events", "member-events", "cipher-events":
		query := vaultwarden.OrganizationEventQuery{OrganizationID: orgID, Start: time.Now().Add(-7 * 24 * time.Hour), End: time.Now()}
		if action == "member-events" {
			query.MemberID = c.selectedMember
		}
		if action == "cipher-events" {
			query.CipherID = entry.ID
		}
		c.replacePanel(newOrgEventsPanel(query, func(ctx context.Context, q vaultwarden.OrganizationEventQuery) (vaultwarden.OrganizationEventPage, error) {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return vaultwarden.OrganizationEventPage{}, err
			}
			return env.session.OrganizationEvents(ctx, env.vault, q, c.checkpoint(env))
		}, c.deliver))
	case "api-key":
		c.replacePanel(newOrgAPIKeyPanel(org.Type == 0, func(ctx context.Context, password []byte, rotate bool, use func(string, []byte, time.Time) error) error {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return err
			}
			return env.session.WithOrganizationAPIKey(ctx, env.vault, orgID, password, rotate, true, use, c.checkpoint(env))
		}, c.deliver))
	case "directory":
		c.replacePanel(newOrgDirectoryPanel(org.Type == 0, org.UseGroups, func(ctx context.Context, key []byte, input vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error) {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return vaultwarden.OrganizationDirectoryResult{}, err
			}
			return env.session.ImportOrganizationDirectory(ctx, env.vault, orgID, key, input, true, c.isolate(env, orgID))
		}, c.deliver))
	case "collections":
		c.replacePanel(newOrgCollectionPanel(entry, c.choices(orgID), entry.CollectionIDs, func(ctx context.Context, id string, ids []string) error {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return err
			}
			grant, err := c.grantFor(ctx, env, orgID, id)
			if err != nil {
				return err
			}
			return env.session.AssignOrganizationCipherCollections(ctx, env.vault, orgID, id, ids, grant, c.isolate(env, orgID), c.checkpoint(env))
		}, c.deliver))
	case "copy":
		c.openCopy(entry)
	case "export":
		c.replacePanel(newOrgExportPanelWithResources(org.Name, org.Type == 0 || org.Type == 1, func(ctx context.Context, path string, official bool) error {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return err
			}
			grants, err := c.allGrants(ctx, env, orgID)
			if err != nil {
				return err
			}
			return exportOrgBackupFormatFile(ctx, env.session, env.vault, orgID, path, grants, true, official, c.checkpoint(env), func() error { return env.lease.check(env.storage) })
		}, func(ctx context.Context, path string) error {
			ctx, done, env, err := c.operation(ctx)
			defer done()
			if err != nil {
				return err
			}
			grants, err := c.allGrants(ctx, env, orgID)
			if err != nil {
				return err
			}
			return exportOrgResourceFile(ctx, env.session, env.vault, orgID, path, grants, true, func() error { return env.lease.check(env.storage) }, c.checkpoint(env))
		}, c.deliver))
	}
}
func (c *orgServicesController) loadMembers() {
	_, err := c.environment()
	if err != nil {
		return
	}
	orgID := c.selectedOrg
	c.busy(true)
	go func() {
		var choices []recoveryMemberChoice
		ctx, done, env, err := c.operation(c.ctx)
		defer done()
		// Filled through the typed directory API; no free-form membership IDs.
		if err == nil {
			directory, e := env.session.OrganizationMembers(ctx, env.vault, orgID, c.checkpoint(env))
			err = e
			if e == nil {
				for _, member := range directory.Members() {
					choices = append(choices, recoveryMemberChoice{OrganizationID: orgID, MemberID: member.ID, Label: member.Email})
				}
				directory.Close()
			}
		}
		c.deliver(func() {
			c.busy(false)
			if c.owner.orgServices != c || c.owner.epoch != env.epoch {
				return
			}
			if err != nil {
				c.status = err.Error()
				return
			}
			c.members = choices
			if len(choices) > 0 {
				c.selectedMember = choices[0].MemberID
			}
		})
	}()
}
func (c *orgServicesController) View(uiContext *ui.Context) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	if c.emergencyOnly {
		c.emergencyView(uiContext)
		return
	}
	if prompt := c.prompt; prompt != nil {
		ui.Column(uiContext).Key(prompt.challenge).Gap(10).Children(func() {
			ui.Text(uiContext, prompt.label).MaxLines(4)
			ui.TextInput(uiContext, &prompt.password).Label("主密码（仅用于本次项目授权）").Password()
			if ui.Button(uiContext, "验证并继续").Clicked() {
				prompt.challenge.submit([]byte(prompt.password))
				prompt.password = ""
				c.prompt = nil
			}
			if ui.Button(uiContext, "取消此操作").Clicked() {
				prompt.challenge.cancel()
				prompt.password = ""
				c.prompt = nil
			}
		})
		return
	}
	ui.Text(uiContext, "组织与账号恢复服务").FontSize(22)
	if ui.Button(uiContext, "我授权的紧急联系人").Disabled(c.owner.pending != 0).Clicked() {
		c.loadEmergency(true)
	}
	if ui.Button(uiContext, "授予我的紧急访问").Disabled(c.owner.pending != 0).Clicked() {
		c.loadEmergency(false)
	}
	if ui.Button(uiContext, "组织恢复登记与管理员恢复").Disabled(c.owner.pending != 0 || len(c.organizations) == 0).Clicked() {
		c.loadRecoveryMembers()
	}
	if !c.emergencyTrusted {
		for _, contact := range c.emergencyContacts {
			if vaultwarden.EmergencyActionAllowed(contact, false, "view") {
				if ui.Button(uiContext, "只读查看："+contact.Name+" · "+contact.Email).Disabled(c.owner.pending != 0).Clicked() {
					c.openEmergencyView(contact)
				}
			}
		}
	}
	if env, err := c.environment(); err == nil {
		if warning := c.owner.targetOutcomeWarnings[env.vault.Scope]; warning != "" {
			ui.Text(uiContext, warning).MaxLines(5)
		}
	}
	for _, org := range c.organizations {
		if ui.Button(uiContext, org.Name).Disabled(c.owner.pending != 0).Clicked() {
			if c.panel != nil {
				c.panel.Close()
				c.panel = nil
			}
			c.selectedOrg = org.ID
			c.selectedItem = ""
			c.members = nil
		}
	}
	for _, entry := range c.entries {
		if entry.OrganizationID == c.selectedOrg {
			if ui.Button(uiContext, entry.Title+" · "+entry.ID).Disabled(c.owner.pending != 0).Clicked() {
				c.selectedItem = entry.ID
			}
		}
	}
	ui.Row(uiContext).Wrap().Gap(6).Children(func() {
		for _, action := range []struct{ id, label string }{{"state", "批量状态"}, {"copy", "复制项目与完整资源"}, {"collections", "分配集合"}, {"export", "组织导出"}, {"events", "组织审计事件"}, {"cipher-events", "所选条目事件"}, {"api-key", "组织 API key"}, {"directory", "Public 目录导入"}} {
			disabled := c.owner.pending != 0 || c.selectedOrg == "" || ((action.id == "copy" || action.id == "collections" || action.id == "cipher-events") && c.selectedItem == "")
			if ui.Button(uiContext, action.label).Disabled(disabled).Clicked() {
				c.selectAction(action.id)
			}
		}
	})
	if ui.Button(uiContext, "读取成员以查看成员事件").Disabled(c.owner.pending != 0 || c.selectedOrg == "").Clicked() {
		c.loadMembers()
	}
	for _, member := range c.members {
		if ui.Button(uiContext, member.Label+" · 成员事件").Disabled(c.owner.pending != 0).Clicked() {
			c.selectedMember = member.MemberID
			c.selectAction("member-events")
		}
	}
	ui.TextInput(uiContext, &c.path).Label("导入文件路径（MyGo / 官方 JSON / 完整资源）").Disabled(c.owner.pending != 0)
	if ui.Button(uiContext, "官方 JSON："+orgBoolLabel(c.official)).Disabled(c.owner.pending != 0).Clicked() {
		c.official = !c.official
		c.resources = false
	}
	if ui.Button(uiContext, "完整资源："+orgBoolLabel(c.resources)).Disabled(c.owner.pending != 0).Clicked() {
		c.resources = !c.resources
		c.official = false
	}
	if ui.Button(uiContext, "读取并预览组织导入").Disabled(c.owner.pending != 0 || c.path == "" || c.selectedOrg == "").Clicked() {
		c.openImport()
	}
	if ui.Button(uiContext, "仅读取完整资源以继续附件恢复（不创建条目）").Disabled(c.owner.pending != 0 || c.path == "" || c.selectedOrg == "").Clicked() {
		c.resources = true
		c.official = false
		c.openImportMode(true)
	}
	if c.panel != nil {
		c.panel.View(uiContext)
	}
	if ui.Button(uiContext, "同步并重新读取（不会自动重放操作）").Disabled(c.owner.pending != 0).Clicked() {
		c.owner.syncVault(false)
	}
	ui.Text(uiContext, c.status).MaxLines(8)
}
func orgBoolLabel(value bool) string {
	if value {
		return "开启"
	}
	return "关闭"
}

// Metadata IDs are used only for display/reconciliation. Every subsequent file
// operation re-reads its target from the newly accepted authenticated snapshot.
func resourceDocumentID(document vaultwarden.CipherDocument) string {
	var data struct{ ID string }
	if json.Unmarshal(document.JSON, &data) != nil {
		return ""
	}
	return data.ID
}
