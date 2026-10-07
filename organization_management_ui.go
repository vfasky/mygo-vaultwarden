// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type organizationEditor struct {
	id, revision, name, email, collection, password, confirmation string
	owner, loaded, uncertain, isolated                            bool
	collectionID                                                  string
	collectionDraft                                               *vaultwarden.CollectionDraft
	members                                                       *vaultwarden.MemberDirectory
	memberProof                                                   *vaultwarden.MemberConfirmation
	memberRole                                                    *vaultwarden.MemberRoleDraft
	memberRoleConsent                                             *vaultwarden.MemberRoleConsent
	memberID, inviteEmail, verifiedSPKI                           string
	invitationLink, accountPublicKey                              string
	inviteRole                                                    int
}

func (a *app) clearOrganizationEditor() {
	if a.organizationEditor != nil {
		a.organizationEditor.collectionDraft.Close()
		a.organizationEditor.members.Close()
		a.organizationEditor.memberProof.Close()
		a.organizationEditor.memberRole.Close()
		a.organizationEditor.memberRoleConsent.Close()
		*a.organizationEditor = organizationEditor{}
		a.organizationEditor = nil
		a.secretInputVersion++
	}
}

func (a *app) adoptOrganizationIsolation(state *snapshotStatus, vault *vaultwarden.VaultData, orgID string) bool {
	return a.adoptOrganizationSnapshot(state, vault, orgID, true)
}

func (a *app) adoptOrganizationSnapshot(state *snapshotStatus, vault *vaultwarden.VaultData, orgID string, isolated bool) bool {
	if !a.sessionOwnsSnapshot() || state == nil || !state.Available || state.Scope == nil || *state.Scope != *a.liveScope || state.Revision == "" || state.Revision == a.sessionRevision || state.SnapshotID == "" || state.SnapshotID == a.snapshot.SnapshotID || vault == nil || vault.Scope != *a.liveScope {
		return false
	}
	found := false
	for _, id := range vault.QuarantinedOrganizations {
		if id == orgID {
			found = true
		}
	}
	if found != isolated {
		return false
	}
	if a.vault != nil {
		for _, priorID := range a.vault.QuarantinedOrganizations {
			if !isolated && priorID == orgID {
				continue
			}
			retained := false
			for _, id := range vault.QuarantinedOrganizations {
				if id == priorID {
					retained = true
				}
			}
			if !retained {
				return false
			}
		}
	}
	a.snapshot, a.sessionRevision = state, state.Revision
	if err := a.adoptVault(vault); err != nil {
		return false
	}
	a.itemsRevision = state.Revision
	return true
}

func (a *app) openOrganizationEditor(id string) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil || a.organizationEditor != nil {
		return
	}
	e := &organizationEditor{id: id, revision: a.sessionRevision, owner: id == "", loaded: id == "", collection: "默认集合"}
	if id != "" {
		found := false
		for _, org := range a.organizations {
			if org.ID == id {
				e.name, e.owner, found = org.Name, org.Type == 0, true
			}
		}
		for _, org := range a.isolatedOrganizations {
			if org.ID == id {
				e.name, e.isolated, found = org.Name, true, true
			}
		}
		if !found {
			return
		}
	}
	a.organizationEditor = e
	a.showSettings = false
	a.secretInputVersion++
	if id != "" && e.owner {
		a.runOrganizationManagement("load")
	}
}

func (a *app) organizationEditorView(c *ui.Context) {
	e := a.organizationEditor
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Key("organization-management").Padding(18).Gap(12).Children(func() {
			title := "管理组织"
			if e.id == "" {
				title = "创建组织"
			}
			ui.Text(c, title).FontSize(23)
			ui.Text(c, "同步会关闭此表单。组织名称与账单邮箱由服务器明文保存，集合名称端到端加密。").MaxLines(3)
			disabled := a.pending != 0 || e.uncertain
			if e.id == "" {
				a.memberInvitationView(c, e, disabled)
			}
			if e.owner {
				ui.TextInput(c, &e.name).Label("组织名称").Disabled(disabled || !e.loaded)
				ui.TextInput(c, &e.email).Label("账单邮箱").Disabled(disabled || !e.loaded)
				if e.id == "" {
					ui.TextInput(c, &e.collection).Label("默认集合名称").Disabled(disabled)
				}
				if action(c, "保存组织", "", true, disabled || !e.loaded || e.name == "" || e.email == "").Key("organization-save").Clicked() {
					a.runOrganizationManagement("save")
				}
				if !e.loaded && action(c, "重新加载组织资料", "sync", false, disabled).Clicked() {
					a.runOrganizationManagement("load")
				}
			} else {
				ui.Text(c, e.name)
				ui.Text(c, "组织资料仅所有者可以修改。")
			}
			if e.isolated {
				ui.Text(c, "此组织的本机访问已隔离。只有重新连接服务器并核验您当前已确认的成员身份和组织密钥后，才可恢复本机访问；不会重新提交退出或删除请求。").MaxLines(5)
				if action(c, "确认重新核验并恢复访问", "sync", true, disabled).Clicked() {
					a.runOrganizationManagement("restore")
				}
			}
			if e.id != "" && !e.isolated {
				a.collectionManagementView(c, e, disabled)
				a.memberManagementView(c, e, disabled)
				if e.confirmation == "" {
					if action(c, "退出组织", "", false, disabled).Key("organization-leave").Clicked() {
						e.confirmation = "leave"
					}
					if e.owner && action(c, "删除组织", "", false, disabled).Key("organization-delete").Clicked() {
						e.confirmation = "delete"
					}
				} else if e.confirmation == "leave" || e.confirmation == "delete" {
					label := "确认退出组织"
					if e.confirmation == "delete" {
						label = "确认永久删除组织"
						ui.Text(c, "这会永久删除整个组织及其密码库，影响所有成员，无法恢复。继续将立即隔离本机此组织访问，其他密码库保留。请输入当前账号主密码确认。").MaxLines(4)
						ui.TextInput(c, &e.password).Label("当前账号主密码").Password().Disabled(disabled)
					} else {
						ui.Text(c, "继续将立即隔离本机此组织访问，其他密码库保留。退出后需要重新邀请才能加入；最后一位所有者须先转移所有权，服务器会再次核验。").MaxLines(4)
					}
					if action(c, label, "", true, disabled || (e.confirmation == "delete" && e.password == "")).Key("organization-danger-confirm").Clicked() {
						a.runOrganizationManagement(e.confirmation)
					}
					if action(c, "取消组织操作", "", false, a.pending != 0).Clicked() {
						e.confirmation, e.password = "", ""
						a.secretInputVersion++
					}
				}
			}
			if e.uncertain {
				ui.Text(c, "请求可能已部分执行。请同步核对组织列表与资料，此表单不能再次提交。").MaxLines(3)
				if action(c, "同步核对组织", "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			}
			if a.pending != 0 {
				if action(c, "取消并锁定密码库", "", false, false).Clicked() {
					a.runStorage("lock")
				}
			} else if action(c, "关闭组织管理", "", false, false).Clicked() {
				a.clearOrganizationEditor()
			}
		})
	})
}

func (a *app) runOrganizationManagement(operation string) {
	e := a.organizationEditor
	if a.pending != 0 || e == nil || e.uncertain || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision || a.vault == nil {
		return
	}
	if operation != "load" && operation != "save" && operation != "leave" && operation != "delete" && operation != "restore" && operation != "collection-load" && operation != "collection-save" && operation != "collection-delete" && !memberManagementOperation(operation) {
		return
	}
	if (operation == "leave" || operation == "delete") && (e.confirmation != operation || e.id == "") {
		return
	}
	if (operation == "save" || operation == "load" || operation == "delete") && !e.owner {
		return
	}
	if operation == "restore" && !e.isolated {
		return
	}
	if e.isolated && operation != "restore" {
		return
	}
	if operation == "save" && !e.loaded {
		return
	}
	if operation == "collection-delete" && e.confirmation != operation {
		return
	}
	if (operation == "collection-save" || operation == "collection-delete" || operation == "collection-access") && e.collectionDraft == nil {
		return
	}
	if operation == "collection-save" && e.collectionDraft != nil && e.collectionDraft.AccessChanged() && e.confirmation != "collection-access-save" {
		return
	}
	if memberManagementOperation(operation) && !a.validMemberOperation(e, operation) {
		return
	}
	collectionID := e.collectionID
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	collectionDraft := e.collectionDraft.Clone()
	members, memberProof := e.members.Clone(), e.memberProof.Clone()
	memberRole := e.memberRole.Clone()
	memberRoleConsent := e.memberRoleConsent.Clone()
	memberID, inviteEmail, inviteRole, verifiedSPKI := e.memberID, e.inviteEmail, e.inviteRole, e.verifiedSPKI
	invitationLink := e.invitationLink
	if operation == "member-accept" {
		e.invitationLink = ""
	}
	id, settings, vault := e.id, vaultwarden.OrganizationSettings{Name: e.name, BillingEmail: e.email, CollectionName: e.collection}, a.vault
	password := []byte(e.password)
	e.password = ""
	a.secretInputVersion++
	prior := a.snapshot
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	a.status = "正在处理组织请求…"
	go func() {
		defer clear(password)
		defer collectionDraft.Close()
		defer members.Close()
		defer memberProof.Close()
		defer memberRole.Close()
		defer memberRoleConsent.Close()
		var loadedRole *vaultwarden.MemberRoleDraft
		var loadedMembers *vaultwarden.MemberDirectory
		var loadedProof *vaultwarden.MemberConfirmation
		var loadedCollection *vaultwarden.CollectionDraft
		var reply storageReply
		var checkpoint *snapshotStatus
		var isolatedVault *vaultwarden.VaultData
		var restoredVault *vaultwarden.VaultData
		isolate := func(cp vaultwarden.SessionCheckpoint) error {
			reply = callStorage(storageRequest{Operation: "quarantineOrganization", ExpectedRevision: prior.Revision, Scope: &cp.Scope, OrganizationID: id, UnlockKey: cp.UnlockKey, Session: cp.Session})
			if !reply.OK || reply.State == nil || reply.Vault == nil {
				return vaultwarden.ErrCheckpoint
			}
			if reply.State.Scope == nil || *reply.State.Scope != cp.Scope || reply.State.Revision == "" || reply.State.Revision == prior.Revision || !reply.State.Available || reply.State.SnapshotID == "" || reply.State.SnapshotID == prior.SnapshotID || reply.Vault.Scope != cp.Scope {
				return vaultwarden.ErrIdentity
			}
			found := false
			for _, org := range reply.Vault.QuarantinedOrganizations {
				if org == id {
					found = true
				}
			}
			if !found {
				return vaultwarden.ErrIdentity
			}
			prior, checkpoint, isolatedVault = reply.State, reply.State, reply.Vault
			return nil
		}
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpoint = reply.State
			}
			return err
		}
		current := callStorage(storageRequest{Operation: "status"})
		var result vaultwarden.OrganizationProfile
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			switch operation {
			case "member-role-load":
				loadedRole, err = session.PrepareMemberRole(ctx, vault, members, memberID, persist)
			case "member-role-save":
				err = session.SaveMemberRole(ctx, vault, memberRole, memberRoleConsent, isolate, persist)
			case "member-accept":
				err = session.AcceptOrganizationInvitation(ctx, vault, invitationLink, persist)
			case "member-load":
				loadedMembers, err = session.OrganizationMembers(ctx, vault, id, persist)
			case "member-invite":
				err = session.InviteOrganizationMember(ctx, vault, members, inviteEmail, inviteRole, persist)
			case "member-prepare":
				loadedProof, err = session.PrepareMemberConfirmation(ctx, vault, members, memberID, persist)
			case "member-confirm":
				err = session.ConfirmOrganizationMember(ctx, vault, memberProof, verifiedSPKI, persist)
			case "member-reinvite", "member-revoke", "member-restore", "member-remove":
				err = session.ChangeOrganizationMember(ctx, vault, members, memberID, operation[len("member-"):], isolate, persist)
			case "collection-load":
				loadedCollection, err = session.CollectionDetails(ctx, vault, id, collectionID, persist)
			case "collection-access":
				loadedCollection, err = session.CollectionAccessDetails(ctx, vault, collectionDraft, persist)
			case "collection-save":
				err = session.SaveCollection(ctx, vault, collectionDraft, isolate, persist)
			case "collection-delete":
				err = session.DeleteCollection(ctx, vault, collectionDraft, isolate, persist)
			case "restore":
				var synced vaultwarden.SyncResult
				synced, err = session.SyncWithCheckpoint(ctx, persist)
				if err == nil {
					var organizations []vaultwarden.Organization
					organizations, _, err = session.Organizations(synced.Vault)
					found := false
					for _, org := range organizations {
						if org.ID == id {
							found = true
						}
					}
					if !found && err == nil {
						err = vaultwarden.ErrPermission
					}
					if ctx.Err() != nil {
						err = vaultwarden.ErrCancelled
					}
				}
				if err == nil {
					reply = callStorage(storageRequest{Operation: "restoreOrganizationAccess", OrganizationID: id, ExpectedRevision: prior.Revision, Scope: &synced.Scope, Credentials: synced.Credentials, PasswordUnlock: synced.PasswordUnlock, Session: synced.Session, Vault: synced.Vault})
					if !reply.OK {
						err = reply.failure()
					} else if reply.State == nil || reply.Vault == nil {
						err = vaultwarden.ErrIdentity
					} else {
						checkpoint, restoredVault = reply.State, reply.Vault
					}
				}
				clear(synced.Session)
				if synced.PasswordUnlock != nil {
					clear(synced.PasswordUnlock.Key)
				}
				for i := range synced.Credentials {
					synced.Credentials[i].Password = ""
				}
			case "load":
				result, err = session.OrganizationProfile(ctx, vault, id, persist)
			case "save":
				result, err = session.SaveOrganization(ctx, vault, id, settings, persist)
			case "leave":
				err = session.LeaveOrganization(ctx, vault, id, isolate, persist)
			case "delete":
				err = session.DeleteOrganization(ctx, vault, id, password, isolate, persist)
			}
		}
		a.window.Update(func() {
			if a.epoch == epoch && isolatedVault != nil {
				if !a.adoptOrganizationIsolation(checkpoint, isolatedVault, id) {
					a.stopNetwork()
				}
			}
			if a.epoch == epoch && restoredVault != nil {
				if !a.adoptOrganizationSnapshot(checkpoint, restoredVault, id, false) {
					a.stopNetwork()
				}
			}
			a.completeOrganizationManagement(epoch, e, operation, result, checkpoint, reply, err, cancel)
			if loadedRole != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.memberRole.Close()
					e.memberRole = loadedRole
					a.status = "已加载成员角色及完整直接分配"
				} else {
					loadedRole.Close()
				}
			}
			if loadedMembers != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.members.Close()
					e.members = loadedMembers
					e.inviteRole = 2
					a.status = "成员列表已加载"
				} else {
					loadedMembers.Close()
				}
			}
			if loadedProof != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.memberProof.Close()
					e.memberProof = loadedProof
					e.verifiedSPKI = ""
					a.status = "请与受邀人通过可信渠道核验完整公钥"
				} else {
					loadedProof.Close()
				}
			}
			if loadedCollection != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.collectionDraft.Close()
					e.collectionDraft = loadedCollection
					a.status = "集合详情已加载；保存名称会保留原访问配置。"
				} else {
					loadedCollection.Close()
				}
			}
		})
	}()
}

func (a *app) completeOrganizationManagement(epoch uint64, e *organizationEditor, operation string, result vaultwarden.OrganizationProfile, checkpoint *snapshotStatus, reply storageReply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		e.collectionDraft.Close()
		e.members.Close()
		e.memberProof.Close()
		e.memberRole.Close()
		e.memberRoleConsent.Close()
		*e = organizationEditor{}
		return
	}
	a.cancel = nil
	if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
		return
	}
	if err != nil {
		if operation == "member-role-save" {
			e.memberRoleConsent.Close()
			e.memberRoleConsent = nil
			e.confirmation = ""
		}
		var unknown *vaultwarden.MutationUncertainError
		e.uncertain = errors.As(err, &unknown)
		a.syncFailed(reply, err)
		if (operation == "leave" || operation == "delete") && a.vault != nil {
			for _, id := range a.vault.QuarantinedOrganizations {
				if id == e.id || a.organizationEditor == nil {
					a.status += " 该组织的本机访问已隔离；可从侧栏重新核验访问，原操作不会重试。"
					break
				}
			}
		}
		return
	}
	if operation == "collection-load" || operation == "collection-access" || operation == "member-load" || operation == "member-prepare" || operation == "member-role-load" {
		return
	}
	if operation == "restore" {
		a.status = "已重新核验成员身份并恢复该组织的本机访问。"
		return
	}
	if operation == "load" {
		e.name, e.email, e.loaded = result.Name, result.BillingEmail, true
		a.status = "组织资料已加载"
		return
	}
	e.uncertain = true
	if operation == "leave" || operation == "delete" {
		a.status = "组织操作已提交，本机该组织已隔离。其他密码库仍可使用；请同步核对最新状态。"
		a.syncVault(false)
		return
	}
	a.status = "组织修改已提交，正在同步核对…"
	if operation == "collection-save" || operation == "collection-delete" {
		a.status = "集合修改已提交，正在同步核对；若侧栏出现“重新核验”，请完成核验以恢复组织访问。"
	}
	a.syncVault(false)
}
