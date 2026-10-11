// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type organizationEditor struct {
	policyRecovery                                                *vaultwarden.PolicyRecoveryReview
	policies                                                      []vaultwarden.PolicyEntry
	policyType                                                    int
	policyDraft                                                   *vaultwarden.PolicyDraft
	policyConsent                                                 *vaultwarden.PolicyConsent
	groups                                                        []vaultwarden.GroupEntry
	groupID                                                       string
	groupDraft                                                    *vaultwarden.GroupDraft
	groupConsent                                                  *vaultwarden.GroupConsent
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
	invitationAcceptance                                          *vaultwarden.InvitationAcceptance
	trustedRecoveryKey, organizationRecoveryKey                   string
	inviteRole                                                    int
}

func (a *app) clearOrganizationEditor() {
	if a.organizationEditor != nil {
		a.organizationEditor.policyRecovery.Close()
		a.organizationEditor.policyDraft.Close()
		a.organizationEditor.policyConsent.Close()
		a.organizationEditor.groupDraft.Close()
		a.organizationEditor.groupConsent.Close()
		a.organizationEditor.invitationAcceptance.Close()
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

func (a *app) adoptOrganizationIsolation(state *localstore.SnapshotStatus, vault *vaultwarden.VaultData, orgID string) bool {
	return a.adoptOrganizationSnapshot(state, vault, orgID, true)
}

func (a *app) adoptOrganizationSnapshot(state *localstore.SnapshotStatus, vault *vaultwarden.VaultData, orgID string, isolated bool, cleared ...vaultwarden.PendingPolicyMutation) bool {
	if !a.sessionOwnsSnapshot() || state == nil || !state.Available || state.Scope == nil || *state.Scope != *a.liveScope {
		return false
	}
	if state.Revision == "" || state.Revision == a.sessionRevision || state.SnapshotID == "" || state.SnapshotID == a.snapshot.SnapshotID {
		return false
	}
	if vault == nil || vault.Scope != *a.liveScope {
		return false
	}
	found := false
	for _, id := range vault.QuarantinedOrganizations {
		if id == orgID {
			found = true
		}
	}
	if len(cleared) > 1 || (len(cleared) == 1 && (cleared[0].OrganizationID != orgID || a.vault == nil || !a.vault.HasPendingPolicy(cleared[0]))) {
		return false
	}
	if a.vault != nil {
		for _, record := range a.vault.PendingPolicyMutations {
			if len(cleared) == 1 && record == cleared[0] {
				if vault.HasPendingPolicy(record) {
					return false
				}
				continue
			}
			if !vault.HasPendingPolicy(record) {
				return false
			}
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
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || session.AcceptAuthenticatedSnapshot(vault, state.Revision) != nil {
		return false
	}
	previousRevision := a.sessionRevision
	a.snapshot, a.sessionRevision = state, state.Revision
	if err := a.adoptVault(vault); err != nil {
		return false
	}
	a.itemsRevision = state.Revision
	if e := a.organizationEditor; e != nil && e.revision == previousRevision {
		e.revision = state.Revision
		if e.id == orgID {
			e.isolated = isolated
		}
	}
	return true
}

func (a *app) openOrganizationEditor(id string) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil || a.organizationEditor != nil {
		return
	}
	e := &organizationEditor{id: id, revision: a.sessionRevision, owner: id == "", loaded: id == "", collection: i18n.T("org.collection.default_name")}
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
	a.secretInputVersion++
	if id != "" && e.owner {
		a.runOrganizationManagement("load")
	}
}

func (a *app) organizationEditorView(c *ui.Context) {
	e := a.organizationEditor
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c.Key("organization-management")).Padding(18).Gap(12).Children(func() {
			title := i18n.T("org.settings.title")
			if e.id == "" {
				title = i18n.T("org.settings.create_title")
			}
			ui.Text(c, title).FontSize(23)
			ui.Text(c, i18n.T("org.settings.form_hint")).MaxLines(3)
			disabled := a.pending != 0 || e.uncertain
			if e.id == "" {
				a.memberInvitationView(c, e, disabled)
			}
			if e.owner {
				ui.TextInput(c, &e.name).Label(i18n.T("org.settings.name")).Disabled(disabled || !e.loaded)
				ui.TextInput(c, &e.email).Label(i18n.T("org.settings.billing_email")).Disabled(disabled || !e.loaded)
				if e.id == "" {
					ui.TextInput(c, &e.collection).Label(i18n.T("org.collection.default_name_label")).Disabled(disabled)
				}
				if kit.Action(c, i18n.T("org.settings.save_organization"), "", true, disabled || !e.loaded || e.name == "" || e.email == "").Key("organization-save").Clicked() {
					a.runOrganizationManagement("save")
				}
				if !e.loaded && kit.Action(c, i18n.T("org.settings.reload_profile"), "sync", false, disabled).Clicked() {
					a.runOrganizationManagement("load")
				}
			} else {
				ui.Text(c, e.name)
				ui.Text(c, i18n.T("org.settings.owner_only_hint"))
			}
			if e.isolated {
				ui.Text(c, i18n.T("org.settings.isolated_access_hint")).MaxLines(5)
				a.pendingPolicyRecoveryView(c, e, disabled)
				if !a.hasPendingPolicy(e.id) && kit.Action(c, i18n.T("org.settings.confirm_restore_access"), "sync", true, disabled).Clicked() {
					a.runOrganizationManagement("restore")
				}
			}
			if e.id != "" && !e.isolated {
				if e.owner {
					a.organizationRecoveryKeyView(c, e, disabled)
				}
				a.collectionManagementView(c, e, disabled)
				a.policyManagementView(c, e, disabled)
				a.groupManagementView(c, e, disabled)
				a.memberManagementView(c, e, disabled)
				if e.confirmation == "" {
					if kit.Action(c, i18n.T("org.settings.leave_organization"), "", false, disabled).Key("organization-leave").Clicked() {
						e.confirmation = "leave"
					}
					if e.owner && kit.Action(c, i18n.T("org.settings.delete_organization"), "", false, disabled).Key("organization-delete").Clicked() {
						e.confirmation = "delete"
					}
				} else if e.confirmation == "leave" || e.confirmation == "delete" {
					label := i18n.T("org.settings.confirm_leave")
					if e.confirmation == "delete" {
						label = i18n.T("org.settings.confirm_delete")
						ui.Text(c, i18n.T("org.settings.confirm_delete_hint")).MaxLines(4)
						ui.TextInput(c, &e.password).Label(i18n.T("org.settings.master_password")).Password().Disabled(disabled)
					} else {
						ui.Text(c, i18n.T("org.settings.confirm_leave_hint")).MaxLines(4)
					}
					if kit.Action(c, label, "", true, disabled || (e.confirmation == "delete" && e.password == "")).Key("organization-danger-confirm").Clicked() {
						a.runOrganizationManagement(e.confirmation)
					}
					if kit.Action(c, i18n.T("org.settings.cancel_operation"), "", false, a.pending != 0).Clicked() {
						e.confirmation, e.password = "", ""
						a.secretInputVersion++
					}
				}
			}
			if e.uncertain {
				ui.Text(c, i18n.T("org.settings.uncertain_hint")).MaxLines(3)
				if kit.Action(c, i18n.T("org.settings.sync_verify"), "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			}
			if a.pending != 0 {
				if kit.Action(c, i18n.T("org.settings.cancel_and_lock"), "", false, false).Clicked() {
					a.runStorage(localstore.OperationLock)
				}
			} else if kit.Action(c, i18n.T("org.settings.close_management"), "", false, false).Clicked() {
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
	knownOperation := false
	switch operation {
	case "recovery-key-load", "recovery-key-create", "load", "save", "leave", "delete", "restore",
		"collection-load", "collection-save", "collection-delete":
		knownOperation = true
	}
	if !knownOperation && !memberManagementOperation(operation) && !groupManagementOperation(operation) && !policyManagementOperation(operation) {
		return
	}
	if (operation == "recovery-key-load" || operation == "recovery-key-create") && (!e.owner || e.id == "" || (operation == "recovery-key-create" && e.confirmation != operation)) {
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
	if operation == "restore" && a.hasPendingPolicy(e.id) {
		return
	}
	if (operation == "policy-review" || operation == "policy-restore") && (!e.isolated || !a.hasPendingPolicy(e.id)) {
		return
	}
	if operation == "policy-restore" && (e.policyRecovery == nil || e.confirmation != operation) {
		return
	}
	if e.isolated && operation != "restore" && operation != "policy-review" && operation != "policy-restore" {
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
	if groupManagementOperation(operation) {
		if e.id == "" || ((operation == "group-save" || operation == "group-delete") && (e.groupDraft == nil || e.confirmation != operation)) {
			return
		}
	}
	if policyManagementOperation(operation) && (e.id == "" || (operation == "policy-save" && (e.policyDraft == nil || e.policyConsent == nil || e.confirmation != operation))) {
		return
	}
	collectionID := e.collectionID
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	policyRecovery := e.policyRecovery.Clone()
	var pendingRecord vaultwarden.PendingPolicyMutation
	for _, record := range a.vault.PendingPolicyMutations {
		if record.OrganizationID == e.id {
			pendingRecord = record
		}
	}
	policyDraft, policyConsent, policyType := e.policyDraft.Clone(), e.policyConsent.Clone(), e.policyType
	groupDraft, groupConsent, groupID := e.groupDraft.Clone(), e.groupConsent.Clone(), e.groupID
	collectionDraft := e.collectionDraft.Clone()
	members, memberProof := e.members.Clone(), e.memberProof.Clone()
	memberRole := e.memberRole.Clone()
	memberRoleConsent := e.memberRoleConsent.Clone()
	memberID, inviteEmail, inviteRole, verifiedSPKI := e.memberID, e.inviteEmail, e.inviteRole, e.verifiedSPKI
	invitationLink := e.invitationLink
	invitationAcceptance := e.invitationAcceptance.Clone()
	trustedRecoveryKey := e.trustedRecoveryKey
	if operation == "member-accept" {
		e.invitationLink = ""
	}
	id, settings, vault := e.id, vaultwarden.OrganizationSettings{Name: e.name, BillingEmail: e.email, CollectionName: e.collection}, a.vault
	password := []byte(e.password)
	e.password = ""
	a.secretInputVersion++
	prior := a.snapshot
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	a.status = i18n.T("org.settings.status_processing")
	go func() {
		defer policyRecovery.Close()
		var loadedPolicyRecovery *vaultwarden.PolicyRecoveryReview
		defer policyDraft.Close()
		defer policyConsent.Close()
		var loadedPolicy *vaultwarden.PolicyDraft
		var loadedPolicies []vaultwarden.PolicyEntry
		defer groupDraft.Close()
		defer groupConsent.Close()
		var loadedGroup *vaultwarden.GroupDraft
		var loadedGroups []vaultwarden.GroupEntry
		defer invitationAcceptance.Close()
		defer clear(password)
		defer collectionDraft.Close()
		defer members.Close()
		defer memberProof.Close()
		defer memberRole.Close()
		defer memberRoleConsent.Close()
		var loadedInvitation *vaultwarden.InvitationAcceptance
		var recoveryPublicKey string
		var loadedRole *vaultwarden.MemberRoleDraft
		var loadedMembers *vaultwarden.MemberDirectory
		var loadedProof *vaultwarden.MemberConfirmation
		var loadedCollection *vaultwarden.CollectionDraft
		var reply localstore.Reply
		var checkpoint *localstore.SnapshotStatus
		var isolatedVault *vaultwarden.VaultData
		var restoredVault *vaultwarden.VaultData
		isolate := func(cp vaultwarden.SessionCheckpoint) error {
			var pendingPolicy *vaultwarden.PendingPolicyMutation
			if operation == "policy-save" {
				record := policyDraft.PendingMutation()
				pendingPolicy = &record
			}
			reply = callStorage(localstore.Request{Operation: localstore.OperationQuarantineOrganization, PendingPolicy: pendingPolicy, ExpectedRevision: prior.Revision, Scope: &cp.Scope, OrganizationID: id, UnlockKey: cp.UnlockKey, Session: cp.Session})
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
			if !reply.Vault.PreservesPendingPolicies(vault) || (pendingPolicy != nil && !reply.Vault.HasPendingPolicy(*pendingPolicy)) {
				return vaultwarden.ErrIdentity
			}
			prior, checkpoint, isolatedVault = reply.State, reply.State, reply.Vault
			return nil
		}
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpoint = reply.State
			}
			return err
		}
		current := callStorage(localstore.Request{Operation: localstore.OperationStatus})
		var result vaultwarden.OrganizationProfile
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			switch operation {
			case "policy-list":
				loadedPolicies, err = session.OrganizationPolicies(ctx, vault, id, persist)
			case "policy-load":
				loadedPolicy, err = session.OrganizationPolicy(ctx, vault, id, policyType, persist)
			case "policy-save":
				err = session.SaveOrganizationPolicy(ctx, vault, policyDraft, policyConsent, isolate, persist)
			case "group-list":
				loadedGroups, err = session.OrganizationGroups(ctx, vault, id, persist)
			case "group-load":
				loadedGroup, err = session.GroupDetails(ctx, vault, id, groupID, persist)
			case "group-save":
				err = session.SaveGroup(ctx, vault, groupDraft, groupConsent, isolate, persist)
			case "group-delete":
				err = session.DeleteGroup(ctx, vault, groupDraft, isolate, persist)
			case "recovery-key-load", "recovery-key-create":
				recoveryPublicKey, err = session.OrganizationRecoveryPublicKey(ctx, vault, id, operation == "recovery-key-create", persist)
			case "invitation-load":
				loadedInvitation, err = session.PrepareInvitationAcceptance(ctx, vault, invitationLink, persist)
			case "member-role-load":
				loadedRole, err = session.PrepareMemberRole(ctx, vault, members, memberID, persist)
			case "member-role-save":
				err = session.SaveMemberRole(ctx, vault, memberRole, memberRoleConsent, isolate, persist)
			case "member-accept":
				err = session.AcceptPreparedInvitation(ctx, vault, invitationAcceptance, invitationAcceptance.RecoveryRequired(), trustedRecoveryKey, persist)
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
			case "restore", "policy-review", "policy-restore":
				var synced vaultwarden.SyncResult
				if operation == "policy-restore" {
					synced, err = session.SyncForPolicyRecovery(ctx, vault, policyRecovery, persist)
				} else {
					synced, err = session.SyncWithCheckpoint(ctx, persist)
				}
				if err == nil {
					if operation == "restore" {
						err = session.ValidateOrganizationRecoveryCandidate(synced, id)
					}
					if ctx.Err() != nil {
						err = vaultwarden.ErrCancelled
					}
				}
				if err == nil && operation == "policy-review" {
					loadedPolicyRecovery, err = session.ReviewPendingPolicy(synced, pendingRecord)
				}
				if err == nil && operation == "policy-restore" {
					err = session.ValidatePolicyRecovery(synced, policyRecovery)
				}
				if err == nil {
					storageOperation := localstore.OperationRestoreOrganizationAccess
					restoreOrgID := id
					var clearingPolicy *vaultwarden.PendingPolicyMutation
					if operation == "policy-review" {
						storageOperation = localstore.OperationPublishVault
					}
					if operation == "policy-restore" {
						storageOperation = localstore.OperationRestorePolicyAccess
						if !policyRecovery.CanRestoreOrganization() {
							restoreOrgID = ""
						}
						record := policyRecovery.Record()
						clearingPolicy = &record
					}
					reply = callStorage(localstore.Request{
						Operation:        storageOperation,
						ClearingPolicy:   clearingPolicy,
						OrganizationID:   restoreOrgID,
						ExpectedRevision: prior.Revision,
						Scope:            &synced.Scope,
						Credentials:      synced.Credentials,
						PasswordUnlock:   synced.PasswordUnlock,
						Session:          synced.Session,
						Vault:            synced.Vault,
					})
					if !reply.OK {
						err = reply.Failure()
					} else if reply.State == nil || reply.Vault == nil {
						err = vaultwarden.ErrIdentity
					} else {
						checkpoint = reply.State
						if operation == "policy-review" {
							isolatedVault = reply.Vault
						} else {
							restoredVault = reply.Vault
						}
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
		a.postUI(func() {
			if a.epoch == epoch && isolatedVault != nil {
				if operation == "policy-review" {
					if err == nil && a.adoptPolicyRecoveryPreview(epoch, e, checkpoint, isolatedVault, loadedPolicyRecovery) {
						loadedPolicyRecovery = nil // The live editor now owns this proof.
					} else {
						a.stopNetwork()
					}
				} else if !a.adoptOrganizationIsolation(checkpoint, isolatedVault, id) {
					a.stopNetwork()
				}
			}
			if a.epoch == epoch && restoredVault != nil {
				var cleared []vaultwarden.PendingPolicyMutation
				if operation == "policy-restore" {
					cleared = append(cleared, policyRecovery.Record())
				}
				remainIsolated := operation == "policy-restore" && !policyRecovery.CanRestoreOrganization()
				if !a.adoptOrganizationSnapshot(checkpoint, restoredVault, id, remainIsolated, cleared...) {
					a.stopNetwork()
				}
			}
			a.completeOrganizationManagement(epoch, e, operation, result, checkpoint, reply, err, cancel)
			if loadedPolicyRecovery != nil {
				loadedPolicyRecovery.Close()
			}
			if loadedPolicies != nil && a.epoch == epoch && a.organizationEditor == e && err == nil {
				e.policies = loadedPolicies
			}
			if loadedPolicy != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil && checkpoint == nil {
					e.policyDraft.Close()
					e.policyDraft = loadedPolicy
					e.policyConsent.Close()
					e.policyConsent = nil
					e.confirmation = ""
					a.status = i18n.T("org.policy.status_loaded")
				} else {
					loadedPolicy.Close()
					if a.epoch == epoch && err == nil && checkpoint != nil {
						a.status = i18n.T("org.policy.status_credentials_updated")
					}
				}
			}
			if loadedGroups != nil && a.epoch == epoch && a.organizationEditor == e && err == nil {
				e.groups = loadedGroups
			}
			if loadedGroup != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil && checkpoint == nil {
					e.groupDraft.Close()
					e.groupDraft = loadedGroup
					e.groupConsent.Close()
					e.groupConsent = nil
					e.confirmation = ""
					a.status = i18n.T("org.group.status_loaded")
				} else {
					loadedGroup.Close()
				}
			}
			if loadedInvitation != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil && checkpoint != nil {
					// Publishing a refresh checkpoint advances the bound revision.
					// Do not present a consent draft from the previous revision.
					loadedInvitation.Close()
					e.invitationLink = invitationLink
					a.status = i18n.T("org.member.status_invite_credentials_updated")
				} else if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.invitationAcceptance.Close()
					e.invitationAcceptance = loadedInvitation
					e.invitationLink, e.trustedRecoveryKey = "", ""
					a.secretInputVersion++
					a.status = i18n.T("org.member.status_invite_verified")
				} else {
					loadedInvitation.Close()
				}
			}
			if (operation == "recovery-key-load" || operation == "recovery-key-create") && a.epoch == epoch && a.organizationEditor == e && err == nil {
				e.organizationRecoveryKey = recoveryPublicKey
				e.confirmation = ""
				a.status = i18n.T("org.recovery.status_public_key_verified")
			}
			if loadedRole != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.memberRole.Close()
					e.memberRole = loadedRole
					a.status = i18n.T("org.member.status_role_loaded")
				} else {
					loadedRole.Close()
				}
			}
			if loadedMembers != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.members.Close()
					e.members = loadedMembers
					e.inviteRole = 2
					a.status = i18n.T("org.member.status_members_loaded")
				} else {
					loadedMembers.Close()
				}
			}
			if loadedProof != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.memberProof.Close()
					e.memberProof = loadedProof
					e.verifiedSPKI = ""
					a.status = i18n.T("org.member.status_verify_public_key")
				} else {
					loadedProof.Close()
				}
			}
			if loadedCollection != nil {
				if a.epoch == epoch && a.organizationEditor == e && err == nil {
					e.collectionDraft.Close()
					e.collectionDraft = loadedCollection
					a.status = i18n.T("org.collection.status_loaded")
				} else {
					loadedCollection.Close()
				}
			}
		})
	}()
}

func (a *app) completeOrganizationManagement(epoch uint64, e *organizationEditor, operation string, result vaultwarden.OrganizationProfile, checkpoint *localstore.SnapshotStatus, reply localstore.Reply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		e.policyRecovery.Close()
		e.policyDraft.Close()
		e.policyConsent.Close()
		e.groupDraft.Close()
		e.groupConsent.Close()
		e.invitationAcceptance.Close()
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
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
		return
	}
	if err != nil {
		if operation == "member-accept" {
			e.invitationAcceptance.Close()
			e.invitationAcceptance = nil
			e.trustedRecoveryKey, e.confirmation = "", ""
		}
		if operation == "member-role-save" {
			e.memberRoleConsent.Close()
			e.memberRoleConsent = nil
			e.confirmation = ""
		}
		if operation == "policy-restore" {
			e.policyRecovery.Close()
			e.policyRecovery = nil
			e.confirmation = ""
		}
		if operation == "policy-save" {
			e.policyConsent.Close()
			e.policyConsent = nil
			e.confirmation = ""
		}
		var unknown *vaultwarden.MutationUncertainError
		e.uncertain = errors.As(err, &unknown)
		a.syncFailed(reply, err)
		if (operation == "leave" || operation == "delete") && a.vault != nil {
			for _, id := range a.vault.QuarantinedOrganizations {
				if id == e.id || a.organizationEditor == nil {
					a.status = i18n.Tf("org.settings.status_isolated", a.status)
					break
				}
			}
		}
		return
	}
	switch operation {
	case "policy-review", "policy-list", "policy-load", "group-list", "group-load", "invitation-load",
		"recovery-key-load", "recovery-key-create", "collection-load", "collection-access",
		"member-load", "member-prepare", "member-role-load":
		return
	}
	if operation == "restore" || operation == "policy-restore" {
		if operation == "policy-restore" {
			a.syncVault(false)
			a.status = i18n.T("org.policy.status_recovery_verified")
		} else {
			a.status = i18n.T("org.settings.status_access_restored")
		}
		return
	}
	if operation == "load" {
		e.name, e.email, e.loaded = result.Name, result.BillingEmail, true
		a.status = i18n.T("org.settings.status_profile_loaded")
		return
	}
	e.uncertain = true
	if operation == "leave" || operation == "delete" {
		a.status = i18n.T("org.settings.status_operation_submitted")
		a.syncVault(false)
		return
	}
	a.status = i18n.T("org.settings.status_changes_submitted")
	if operation == "collection-save" || operation == "collection-delete" {
		a.status = i18n.T("org.collection.status_changes_submitted")
	}
	a.syncVault(false)
}
