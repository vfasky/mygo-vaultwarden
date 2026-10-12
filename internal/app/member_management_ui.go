// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strconv"
)

func memberManagementOperation(operation string) bool {
	switch operation {
	case "member-role-load", "member-role-save", "invitation-load", "member-accept", "member-load", "member-invite", "member-prepare", "member-confirm", "member-reinvite", "member-revoke", "member-restore", "member-remove":
		return true
	}
	return false
}
func (a *app) validMemberOperation(e *organizationEditor, operation string) bool {
	if operation == "invitation-load" {
		return e.id == "" && e.invitationLink != ""
	}
	if operation == "member-accept" {
		return e.id == "" && e.invitationAcceptance != nil && e.confirmation == operation && (!e.invitationAcceptance.RecoveryRequired() || e.trustedRecoveryKey == e.invitationAcceptance.RecoveryPublicKey())
	}
	admin := false
	for _, org := range a.organizations {
		if org.ID == e.id && (org.Type == 0 || org.Type == 1) {
			admin = true
		}
	}
	if !admin {
		return false
	}
	if operation == "member-load" {
		return true
	}
	if e.members == nil {
		return false
	}
	if operation == "member-prepare" || operation == "member-role-load" {
		return e.memberID != ""
	}
	if e.confirmation != operation {
		return false
	}
	if operation == "member-role-save" {
		return e.memberRole != nil
	}
	if operation == "member-confirm" {
		return e.memberProof != nil && e.verifiedSPKI != "" && e.verifiedSPKI == e.memberProof.PublicKey()
	}
	return true
}
func (a *app) memberInvitationView(c *ui.Context, e *organizationEditor, disabled bool) {
	ui.Text(c, i18n.T("org.member.invite_accept_title")).FontSize(18)
	ui.Text(c, i18n.T("org.member.invite_accept_hint")).MaxLines(4)
	if e.invitationAcceptance == nil {
		ui.TextInput(c, &e.invitationLink).Label(i18n.T("org.member.invite_link")).Password().Disabled(disabled)
		if kit.Action(c.Key("member-accept"), i18n.T("org.member.verify_invitation_policy"), "", true, disabled || e.invitationLink == "").Clicked() {
			a.runOrganizationManagement("invitation-load")
		}
	}
	if e.invitationAcceptance != nil {
		ui.Text(c, i18n.T("org.member.invite_trust_hint")).MaxLines(3)
		label := i18n.T("org.member.confirm_invite_accept")
		if e.invitationAcceptance.RecoveryRequired() {
			ui.Text(c, i18n.T("org.member.invite_recovery_hint")).MaxLines(8)
			ui.TextInput(c, &e.trustedRecoveryKey).Label(i18n.T("org.member.trusted_recovery_public_key")).Disabled(disabled)
			label = i18n.T("org.member.accept_invitation_with_recovery")
		}
		if kit.Action(c.Key("member-accept-confirm"), label, "", true, disabled || (e.invitationAcceptance.RecoveryRequired() && e.trustedRecoveryKey != e.invitationAcceptance.RecoveryPublicKey())).Clicked() {
			e.confirmation = "member-accept"
			a.runOrganizationManagement("member-accept")
		}
		if kit.Action(c, i18n.T("org.member.cancel_invite_accept"), "", false, disabled).Clicked() {
			e.invitationAcceptance.Close()
			e.invitationAcceptance = nil
			e.confirmation, e.invitationLink, e.trustedRecoveryKey = "", "", ""
			a.secretInputVersion++
		}
	}
	if kit.Action(c.Key("member-own-public-key"), i18n.T("org.member.show_sharing_public_key"), "", false, disabled).Clicked() {
		if session, ok := a.session.(*vaultwarden.Session); ok && a.sessionOwnsSnapshot() {
			public, err := session.AccountSharingPublicKey(a.vault)
			if err != nil {
				a.status = vaultwarden.ErrorMessage(err)
			} else {
				e.accountPublicKey = public
			}
		}
	}
	if e.accountPublicKey != "" {
		ui.Text(c, i18n.T("org.member.sharing_public_key_hint")).MaxLines(3)
		ui.TextInput(c, &e.accountPublicKey).Label(i18n.T("org.member.sharing_public_key")).Disabled(disabled)
	}
}

func memberRoleName(role int) string {
	switch role {
	case 0:
		return "role.owner"
	case 1:
		return "role.admin"
	case 2:
		return "role.user"
	case 4:
		return "role.collection_manager"
	}
	return "role.unknown"
}
func memberStatusName(status int) string {
	switch status {
	case -1:
		return i18n.T("org.member.status_revoked")
	case 0:
		return i18n.T("org.member.status_invited")
	case 1:
		return i18n.T("org.member.status_awaiting_key")
	case 2:
		return i18n.T("org.member.status_confirmed")
	}
	return i18n.T("org.member.status_unknown")
}
func (a *app) memberManagementView(c *ui.Context, e *organizationEditor, disabled bool) {
	if !a.validMemberOperation(e, "member-load") {
		return
	}
	ui.Text(c, i18n.T("org.member.title")).FontSize(18)
	if e.members == nil {
		if kit.Action(c.Key("member-load"), i18n.T("org.member.manage_members"), "", false, disabled).Clicked() {
			a.runOrganizationManagement("member-load")
		}
		return
	}
	ui.Text(c, i18n.T("org.member.operations_hint")).MaxLines(4)
	ui.TextInput(c, &e.inviteEmail).Label(i18n.T("org.member.invite_email")).Disabled(disabled)
	ui.Text(c, i18n.Tf("org.member.invite_role", i18n.T(memberRoleName(e.inviteRole))))
	if e.owner {
		for _, role := range []int{2, 4, 1, 0} {
			if kit.Action(c.Key("member-role-"+strconv.Itoa(role)), i18n.Tf("org.member.select_role", i18n.T(memberRoleName(role))), "", false, disabled).Clicked() {
				e.inviteRole = role
			}
		}
	}
	ui.Text(c, i18n.T("org.member.invite_permissions_hint")).MaxLines(3)
	if kit.Action(c.Key("member-invite"), i18n.T("org.member.send_invitation"), "", true, disabled || e.inviteEmail == "").Clicked() {
		e.confirmation = "member-invite"
		e.memberID = ""
	}
	for _, member := range e.members.Members() {
		ui.Text(c, member.Name+" · "+member.Email).MaxLines(2)
		ui.Text(c, i18n.T(memberRoleName(member.Type))+" · "+memberStatusName(member.Status))
		if e.owner || member.Type != 0 {
			if kit.Action(c.Key("member-role-load-"+member.ID), i18n.T("org.member.change_role"), "", false, disabled).Clicked() {
				e.memberID = member.ID
				e.confirmation = ""
				a.runOrganizationManagement("member-role-load")
			}
		}
		operations := []struct{ operation, label string }{}
		if member.Status == 0 {
			operations = append(operations, struct{ operation, label string }{"member-reinvite", i18n.T("org.member.resend_invitation")})
		}
		if member.Status == 1 && (e.owner || member.Type == 2) {
			if kit.Action(c.Key("member-prepare-"+member.ID), i18n.T("org.member.verify_member_key"), "", false, disabled).Clicked() {
				e.memberID = member.ID
				e.confirmation = ""
				e.memberProof.Close()
				e.memberProof = nil
				e.verifiedSPKI = ""
				a.runOrganizationManagement("member-prepare")
			}
		}
		if member.UserID != a.liveScope.Account && (e.owner || member.Type != 0) {
			if member.Status == -1 {
				operations = append(operations, struct{ operation, label string }{"member-restore", i18n.T("org.member.restore_member")})
			} else {
				operations = append(operations, struct{ operation, label string }{"member-revoke", i18n.T("org.member.revoke_access")})
			}
		}
		if e.owner || member.Type == 2 {
			operations = append(operations, struct{ operation, label string }{"member-remove", i18n.T("org.member.remove_member")})
		}
		for _, op := range operations {
			if kit.Action(c.Key(op.operation+"-"+member.ID), op.label, "", false, disabled).Clicked() {
				e.memberID = member.ID
				e.confirmation = op.operation
				e.memberProof.Close()
				e.memberProof = nil
				e.verifiedSPKI = ""
			}
		}
	}
	if e.memberRole != nil {
		draft := e.memberRole
		ui.Text(c, i18n.Tf("org.member.change_role_title", draft.Member().Email)).FontSize(16)
		ui.Text(c, i18n.Tf("org.member.selected_role", i18n.T(memberRoleName(draft.Role))))
		for _, role := range []int{2, 4, 1, 0} {
			if !e.owner && (role == 0 || role == 1 || draft.Member().Type == 1) {
				continue
			}
			if kit.Action(c, i18n.Tf("org.member.set_role", i18n.T(memberRoleName(role))), "", false, disabled).Clicked() {
				draft.Role = role
			}
		}
		if draft.Role == 4 && kit.Action(c, collectionPermissionLabel(i18n.T("org.member.manage_all_collections"), draft.ManageAllCollections), "", false, disabled).Clicked() {
			draft.ManageAllCollections = !draft.ManageAllCollections
		}
		ui.Text(c, i18n.T("org.member.role_permissions_hint")).MaxLines(6)
		if draft.ResetsCollections() {
			ui.Text(c, i18n.T("org.member.reset_collections_hint")).MaxLines(2)
			for _, entry := range draft.ResetCollections() {
				ui.Text(c, entry.Name+" · "+collectionPermissionLabel(i18n.T("org.collection.read_only"), entry.ReadOnly)+" · "+collectionPermissionLabel(i18n.T("org.collection.hide_passwords"), entry.HidePasswords)+" · "+collectionPermissionLabel(i18n.T("org.collection.manage"), entry.Manage)).MaxLines(3)
			}
		}
		if kit.Action(c.Key("member-role-save"), i18n.T("org.member.save_role"), "", true, disabled).Clicked() {
			e.memberID = draft.Member().ID
			e.confirmation = "member-role-save"
		}
		if kit.Action(c, i18n.T("org.member.cancel_role_change"), "", false, disabled).Clicked() {
			draft.Close()
			e.memberRole = nil
			e.confirmation = ""
		}
	}
	if e.memberProof != nil {
		member := e.memberProof.Member()
		ui.Text(c, i18n.Tf("org.member.confirm_member_title", member.Email)).FontSize(16)
		ui.Text(c, i18n.T("org.member.verify_public_key_hint")).MaxLines(5)
		ui.Text(c, e.memberProof.PublicKey()).MaxLines(30)
		ui.TextInput(c, &e.verifiedSPKI).Label(i18n.T("org.member.trusted_public_key")).Disabled(disabled)
		if kit.Action(c.Key("member-confirm"), i18n.T("org.member.confirm_verified_key"), "", true, disabled || e.verifiedSPKI != e.memberProof.PublicKey()).Clicked() {
			e.confirmation = "member-confirm"
			a.runOrganizationManagement("member-confirm")
		}
		if kit.Action(c, i18n.T("org.member.cancel_key_confirmation"), "", false, disabled).Clicked() {
			e.memberProof.Close()
			e.memberProof = nil
			e.verifiedSPKI = ""
			e.confirmation = ""
		}
	}
	if memberManagementOperation(e.confirmation) && e.confirmation != "member-confirm" {
		target := e.inviteEmail
		for _, member := range e.members.Members() {
			if member.ID == e.memberID {
				target = member.Email
			}
		}
		if e.confirmation == "member-remove" {
			kit.ConfirmDialog(c, "member-action", i18n.T("org.member.remove_member"), i18n.Tf("org.member.confirm_operation_hint", target), i18n.T("org.member.confirm_operation"), i18n.T("org.member.cancel_operation"), disabled,
				func() { a.runOrganizationManagement("member-remove") }, func() {
					if !disabled {
						e.confirmation = ""
					}
				})
			return
		}
		ui.Text(c, i18n.Tf("org.member.confirm_operation_hint", target)).MaxLines(4)
		if kit.Action(c.Key("member-action-confirm"), i18n.T("org.member.confirm_operation"), "", true, disabled).Clicked() {
			if e.confirmation == "member-role-save" && e.memberRole != nil {
				e.memberRoleConsent.Close()
				e.memberRoleConsent = e.memberRole.ConfirmCollectionReset()
			}
			a.runOrganizationManagement(e.confirmation)
		}
		if kit.Action(c, i18n.T("org.member.cancel_operation"), "", false, disabled).Clicked() {
			e.confirmation = ""
		}
	}
}
