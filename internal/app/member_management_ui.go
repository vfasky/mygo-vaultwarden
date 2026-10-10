// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
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
	ui.Text(c, "接受组织邀请").FontSize(18)
	ui.Text(c, "粘贴当前服务器发给此账号的邀请链接，先核验邀请策略。接受后仍需管理员核验您的公钥并确认。").MaxLines(4)
	if e.invitationAcceptance == nil {
		ui.TextInput(c, &e.invitationLink).Label("邮件邀请链接").Password().Disabled(disabled)
		if kit.Action(c, "核验邀请策略", "", true, disabled || e.invitationLink == "").Key("member-accept").Clicked() {
			a.runOrganizationManagement("invitation-load")
		}
	}
	if e.invitationAcceptance != nil {
		ui.Text(c, "请确认邮件来自您信任的组织。邀请令牌只发送给当前已登录服务器；接受后仍需管理员确认组织访问。").MaxLines(3)
		label := "确认接受邀请"
		if e.invitationAcceptance.RecoveryRequired() {
			ui.Text(c, "此组织要求加入账号恢复。继续会将您的账号解密密钥用组织公钥加密交给组织；拥有组织恢复私钥的管理员将能够恢复账号并访问您的个人密码库。请通过独立可信渠道向组织所有者核验完整公钥。").MaxLines(8)
			ui.TextInput(c, &e.trustedRecoveryKey).Label("可信渠道取得的组织恢复公钥（完整 DER/SPKI）").Disabled(disabled)
			label = "同意账号恢复并接受邀请"
		}
		if kit.Action(c, label, "", true, disabled || (e.invitationAcceptance.RecoveryRequired() && e.trustedRecoveryKey != e.invitationAcceptance.RecoveryPublicKey())).Key("member-accept-confirm").Clicked() {
			e.confirmation = "member-accept"
			a.runOrganizationManagement("member-accept")
		}
		if kit.Action(c, "取消接受邀请", "", false, disabled).Clicked() {
			e.invitationAcceptance.Close()
			e.invitationAcceptance = nil
			e.confirmation, e.invitationLink, e.trustedRecoveryKey = "", "", ""
			a.secretInputVersion++
		}
	}
	if kit.Action(c, "查看我的共享公钥", "", false, disabled).Key("member-own-public-key").Clicked() {
		if session, ok := a.session.(*vaultwarden.Session); ok && a.sessionOwnsSnapshot() {
			public, err := session.AccountSharingPublicKey(a.vault)
			if err != nil {
				a.status = err.Error()
			} else {
				e.accountPublicKey = public
			}
		}
	}
	if e.accountPublicKey != "" {
		ui.Text(c, "将完整公钥通过独立可信渠道交给管理员，用于核验共享对象。公钥不是密码；不得发送私钥或主密码。").MaxLines(3)
		ui.TextInput(c, &e.accountPublicKey).Label("我的完整 DER/SPKI 公钥（可选择复制）").Disabled(disabled)
	}
}

func memberRoleName(role int) string {
	switch role {
	case 0:
		return "所有者"
	case 1:
		return "管理员"
	case 2:
		return "普通成员"
	case 4:
		return "集合经理"
	}
	return "未知角色"
}
func memberStatusName(status int) string {
	switch status {
	case -1:
		return "已撤销"
	case 0:
		return "等待接受邀请"
	case 1:
		return "等待公钥确认"
	case 2:
		return "已确认"
	}
	return "未知状态"
}
func (a *app) memberManagementView(c *ui.Context, e *organizationEditor, disabled bool) {
	if !a.validMemberOperation(e, "member-load") {
		return
	}
	ui.Text(c, "组织成员").FontSize(18)
	if e.members == nil {
		if kit.Action(c, "管理成员与邀请", "", false, disabled).Key("member-load").Clicked() {
			a.runOrganizationManagement("member-load")
		}
		return
	}
	ui.Text(c, "每次只提交一个成员操作。成功后同步核对；失败可能已经执行，请勿重复发送邀请。最后所有者保护由服务器实时检查。").MaxLines(4)
	ui.TextInput(c, &e.inviteEmail).Label("邀请邮箱").Disabled(disabled)
	ui.Text(c, "邀请角色："+memberRoleName(e.inviteRole))
	if e.owner {
		for _, role := range []int{2, 4, 1, 0} {
			if kit.Action(c, "选择"+memberRoleName(role), "", false, disabled).Key("member-role-" + memberRoleName(role)).Clicked() {
				e.inviteRole = role
			}
		}
	}
	ui.Text(c, "新普通成员和集合经理初始没有集合分配；确认加入后在集合访问配置中授权。管理员与所有者拥有完整组织权限。").MaxLines(3)
	if kit.Action(c, "发送邀请", "", true, disabled || e.inviteEmail == "").Key("member-invite").Clicked() {
		e.confirmation = "member-invite"
		e.memberID = ""
	}
	for _, member := range e.members.Members() {
		ui.Text(c, member.Name+" · "+member.Email).MaxLines(2)
		ui.Text(c, memberRoleName(member.Type)+" · "+memberStatusName(member.Status))
		if e.owner || member.Type != 0 {
			if kit.Action(c, "修改角色", "", false, disabled).Key("member-role-load-" + member.ID).Clicked() {
				e.memberID = member.ID
				e.confirmation = ""
				a.runOrganizationManagement("member-role-load")
			}
		}
		operations := []struct{ operation, label string }{}
		if member.Status == 0 {
			operations = append(operations, struct{ operation, label string }{"member-reinvite", "重新发送邀请"})
		}
		if member.Status == 1 && (e.owner || member.Type == 2) {
			if kit.Action(c, "核验公钥并确认成员", "", false, disabled).Key("member-prepare-" + member.ID).Clicked() {
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
				operations = append(operations, struct{ operation, label string }{"member-restore", "恢复成员"})
			} else {
				operations = append(operations, struct{ operation, label string }{"member-revoke", "撤销访问"})
			}
		}
		if e.owner || member.Type == 2 {
			operations = append(operations, struct{ operation, label string }{"member-remove", "移除成员"})
		}
		for _, op := range operations {
			if kit.Action(c, op.label, "", false, disabled).Key(op.operation + "-" + member.ID).Clicked() {
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
		ui.Text(c, "修改角色："+draft.Member().Email).FontSize(16)
		ui.Text(c, "当前选择："+memberRoleName(draft.Role))
		for _, role := range []int{2, 4, 1, 0} {
			if !e.owner && (role == 0 || role == 1 || draft.Member().Type == 1) {
				continue
			}
			if kit.Action(c, "设为"+memberRoleName(role), "", false, disabled).Clicked() {
				draft.Role = role
			}
		}
		if draft.Role == 4 && kit.Action(c, collectionPermissionLabel("管理全部集合", draft.ManageAllCollections), "", false, disabled).Clicked() {
			draft.ManageAllCollections = !draft.ManageAllCollections
		}
		ui.Text(c, "普通成员与集合级经理保留直接集合及群组分配。全组织权限角色会按服务器规则删除直接集合分配；群组保留，今后降级不会自动恢复直接分配。保存前重新核对关系，服务器无原子版本比较，仍有并发窗口。涉及自己时先隔离本机组织。").MaxLines(6)
		if draft.ResetsCollections() {
			ui.Text(c, "将授予全组织访问，并删除以下直接集合分配：").MaxLines(2)
			for _, entry := range draft.ResetCollections() {
				ui.Text(c, entry.Name+" · "+collectionPermissionLabel("只读", entry.ReadOnly)+" · "+collectionPermissionLabel("隐藏密码", entry.HidePasswords)+" · "+collectionPermissionLabel("管理", entry.Manage)).MaxLines(3)
			}
		}
		if kit.Action(c, "保存成员角色", "", true, disabled).Key("member-role-save").Clicked() {
			e.memberID = draft.Member().ID
			e.confirmation = "member-role-save"
		}
		if kit.Action(c, "取消角色修改", "", false, disabled).Clicked() {
			draft.Close()
			e.memberRole = nil
			e.confirmation = ""
		}
	}
	if e.memberProof != nil {
		member := e.memberProof.Member()
		ui.Text(c, "确认对象："+member.Email).FontSize(16)
		ui.Text(c, "请通过可信渠道向受邀人取得其完整 Base64 DER/SPKI 公钥，并粘贴到下方。此处不是官方词组指纹；请核对账号及完整公钥，不能只比较开头或结尾。确认后会用该公钥加密组织密钥。").MaxLines(5)
		ui.Text(c, e.memberProof.PublicKey()).MaxLines(30)
		ui.TextInput(c, &e.verifiedSPKI).Label("从可信渠道取得的完整公钥").Disabled(disabled)
		if kit.Action(c, "公钥已核验，确认加入", "", true, disabled || e.verifiedSPKI != e.memberProof.PublicKey()).Key("member-confirm").Clicked() {
			e.confirmation = "member-confirm"
			a.runOrganizationManagement("member-confirm")
		}
		if kit.Action(c, "取消公钥确认", "", false, disabled).Clicked() {
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
		ui.Text(c, "确认对 "+target+" 执行上述操作。移除自己会先持久隔离本机组织；不能撤销或恢复自己。操作可能影响共享密码库访问。").MaxLines(4)
		if kit.Action(c, "确认成员操作", "", true, disabled).Key("member-action-confirm").Clicked() {
			if e.confirmation == "member-role-save" && e.memberRole != nil {
				e.memberRoleConsent.Close()
				e.memberRoleConsent = e.memberRole.ConfirmCollectionReset()
			}
			a.runOrganizationManagement(e.confirmation)
		}
		if kit.Action(c, "取消成员操作", "", false, disabled).Clicked() {
			e.confirmation = ""
		}
	}
}
