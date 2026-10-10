// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func groupManagementOperation(op string) bool {
	return op == "group-list" || op == "group-load" || op == "group-save" || op == "group-delete"
}
func (a *app) groupManagementView(c *ui.Context, e *organizationEditor, disabled bool) {
	allowed, enabled := false, false
	for _, org := range a.organizations {
		if org.ID == e.id {
			allowed = org.Type == 0 || org.Type == 1
			enabled = org.UseGroups
		}
	}
	if !allowed {
		return
	}
	ui.Text(c, i18n.T("群组管理")).FontSize(18)
	if !enabled {
		ui.Text(c, i18n.T("服务器未启用群组，无法读取或修改群组。"))
		return
	}
	if e.groupDraft == nil {
		if kit.Action(c, i18n.T("加载群组"), "", false, disabled).Key("group-list").Clicked() {
			a.runOrganizationManagement("group-list")
		}
		if kit.Action(c, i18n.T("新建群组"), "", false, disabled).Key("group-create").Clicked() {
			e.groupID = ""
			a.runOrganizationManagement("group-load")
		}
		for _, row := range e.groups {
			if kit.Action(c, i18n.Tf("管理群组：%s", row.Name), "", false, disabled).Key("group-edit-" + row.ID).Clicked() {
				e.groupID = row.ID
				a.runOrganizationManagement("group-load")
			}
		}
		return
	}
	d := e.groupDraft
	confirming := e.confirmation == "group-save" || e.confirmation == "group-delete"
	ui.TextInput(c, &d.Name).Label(i18n.T("群组名称（服务器明文保存）")).Disabled(disabled || confirming)
	ui.Text(c, i18n.T("服务器未返回当前访问范围。保存时必须重新明确设置；仅更名也会应用所选范围。服务器不提供版本比较，无法检测未公开范围的并发变化。")).MaxLines(5)
	for _, option := range []struct {
		scope vaultwarden.GroupScope
		label string
	}{{vaultwarden.GroupAllCollections, i18n.T("全部集合（含未来新增集合）")}, {vaultwarden.GroupSelectedCollections, i18n.T("仅选定集合")}} {
		if kit.Action(c, collectionPermissionLabel(option.label, d.AccessScope == option.scope), "", false, disabled || confirming).Clicked() {
			d.AccessScope = option.scope
		}
	}
	if d.AccessScope == vaultwarden.GroupAllCollections {
		ui.Text(c, i18n.T("群组成员将获得整个组织全部集合的完整访问。以下集合分配仍保留，但不能限制全集合授权。")).MaxLines(3)
	}
	if d.AccessScope == vaultwarden.GroupSelectedCollections {
		ui.Text(c, i18n.T("仅应用以下勾选集合及权限；空集合列表不通过本群组授予集合访问。成员的其他独立授权仍有效。")).MaxLines(3)
	}
	ui.Text(c, i18n.T("直接集合权限与群组完整访问按服务器规则核验，不能将多条授权简单合并。保存前会重新核对完整成员与集合目录。")).MaxLines(3)
	for i := range d.Access {
		entry := &d.Access[i]
		label := i18n.Tf("成员：%s", entry.Label)
		if entry.Collection {
			label = i18n.Tf("集合：%s", entry.Label)
		}
		ui.Text(c, label).MaxLines(2)
		if kit.Action(c, collectionPermissionLabel(i18n.T("分配"), entry.Assigned), "", false, disabled || confirming).Key("group-assign-" + entry.ID).Clicked() {
			entry.Assigned = !entry.Assigned
		}
		if !entry.Collection || !entry.Assigned {
			continue
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("只读"), entry.ReadOnly), "", false, disabled || confirming).Key("group-read-" + entry.ID).Clicked() {
			entry.ReadOnly = !entry.ReadOnly
			if entry.ReadOnly {
				entry.Manage = false
			}
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("隐藏密码"), entry.HidePasswords), "", false, disabled || confirming).Key("group-hide-" + entry.ID).Clicked() {
			entry.HidePasswords = !entry.HidePasswords
			if entry.HidePasswords {
				entry.Manage = false
			}
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("管理集合"), entry.Manage), "", false, disabled || confirming).Key("group-manage-" + entry.ID).Clicked() {
			entry.Manage = !entry.Manage
			if entry.Manage {
				entry.ReadOnly = false
				entry.HidePasswords = false
			}
		}
	}
	if !confirming {
		if kit.Action(c, i18n.T("保存群组"), "", true, disabled || d.Name == "" || d.AccessScope == vaultwarden.GroupScopeUnset).Key("group-save").Clicked() {
			e.groupConsent.Close()
			e.groupConsent = d.Confirm()
			e.confirmation = "group-save"
		}
		if d.ID() != "" && kit.Action(c, i18n.T("删除群组"), "", false, disabled).Clicked() {
			e.confirmation = "group-delete"
		}
	} else {
		ui.Text(c, i18n.T("确认本次操作及上述访问范围：将影响群组成员授权；编辑或删除既有群组前会先持久隔离本机此组织。操作可能部分执行，未知结果不会自动重试，请重新核验访问与服务器结果。")).MaxLines(5)
		if kit.Action(c, i18n.T("确认群组操作"), "", true, disabled).Key("group-confirm").Clicked() {
			a.runOrganizationManagement(e.confirmation)
		}
		if kit.Action(c, i18n.T("取消群组确认"), "", false, disabled).Clicked() {
			e.groupConsent.Close()
			e.groupConsent = nil
			e.confirmation = ""
		}
	}
	if kit.Action(c, i18n.T("返回群组列表"), "", false, disabled).Clicked() {
		e.groupDraft.Close()
		e.groupDraft = nil
		e.groupConsent.Close()
		e.groupConsent = nil
		e.confirmation = ""
	}
}
