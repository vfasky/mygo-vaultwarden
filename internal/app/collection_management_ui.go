// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) collectionManagementView(c *ui.Context, e *organizationEditor, disabled bool) {
	manager, canCreate := false, false
	for _, org := range a.organizations {
		if org.ID == e.id {
			manager = org.Type == 0 || org.Type == 1 || org.Type == 4
			canCreate = org.CanCreateCollections()
		}
	}
	if !manager {
		return
	}
	ui.Text(c, i18n.T("集合管理")).FontSize(18)
	if e.collectionDraft == nil {
		if canCreate && kit.Action(c, i18n.T("新建集合"), "", false, disabled).Key("collection-create").Clicked() {
			e.collectionID = ""
			a.runOrganizationManagement("collection-load")
		}
		for _, collection := range a.collections {
			if collection.OrganizationID != e.id || !collection.Manage {
				continue
			}
			if kit.Action(c, i18n.Tf("管理集合：%s", collection.Name), "", false, disabled).Key("collection-manage-" + collection.ID).Clicked() {
				e.collectionID = collection.ID
				a.runOrganizationManagement("collection-load")
			}
		}
		return
	}
	draft := e.collectionDraft
	ui.TextInput(c, &draft.Name).Label(i18n.T("集合名称")).Disabled(disabled)
	ui.Text(c, i18n.T("名称端到端加密。更名保留成员、群组和外部目录关联；服务器没有集合版本比较，保存前会重新核对详情。多人同时管理时请同步核对结果。")).MaxLines(4)
	if !draft.AccessLoaded {
		if kit.Action(c, i18n.T("配置成员与群组访问"), "", false, disabled).Key("collection-access-load").Clicked() {
			a.runOrganizationManagement("collection-access")
		}
	} else {
		ui.Text(c, i18n.T("集合访问")).FontSize(16)
		ui.Text(c, i18n.T("直接成员权限优先于群组；完整组织管理员可能拥有额外访问权。只更改所选条目，目录中未出现的既有分配会保留。")).MaxLines(3)
		if !draft.GroupsEnabled {
			ui.Text(c, i18n.T("服务器未启用群组。"))
		}
		for i := range draft.Access {
			entry := &draft.Access[i]
			label := i18n.Tf("成员：%s", entry.Label)
			if entry.Group {
				label = i18n.Tf("群组：%s", entry.Label)
			}
			ui.Text(c, label).MaxLines(2)
			assigned := i18n.T("允许访问此集合")
			if entry.Assigned {
				assigned = i18n.T("移除此访问分配")
			}
			if kit.Action(c, assigned, "", false, disabled).Key("collection-access-assigned-" + entry.ID).Clicked() {
				entry.Assigned = !entry.Assigned
			}
			if entry.Assigned {
				if kit.Action(c, collectionPermissionLabel(i18n.T("只读"), entry.ReadOnly), "", false, disabled).Key("collection-access-read-" + entry.ID).Clicked() {
					entry.ReadOnly = !entry.ReadOnly
					if entry.ReadOnly {
						entry.Manage = false
					}
				}
				if kit.Action(c, collectionPermissionLabel(i18n.T("隐藏密码"), entry.HidePasswords), "", false, disabled).Key("collection-access-hide-" + entry.ID).Clicked() {
					entry.HidePasswords = !entry.HidePasswords
					if entry.HidePasswords {
						entry.Manage = false
					}
				}
				if kit.Action(c, collectionPermissionLabel(i18n.T("管理集合"), entry.Manage), "", false, disabled).Key("collection-access-manage-" + entry.ID).Clicked() {
					entry.Manage = !entry.Manage
					if entry.Manage {
						entry.ReadOnly, entry.HidePasswords = false, false
					}
				}
			}
		}
	}
	if kit.Action(c, i18n.T("保存集合"), "", true, disabled || draft.Name == "").Key("collection-save").Clicked() {
		if draft.AccessChanged() {
			e.confirmation = "collection-access-save"
		} else {
			a.runOrganizationManagement("collection-save")
		}
	}
	if e.confirmation == "collection-access-save" {
		ui.Text(c, i18n.T("确认提交当前访问分配。对已有集合修改访问前，将先隔离本机整个组织；保存后从侧栏重新核验访问。服务器可能部分执行，失败后请同步核对。")).MaxLines(4)
		if kit.Action(c, i18n.T("确认保存访问配置"), "", true, disabled).Key("collection-access-confirm").Clicked() {
			a.runOrganizationManagement("collection-save")
		}
		if kit.Action(c, i18n.T("取消访问配置确认"), "", false, disabled).Clicked() {
			e.confirmation = ""
		}
	}
	if draft.ID() != "" {
		if e.confirmation != "collection-delete" {
			if kit.Action(c, i18n.T("删除集合"), "", false, disabled).Key("collection-delete").Clicked() {
				e.confirmation = "collection-delete"
			}
		} else {
			ui.Text(c, i18n.T("删除集合会解除集合的项目关联和成员访问。组织项目本身不会被删除。继续会先隔离本机整个组织，须从侧栏重新核验访问后恢复。")).MaxLines(4)
			if kit.Action(c, i18n.T("确认删除集合"), "", true, disabled).Key("collection-delete-confirm").Clicked() {
				a.runOrganizationManagement("collection-delete")
			}
			if kit.Action(c, i18n.T("取消删除集合"), "", false, disabled).Clicked() {
				e.confirmation = ""
			}
		}
	}
	if kit.Action(c, i18n.T("返回集合列表"), "", false, a.pending != 0).Clicked() {
		draft.Close()
		e.collectionDraft = nil
		e.collectionID, e.confirmation = "", ""
	}
}

func collectionPermissionLabel(name string, enabled bool) string {
	if enabled {
		return i18n.Tf("%s：是", name)
	}
	return i18n.Tf("%s：否", name)
}
