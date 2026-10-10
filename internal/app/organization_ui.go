// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

const shareOrganizationAction vaultwarden.CipherAction = "shareOrganization"

func (a *app) organizationTypePicker(c *ui.Context, e *cipherEditor) {
	for row := 0; row < 2; row++ {
		ui.Row(c).Gap(4).Children(func() {
			for kind := 1 + row*4; kind <= 4+row*4; kind++ {
				if action(c, "类型："+cipherTypeNames[kind], "", kind == e.fields.Type, a.pending != 0 || e.uncertain).Key("organization-type-" + cipherTypeNames[kind]).Clicked() {
					e.applyInputs()
					e.fields.Type = kind
					populateCipherEditor(e)
					a.secretInputVersion++
				}
			}
		})
	}
}

func (a *app) organizationShareView(c *ui.Context, e *cipherEditor) {
	if e.fields.DeletedDate != nil {
		return
	}
	if e.shareCollectionID != "" {
		ui.Text(c, "共享后项目归组织所有，组织中具备权限的成员将能访问。请确认目标集合；此操作不会保留个人副本。")
		for _, collection := range a.collections {
			if collection.ID == e.shareCollectionID {
				ui.Text(c, "目标集合："+collection.Name)
			}
		}
		if action(c, "确认共享到组织", "", true, a.pending != 0 || e.uncertain || e.conflict).Key("organization-share-confirm").Clicked() {
			a.mutateCipher(shareOrganizationAction)
		}
		if action(c, "取消共享", "", false, a.pending != 0).Key("organization-share-cancel").Clicked() {
			e.shareOrganizationID, e.shareCollectionID = "", ""
		}
		return
	}
	for _, org := range a.organizations {
		for _, collection := range a.collections {
			if collection.OrganizationID == org.ID && !collection.ReadOnly && !collection.HidePasswords {
				if action(c, "共享到 "+org.Name+" / "+collection.Name, "", false, a.pending != 0 || e.uncertain || e.conflict).Key("organization-share-select-" + collection.ID).Clicked() {
					e.shareOrganizationID, e.shareCollectionID = org.ID, collection.ID
				}
			}
		}
	}
}

func (a *app) organizationItem(id string) bool {
	for _, item := range a.items {
		if item.ID == id {
			return item.OrganizationID != ""
		}
	}
	return false
}
func (a *app) organizationItemRequiresPassword(id string) bool {
	for _, item := range a.items {
		if item.ID == id {
			return item.OrganizationID != "" && item.RequiresPassword
		}
	}
	return false
}
func (a *app) readOnlyOrganizationCipherView(c *ui.Context, e *cipherEditor) {
	callStorage := a.vaultStorage()
	if !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision || (!e.authorizationExpires.IsZero() && !time.Now().Before(e.authorizationExpires)) {
		*e = cipherEditor{}
		a.editor = nil
		a.secretInputVersion++
		return
	}
	if !e.authorizationExpires.IsZero() {
		c.After(time.Until(e.authorizationExpires))
	}
	ui.Column(c).Gap(12).Padding(18).Children(func() {
		ui.Text(c, e.fields.Name).FontSize(23)
		ui.Text(c, "组织授予此项目查看权限。修改需要组织管理员调整集合权限。")
		for _, input := range e.inputs {
			if !input.secret {
				ui.Text(c, input.label+"："+input.value)
			}
		}
		if e.shownSecret != "" {
			if time.Now().Before(e.shownSecretExpires) {
				ui.Text(c, e.shownSecret)
				c.After(time.Until(e.shownSecretExpires))
			} else {
				e.shownSecret = ""
			}
		}
		if e.fields.Type == 1 {
			if action(c, "显示密码（30 秒）", "", false, a.pending != 0).Clicked() {
				a.showPersonalSecret("password", callStorage)
			}
			if action(c, "复制密码", "", false, a.pending != 0).Clicked() {
				a.copyPersonalSecret("password", callStorage)
			}
			if action(c, "显示验证码", "", false, a.pending != 0).Clicked() {
				a.showPersonalSecret("totp", callStorage)
			}
			if action(c, "复制验证码", "", false, a.pending != 0).Clicked() {
				a.copyPersonalSecret("totp", callStorage)
			}
		}
		a.attachmentView(c, e)
		if action(c, "关闭", "", false, false).Clicked() {
			*e = cipherEditor{}
			a.editor = nil
		}
	})
}
