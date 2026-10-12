// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strconv"
	"time"
)

const shareOrganizationAction vaultwarden.CipherAction = "shareOrganization"

func (a *app) organizationTypePicker(c *ui.Context, e *cipherEditor) {
	for row := 0; row < 2; row++ {
		ui.Row(c).Gap(4).Children(func() {
			for kind := 1 + row*4; kind <= 4+row*4; kind++ {
				if kit.Action(c.Key("organization-type-"+strconv.Itoa(kind)), i18n.Tf("org.share.item_type", i18n.T(cipherTypeNames[kind])), "", kind == e.fields.Type, a.pending != 0 || e.uncertain).Clicked() {
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
		ui.Text(c, i18n.T("org.share.ownership_hint"))
		for _, collection := range a.collections {
			if collection.ID == e.shareCollectionID {
				ui.Text(c, i18n.Tf("org.share.target_collection", collection.Name))
			}
		}
		if kit.Action(c.Key("organization-share-confirm"), i18n.T("org.share.confirm_share"), "", true, a.pending != 0 || e.uncertain || e.conflict).Clicked() {
			a.mutateCipher(shareOrganizationAction)
		}
		if kit.Action(c.Key("organization-share-cancel"), i18n.T("org.share.cancel_share"), "", false, a.pending != 0).Clicked() {
			e.shareOrganizationID, e.shareCollectionID = "", ""
		}
		return
	}
	for _, org := range a.organizations {
		for _, collection := range a.collections {
			if collection.OrganizationID == org.ID && !collection.ReadOnly && !collection.HidePasswords {
				if kit.Action(c.Key("organization-share-select-"+collection.ID), i18n.Tf("org.share.share_to", org.Name, collection.Name), "", false, a.pending != 0 || e.uncertain || e.conflict).Clicked() {
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
	if a.drawerHeader(c, e.fields.Name, i18n.T("org.share.read_only_hint")) {
		return
	}
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(12).Padding(20).Children(func() {
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
				if kit.Action(c, i18n.T("org.share.show_password"), "", false, a.pending != 0).Clicked() {
					a.showPersonalSecret("password", callStorage)
				}
				if kit.Action(c, i18n.T("org.share.copy_password"), "", false, a.pending != 0).Clicked() {
					a.copyPersonalSecret("password", callStorage)
				}
				if kit.Action(c, i18n.T("org.share.show_totp"), "", false, a.pending != 0).Clicked() {
					a.showPersonalSecret("totp", callStorage)
				}
				if kit.Action(c, i18n.T("org.share.copy_totp"), "", false, a.pending != 0).Clicked() {
					a.copyPersonalSecret("totp", callStorage)
				}
			}
			a.attachmentView(c, e)
		})
	})
}
