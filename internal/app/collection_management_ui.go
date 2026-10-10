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
	ui.Text(c, i18n.T("org.collection.title")).FontSize(18)
	if e.collectionDraft == nil {
		if canCreate && kit.Action(c, i18n.T("org.collection.create_collection"), "", false, disabled).Key("collection-create").Clicked() {
			e.collectionID = ""
			a.runOrganizationManagement("collection-load")
		}
		for _, collection := range a.collections {
			if collection.OrganizationID != e.id || !collection.Manage {
				continue
			}
			if kit.Action(c, i18n.Tf("org.collection.manage_title", collection.Name), "", false, disabled).Key("collection-manage-" + collection.ID).Clicked() {
				e.collectionID = collection.ID
				a.runOrganizationManagement("collection-load")
			}
		}
		return
	}
	draft := e.collectionDraft
	ui.TextInput(c, &draft.Name).Label(i18n.T("org.collection.name")).Disabled(disabled)
	ui.Text(c, i18n.T("org.collection.rename_hint")).MaxLines(4)
	if !draft.AccessLoaded {
		if kit.Action(c, i18n.T("org.collection.configure_access"), "", false, disabled).Key("collection-access-load").Clicked() {
			a.runOrganizationManagement("collection-access")
		}
	} else {
		ui.Text(c, i18n.T("org.collection.access_title")).FontSize(16)
		ui.Text(c, i18n.T("org.collection.access_hint")).MaxLines(3)
		if !draft.GroupsEnabled {
			ui.Text(c, i18n.T("org.collection.groups_disabled_hint"))
		}
		for i := range draft.Access {
			entry := &draft.Access[i]
			label := i18n.Tf("org.member.label_member", entry.Label)
			if entry.Group {
				label = i18n.Tf("org.group.label_group", entry.Label)
			}
			ui.Text(c, label).MaxLines(2)
			assigned := i18n.T("org.collection.allow_access")
			if entry.Assigned {
				assigned = i18n.T("org.collection.remove_access")
			}
			if kit.Action(c, assigned, "", false, disabled).Key("collection-access-assigned-" + entry.ID).Clicked() {
				entry.Assigned = !entry.Assigned
			}
			if entry.Assigned {
				if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.read_only"), entry.ReadOnly), "", false, disabled).Key("collection-access-read-" + entry.ID).Clicked() {
					entry.ReadOnly = !entry.ReadOnly
					if entry.ReadOnly {
						entry.Manage = false
					}
				}
				if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.hide_passwords"), entry.HidePasswords), "", false, disabled).Key("collection-access-hide-" + entry.ID).Clicked() {
					entry.HidePasswords = !entry.HidePasswords
					if entry.HidePasswords {
						entry.Manage = false
					}
				}
				if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.manage_collection"), entry.Manage), "", false, disabled).Key("collection-access-manage-" + entry.ID).Clicked() {
					entry.Manage = !entry.Manage
					if entry.Manage {
						entry.ReadOnly, entry.HidePasswords = false, false
					}
				}
			}
		}
	}
	if kit.Action(c, i18n.T("org.collection.save_collection"), "", true, disabled || draft.Name == "").Key("collection-save").Clicked() {
		if draft.AccessChanged() {
			e.confirmation = "collection-access-save"
		} else {
			a.runOrganizationManagement("collection-save")
		}
	}
	if e.confirmation == "collection-access-save" {
		ui.Text(c, i18n.T("org.collection.confirm_access_hint")).MaxLines(4)
		if kit.Action(c, i18n.T("org.collection.confirm_save_access"), "", true, disabled).Key("collection-access-confirm").Clicked() {
			a.runOrganizationManagement("collection-save")
		}
		if kit.Action(c, i18n.T("org.collection.cancel_access_confirmation"), "", false, disabled).Clicked() {
			e.confirmation = ""
		}
	}
	if draft.ID() != "" {
		if e.confirmation != "collection-delete" {
			if kit.Action(c, i18n.T("org.collection.delete_collection"), "", false, disabled).Key("collection-delete").Clicked() {
				e.confirmation = "collection-delete"
			}
		} else {
			ui.Text(c, i18n.T("org.collection.delete_hint")).MaxLines(4)
			if kit.Action(c, i18n.T("org.collection.confirm_delete"), "", true, disabled).Key("collection-delete-confirm").Clicked() {
				a.runOrganizationManagement("collection-delete")
			}
			if kit.Action(c, i18n.T("org.collection.cancel_delete"), "", false, disabled).Clicked() {
				e.confirmation = ""
			}
		}
	}
	if kit.Action(c, i18n.T("org.collection.back_to_list"), "", false, a.pending != 0).Clicked() {
		draft.Close()
		e.collectionDraft = nil
		e.collectionID, e.confirmation = "", ""
	}
}

func collectionPermissionLabel(name string, enabled bool) string {
	if enabled {
		return i18n.Tf("org.collection.permission_yes", name)
	}
	return i18n.Tf("org.collection.permission_no", name)
}
