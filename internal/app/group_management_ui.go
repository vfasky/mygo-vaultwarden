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
	ui.Text(c, i18n.T("org.group.title")).FontSize(18)
	if !enabled {
		ui.Text(c, i18n.T("org.group.disabled_hint"))
		return
	}
	if e.groupDraft == nil {
		if kit.Action(c, i18n.T("org.group.load_groups"), "", false, disabled).Key("group-list").Clicked() {
			a.runOrganizationManagement("group-list")
		}
		if kit.Action(c, i18n.T("org.group.create_group"), "", false, disabled).Key("group-create").Clicked() {
			e.groupID = ""
			a.runOrganizationManagement("group-load")
		}
		for _, row := range e.groups {
			if kit.Action(c, i18n.Tf("org.group.manage_title", row.Name), "", false, disabled).Key("group-edit-" + row.ID).Clicked() {
				e.groupID = row.ID
				a.runOrganizationManagement("group-load")
			}
		}
		return
	}
	d := e.groupDraft
	confirming := e.confirmation == "group-save" || e.confirmation == "group-delete"
	ui.TextInput(c, &d.Name).Label(i18n.T("org.group.name")).Disabled(disabled || confirming)
	ui.Text(c, i18n.T("org.group.access_scope_hint")).MaxLines(5)
	for _, option := range []struct {
		scope vaultwarden.GroupScope
		label string
	}{{vaultwarden.GroupAllCollections, i18n.T("org.group.all_collections")}, {vaultwarden.GroupSelectedCollections, i18n.T("org.group.selected_collections")}} {
		if kit.Action(c, collectionPermissionLabel(option.label, d.AccessScope == option.scope), "", false, disabled || confirming).Clicked() {
			d.AccessScope = option.scope
		}
	}
	if d.AccessScope == vaultwarden.GroupAllCollections {
		ui.Text(c, i18n.T("org.group.all_collections_hint")).MaxLines(3)
	}
	if d.AccessScope == vaultwarden.GroupSelectedCollections {
		ui.Text(c, i18n.T("org.group.selected_collections_hint")).MaxLines(3)
	}
	ui.Text(c, i18n.T("org.group.permissions_hint")).MaxLines(3)
	for i := range d.Access {
		entry := &d.Access[i]
		label := i18n.Tf("org.member.member_label", entry.Label)
		if entry.Collection {
			label = i18n.Tf("org.collection.collection_label", entry.Label)
		}
		ui.Text(c, label).MaxLines(2)
		if kit.Action(c, collectionPermissionLabel(i18n.T("org.group.assign"), entry.Assigned), "", false, disabled || confirming).Key("group-assign-" + entry.ID).Clicked() {
			entry.Assigned = !entry.Assigned
		}
		if !entry.Collection || !entry.Assigned {
			continue
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.read_only"), entry.ReadOnly), "", false, disabled || confirming).Key("group-read-" + entry.ID).Clicked() {
			entry.ReadOnly = !entry.ReadOnly
			if entry.ReadOnly {
				entry.Manage = false
			}
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.hide_passwords"), entry.HidePasswords), "", false, disabled || confirming).Key("group-hide-" + entry.ID).Clicked() {
			entry.HidePasswords = !entry.HidePasswords
			if entry.HidePasswords {
				entry.Manage = false
			}
		}
		if kit.Action(c, collectionPermissionLabel(i18n.T("org.collection.manage_collection"), entry.Manage), "", false, disabled || confirming).Key("group-manage-" + entry.ID).Clicked() {
			entry.Manage = !entry.Manage
			if entry.Manage {
				entry.ReadOnly = false
				entry.HidePasswords = false
			}
		}
	}
	if !confirming {
		if kit.Action(c, i18n.T("org.group.save_group"), "", true, disabled || d.Name == "" || d.AccessScope == vaultwarden.GroupScopeUnset).Key("group-save").Clicked() {
			e.groupConsent.Close()
			e.groupConsent = d.Confirm()
			e.confirmation = "group-save"
		}
		if d.ID() != "" && kit.Action(c, i18n.T("org.group.delete_group"), "", false, disabled).Clicked() {
			e.confirmation = "group-delete"
		}
	} else {
		ui.Text(c, i18n.T("org.group.confirm_operation_hint")).MaxLines(5)
		if kit.Action(c, i18n.T("org.group.confirm_operation"), "", true, disabled).Key("group-confirm").Clicked() {
			a.runOrganizationManagement(e.confirmation)
		}
		if kit.Action(c, i18n.T("org.group.cancel_confirmation"), "", false, disabled).Clicked() {
			e.groupConsent.Close()
			e.groupConsent = nil
			e.confirmation = ""
		}
	}
	if kit.Action(c, i18n.T("org.group.back_to_list"), "", false, disabled).Clicked() {
		e.groupDraft.Close()
		e.groupDraft = nil
		e.groupConsent.Close()
		e.groupConsent = nil
		e.confirmation = ""
	}
}
