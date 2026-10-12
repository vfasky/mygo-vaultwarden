// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type APIKeyPanel struct {
	Flow                    orgBusinessFlow
	allowed, rotate, reveal bool
	password, key, clientID string
	expires                 time.Time
	execute                 func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error
}

func NewAPIKeyPanel(owner bool, execute func(context.Context, []byte, bool, func(string, []byte, time.Time) error) error, dispatch func(func())) *APIKeyPanel {
	return &APIKeyPanel{Flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, execute: execute}
}
func (p *APIKeyPanel) Close() {
	p.Flow.close()
	p.password = ""
	p.key = ""
	p.clientID = ""
	p.reveal = false
}
func (p *APIKeyPanel) start() {
	if !p.allowed || p.execute == nil || p.password == "" || p.Flow.dispatch == nil || p.Flow.blocked() || !p.Flow.confirm {
		return
	}
	password := []byte(p.password)
	p.password = ""
	rotate, execute, dispatch := p.rotate, p.execute, p.Flow.dispatch
	ctx, cancel := context.WithCancel(context.Background())
	p.Flow.cancel = cancel
	p.Flow.running = true
	if p.Flow.Busy != nil {
		p.Flow.Busy(true)
	}
	p.Flow.confirm = false
	generation := p.Flow.generation
	go func() {
		var secret []byte
		var clientID string
		var expires time.Time
		err := execute(ctx, password, rotate, func(id string, key []byte, date time.Time) error {
			clientID = id
			secret = append([]byte(nil), key...)
			expires = date
			return nil
		})
		clear(password)
		cancel()
		dispatch(func() {
			if p.Flow.Busy != nil {
				p.Flow.Busy(false)
			}
			defer clear(secret)
			if p.Flow.closed || p.Flow.generation != generation {
				return
			}
			p.Flow.running = false
			p.Flow.terminal = true
			p.Flow.cancel = nil
			if err != nil {
				p.Flow.status = i18n.T("org.apikey.status_incomplete")
				return
			}
			p.key = string(secret)
			p.clientID = clientID
			p.expires = expires
			p.Flow.status = i18n.T("org.apikey.status_temporary")
		})
	}()
}
func (p *APIKeyPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("org.apikey.title")).FontSize(22)
	if !p.allowed {
		ui.Text(c, i18n.T("org.apikey.owner_only_hint"))
	}
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.password).Label(i18n.T("common.current_master_password")).Password().Disabled(disabled)
	if kit.Action(c.Key("org-key-read"), i18n.T("org.apikey.read"), "", !p.rotate, disabled).Clicked() {
		p.rotate = false
	}
	if kit.Action(c.Key("org-key-rotate"), i18n.T("org.apikey.rotate"), "", p.rotate, disabled).Clicked() {
		p.rotate = true
	}
	p.Flow.footer(c, "org-key", i18n.T("org.apikey.confirm_read_rotate"), p.allowed && p.execute != nil && p.password != "", p.start)
	if p.key != "" {
		ui.Text(c, fmt.Sprintf("Client ID: %s", p.clientID))
		field := ui.TextInput(c, &p.key).Label(i18n.T("org.apikey.title")).Disabled(true)
		if !p.reveal {
			field.Password()
		}
		if kit.Action(c.Key("org-key-reveal"), i18n.T("org.apikey.toggle_visibility"), "", p.reveal, false).Clicked() {
			p.reveal = !p.reveal
		}
		if kit.Action(c.Key("org-key-clear"), i18n.T("org.apikey.clear"), "", false, false).Clicked() {
			p.key = ""
			p.clientID = ""
			p.reveal = false
		}
	}
}

type DirectoryPanel struct {
	Flow                                         orgBusinessFlow
	allowed, useGroups, overwrite                bool
	secret, email, external, name, groupExternal string
	deleted                                      bool
	members                                      []vaultwarden.OrganizationDirectoryMember
	groups                                       []vaultwarden.OrganizationDirectoryGroup
	groupMembers                                 map[string]bool
	execute                                      func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error)
}

func NewDirectoryPanel(owner, useGroups bool, execute func(context.Context, []byte, vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error), dispatch func(func())) *DirectoryPanel {
	return &DirectoryPanel{Flow: orgBusinessFlow{dispatch: dispatch}, allowed: owner, useGroups: useGroups, groupMembers: map[string]bool{}, execute: execute}
}
func (p *DirectoryPanel) Close() {
	p.Flow.close()
	p.secret = ""
	p.email = ""
	p.external = ""
	p.name = ""
	p.groupExternal = ""
	p.members = nil
	p.groups = nil
	p.groupMembers = nil
}
func (p *DirectoryPanel) addMember() {
	if p.Flow.blocked() || p.Flow.confirm || !p.allowed {
		return
	}
	email := strings.ToLower(strings.TrimSpace(p.email))
	external := strings.TrimSpace(p.external)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 320 || external == "" || len(external) > 1024 {
		p.Flow.status = i18n.T("org.directory.err_member_invalid")
		return
	}
	for _, m := range p.members {
		if m.Email == email || m.ExternalID == external {
			p.Flow.status = i18n.T("org.directory.err_member_duplicate")
			return
		}
	}
	p.members = append(p.members, vaultwarden.OrganizationDirectoryMember{Email: email, ExternalID: external, Deleted: p.deleted})
	p.email = ""
	p.external = ""
	p.deleted = false
	p.Flow.status = ""
}
func (p *DirectoryPanel) addGroup() {
	if p.Flow.blocked() || p.Flow.confirm || !p.allowed || !p.useGroups {
		return
	}
	name, external := strings.TrimSpace(p.name), strings.TrimSpace(p.groupExternal)
	if name == "" || external == "" {
		return
	}
	for _, g := range p.groups {
		if g.ExternalID == external {
			p.Flow.status = i18n.T("org.directory.err_group_duplicate")
			return
		}
	}
	members := []string{}
	for _, m := range p.members {
		if p.groupMembers[m.ExternalID] {
			members = append(members, m.ExternalID)
		}
	}
	p.groups = append(p.groups, vaultwarden.OrganizationDirectoryGroup{Name: name, ExternalID: external, MemberExternalIDs: members})
	p.name = ""
	p.groupExternal = ""
	p.groupMembers = map[string]bool{}
}
func (p *DirectoryPanel) start() {
	if !p.allowed || p.execute == nil || p.secret == "" || len(p.members)+len(p.groups) == 0 || p.Flow.blocked() || !p.Flow.confirm || p.Flow.dispatch == nil {
		return
	}
	secret := []byte(p.secret)
	p.secret = ""
	execute := p.execute
	input := vaultwarden.OrganizationDirectoryImport{Members: append([]vaultwarden.OrganizationDirectoryMember(nil), p.members...), Groups: append([]vaultwarden.OrganizationDirectoryGroup(nil), p.groups...), OverwriteExisting: p.overwrite}
	for i := range input.Groups {
		input.Groups[i].MemberExternalIDs = append([]string(nil), input.Groups[i].MemberExternalIDs...)
	}
	p.Flow.run(func(ctx context.Context) ([]string, error) {
		defer clear(secret)
		result, err := execute(ctx, secret, input)
		rows := []string{i18n.T("org.directory.status_quarantined")}
		if r := result.Reconciliation; r != nil {
			for _, row := range r.Rows {
				state := i18n.T("org.directory.status_unknown")
				if row.Verified {
					state = i18n.T("org.services.status_reread_verified")
				}
				rows = append(rows, fmt.Sprintf("%s · %s: %s; %s", row.Kind, row.ExternalID, state, row.Reason))
			}
		} else {
			rows = append(rows, i18n.T("org.directory.status_no_results"))
		}
		return rows, err
	})
}
func (p *DirectoryPanel) View(c *ui.Context) {
	if p.Flow.closed {
		return
	}
	ui.Text(c, i18n.T("org.directory.title")).FontSize(22)
	ui.Text(c, i18n.T("org.directory.description"))
	disabled := p.Flow.blocked() || p.Flow.confirm || !p.allowed
	ui.TextInput(c, &p.secret).Label(i18n.T("org.directory.temporary_api_key")).Password().Disabled(disabled)
	ui.TextInput(c, &p.email).Label(i18n.T("org.directory.member_email")).Disabled(disabled)
	ui.TextInput(c, &p.external).Label(i18n.T("org.directory.member_external_id")).Disabled(disabled)
	if kit.Action(c.Key("org-dir-deleted"), i18n.T("org.directory.mark_member_deleted"), "", p.deleted, disabled).Clicked() {
		p.deleted = !p.deleted
	}
	if kit.Action(c.Key("org-dir-add"), i18n.T("org.directory.add_member_preview"), "", true, disabled).Clicked() {
		p.addMember()
	}
	for i, m := range p.members {
		label := m.Email + " · " + m.ExternalID
		if m.Deleted {
			label = i18n.Tf("org.directory.revoked_member", label)
		}
		ui.Text(c, label)
		if kit.Action(c.Key("org-dir-remove-"+m.ExternalID), i18n.T("org.directory.remove_member_row"), "", false, disabled || len(p.groups) > 0).Clicked() {
			p.members = append(p.members[:i], p.members[i+1:]...)
			delete(p.groupMembers, m.ExternalID)
			break
		}
	}
	if p.useGroups {
		ui.TextInput(c, &p.name).Label(i18n.T("org.directory.group_name")).Disabled(disabled)
		ui.TextInput(c, &p.groupExternal).Label(i18n.T("org.directory.group_external_id")).Disabled(disabled)
		for _, m := range p.members {
			if kit.Action(c.Key("org-dir-group-member-"+m.ExternalID), m.Email, "", p.groupMembers[m.ExternalID], disabled).Clicked() {
				p.groupMembers[m.ExternalID] = !p.groupMembers[m.ExternalID]
			}
		}
		if kit.Action(c.Key("org-dir-add-group"), i18n.T("org.directory.add_group_preview"), "", true, disabled).Clicked() {
			p.addGroup()
		}
		for i, g := range p.groups {
			ui.Text(c, g.Name+" · "+g.ExternalID+" · "+strings.Join(g.MemberExternalIDs, ", "))
			if kit.Action(c.Key("org-dir-remove-group-"+g.ExternalID), i18n.T("org.directory.remove_group"), "", false, disabled).Clicked() {
				p.groups = append(p.groups[:i], p.groups[i+1:]...)
				break
			}
		}
	}
	if kit.Action(c.Key("org-dir-overwrite"), i18n.T("org.directory.revoke_absent_members"), "", p.overwrite, disabled).Clicked() {
		p.overwrite = !p.overwrite
	}
	p.Flow.footer(c, "org-dir", i18n.T("org.directory.confirm_import"), p.allowed && p.execute != nil && p.secret != "" && len(p.members)+len(p.groups) > 0, p.start)
}
