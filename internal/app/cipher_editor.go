// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type editorField struct {
	key, label, value string
	secret            bool
}
type editorURI struct {
	source    map[string]any
	value     string
	showMatch bool
}

type editorCustom struct {
	source           map[string]any
	name, value      string
	hidden, editable bool
	kind             string
	linkedID         json.Number
	showLinks        bool
}

type cipherEditor struct {
	attachments                            []vaultwarden.AttachmentInfo
	attachmentsLoaded, attachmentBusy      bool
	attachmentDelete                       string
	defaultURIMatch                        int
	organizationID, collectionID           string
	shareOrganizationID, shareCollectionID string
	document                               vaultwarden.CipherDocument
	fields                                 vaultwarden.CipherFields
	inputs                                 []editorField
	notes                                  string
	uris                                   []editorURI
	custom                                 []editorCustom
	conflict                               bool
	comparison                             *vaultwarden.CipherRebase
	changes                                []vaultwarden.CipherChange
	localChoices                           map[string]bool
	rowChoices                             map[string][]int
	rowPreview                             *cipherRowReveal
	attachmentMigration                    *cipherAttachmentMigrationEditor
	compareAuthorization                   bool
	uncertain                              bool
	saved                                  bool
	revision                               string
	confirm                                vaultwarden.CipherAction
	showHistory                            bool
	shownHistory                           []vaultwarden.PasswordHistoryValue
	historyExpires                         time.Time
	confirmHistoryDelete                   bool
	authorization                          *vaultwarden.ItemAuthorization
	repromptID, repromptPassword           string
	authorizationExpires                   time.Time
	shownSecret                            string
	shownSecretExpires                     time.Time
}

// Type names also form organization selector keys; translate only for display.
var cipherTypeNames = []string{"", "itemtype.login", "itemtype.note", "itemtype.card", "itemtype.identity", "itemtype.ssh_key", "itemtype.bank", "itemtype.license", "itemtype.passport"}

// Specs store label keys; populateCipherEditor resolves them for display.
var editorSpecs = map[int][]editorField{
	1: {{key: "username", label: "common.username"}, {key: "password", label: "common.password", secret: true}, {key: "totp", label: "vault.field.login.totp", secret: true}},
	2: {},
	3: {
		{key: "cardholderName", label: "vault.field.card.holder"},
		{key: "brand", label: "vault.field.card.brand"},
		{
			key:    "number",
			label:  "vault.field.card.number",
			secret: true,
		},
		{key: "expMonth", label: "vault.field.card.expiration_month"},
		{key: "expYear", label: "vault.field.card.expiration_year"},
		{
			key:    "code",
			label:  "vault.field.card.security_code",
			secret: true,
		},
	},
	4: {
		{key: "title", label: "vault.field.identity.title"},
		{key: "firstName", label: "vault.field.first_name"},
		{key: "middleName", label: "vault.field.middle_name"},
		{key: "lastName", label: "vault.field.last_name"},
		{key: "address1", label: "vault.field.identity.address_one"},
		{key: "address2", label: "vault.field.identity.address_two"},
		{key: "address3", label: "vault.field.identity.address_three"},
		{key: "city", label: "vault.field.identity.city"},
		{key: "state", label: "vault.field.identity.state"},
		{key: "postalCode", label: "vault.field.identity.postal_code"},
		{key: "country", label: "vault.field.identity.country"},
		{key: "company", label: "vault.field.identity.company"},
		{key: "email", label: "common.email"},
		{key: "phone", label: "vault.field.identity.phone"},
		{
			key:    "ssn",
			label:  "vault.field.identity.social_security_number",
			secret: true,
		},
		{key: "username", label: "common.username"},
		{
			key:    "passportNumber",
			label:  "vault.field.passport.number",
			secret: true,
		},
		{
			key:    "licenseNumber",
			label:  "vault.field.license.number",
			secret: true,
		},
	},
	5: {{key: "privateKey", label: "vault.field.ssh.private_key", secret: true}, {key: "publicKey", label: "vault.field.ssh.public_key"}, {key: "keyFingerprint", label: "vault.field.ssh.fingerprint"}},
	6: {
		{key: "bankName", label: "vault.field.bank.name"},
		{key: "nameOnAccount", label: "vault.field.bank.account_holder"},
		{key: "accountType", label: "vault.field.bank.account_type"},
		{
			key:    "accountNumber",
			label:  "vault.field.bank.account_number",
			secret: true,
		},
		{key: "routingNumber", label: "vault.field.bank.routing_number"},
		{key: "branchNumber", label: "vault.field.bank.branch_number"},
		{
			key:    "pin",
			label:  "vault.field.bank.pin",
			secret: true,
		},
		{key: "swiftCode", label: "vault.field.bank.swift"},
		{key: "iban", label: "vault.field.bank.iban"},
		{key: "bankContactPhone", label: "vault.field.bank.phone"},
	},
	7: {
		{key: "firstName", label: "vault.field.first_name"},
		{key: "middleName", label: "vault.field.middle_name"},
		{key: "lastName", label: "vault.field.last_name"},
		{key: "dateOfBirth", label: "vault.field.date_of_birth"},
		{
			key:    "licenseNumber",
			label:  "vault.field.license.number",
			secret: true,
		},
		{key: "issuingCountry", label: "vault.field.issuing_country"},
		{key: "issuingState", label: "vault.field.license.issuing_state"},
		{key: "issueDate", label: "vault.field.issue_date"},
		{key: "expirationDate", label: "vault.field.expiration_date"},
		{key: "issuingAuthority", label: "vault.field.issuing_authority"},
		{key: "licenseClass", label: "vault.field.license.class"},
	},
	8: {
		{key: "surname", label: "vault.field.last_name"},
		{key: "givenName", label: "vault.field.first_name"},
		{key: "dateOfBirth", label: "vault.field.date_of_birth"},
		{key: "sex", label: "vault.field.passport.sex"},
		{key: "birthPlace", label: "vault.field.passport.birth_place"},
		{key: "nationality", label: "vault.field.passport.nationality"},
		{key: "issuingCountry", label: "vault.field.issuing_country"},
		{
			key:    "passportNumber",
			label:  "vault.field.passport.number",
			secret: true,
		},
		{key: "passportType", label: "vault.field.passport.type"},
		{
			key:    "nationalIdentificationNumber",
			label:  "vault.field.passport.national_identification_number",
			secret: true,
		},
		{key: "issuingAuthority", label: "vault.field.issuing_authority"},
		{key: "issueDate", label: "vault.field.issue_date"},
		{key: "expirationDate", label: "vault.field.expiration_date"},
	},
}

func sectionFields(f *vaultwarden.CipherFields) map[string]any {
	switch f.Type {
	case 1:
		return f.Login
	case 2:
		return f.SecureNote
	case 3:
		return f.Card
	case 4:
		return f.Identity
	case 5:
		return f.SSHKey
	case 6:
		return f.BankAccount
	case 7:
		return f.DriversLicense
	case 8:
		return f.Passport
	}
	return nil
}
func (a *app) adoptVault(vault *vaultwarden.VaultData) error {
	if a.session != nil {
		a.idleLock.start()
	}
	a.clearOrganizationEditor()
	organizationPrompt := a.editor != nil && a.organizationItem(a.editor.repromptID)
	a.vault = nil
	a.folders = nil
	a.organizations, a.collections, a.isolatedOrganizations = nil, nil, nil
	if vault == nil {
		return nil
	}
	a.items = nil
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.liveScope == nil || vault.Scope != *a.liveScope {
		return vaultwarden.ErrIdentity
	}
	if err := session.ValidateAuthenticatedSnapshot(vault, a.sessionRevision); err != nil {
		return err
	}
	entries, err := session.PersonalEntries(vault)
	if err != nil {
		return err
	}
	folders, err := session.PersonalFolders(vault)
	if err != nil {
		return err
	}
	organizations, collections, err := session.Organizations(vault)
	if err != nil {
		return err
	}
	isolated, err := session.IsolatedOrganizations(vault)
	if err != nil {
		return err
	}
	orgEntries, err := session.OrganizationEntries(vault)
	if err != nil {
		return err
	}
	entries = append(entries, orgEntries...)
	items := make([]localstore.DisplayCredential, 0, len(entries))
	for _, e := range entries {
		items = append(items, localstore.DisplayCredential{
			OrganizationID:   e.OrganizationID,
			CollectionIDs:    e.CollectionIDs,
			Readable:         e.Readable,
			ID:               e.ID,
			Title:            e.Title,
			Username:         e.Username,
			URL:              e.URL,
			Type:             e.Type,
			Favorite:         e.Favorite,
			Archived:         e.Archived,
			Deleted:          e.Deleted,
			Editable:         e.Editable,
			RequiresPassword: e.RequiresPassword,
			FolderID:         e.FolderID,
		})
	}
	a.clearSecretClipboard()
	if a.editor != nil {
		e := a.editor
		organizationDraft := organizationPrompt || e.fields.OrganizationID != nil || e.organizationID != "" || e.shareOrganizationID != ""
		for _, entry := range entries {
			if entry.ID == e.fields.ID && entry.OrganizationID != "" {
				organizationDraft = true
			}
		}
		if organizationDraft {
			// A new organization sync may revoke access or replace its owner key.
			// Personal conflict retention must not keep organization plaintext alive.
			*e = cipherEditor{}
			a.editor = nil
			a.secretInputVersion++
		}
	}
	a.organizations, a.collections, a.isolatedOrganizations = organizations, collections, isolated
	a.vault, a.items, a.folders = vault, items, folders
	if strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
		found := false
		for _, folder := range folders {
			if a.category == "folder:"+folder.ID {
				found = true
				break
			}
		}
		if !found {
			a.category = "folder:"
		}
	}
	return nil
}
func (a *app) openCipherEditor(id string, kind int) {
	a.openCipherEditorAuthorized(id, kind, nil)
}

func (a *app) openCipherEditorAuthorized(id string, kind int, grant *vaultwarden.ItemAuthorization) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.organizationEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	defaultMatch, err := session.DefaultURIMatch(a.vault)
	if err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	editor := &cipherEditor{revision: a.sessionRevision, authorization: grant, defaultURIMatch: defaultMatch}
	if grant != nil {
		editor.authorizationExpires = grant.ExpiresAt()
	}
	if err := session.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	if id != "" {
		var err error
		if a.organizationItem(id) {
			editor.document, editor.fields, err = session.ReadOrganizationCipher(a.vault, id, grant)
		} else {
			editor.document, editor.fields, err = session.ReadPersonalCipherAuthorized(a.vault, id, grant)
		}
		if err != nil {
			if errors.Is(err, vaultwarden.ErrPermission) && grant == nil && (session.PersonalItemRequiresPassword(a.vault, id) || a.organizationItemRequiresPassword(id)) {
				editor.repromptID = id
				a.editor = editor
				a.secretInputVersion++
			}
			a.status = vaultwarden.ErrorMessage(err)
			return
		}
		if (!editor.fields.Edit && editor.fields.OrganizationID == nil) || !editor.fields.ViewPassword {
			a.status = vaultwarden.ErrorMessage(vaultwarden.ErrPermission)
			return
		}
	} else {
		editor.fields = vaultwarden.CipherFields{Type: kind, Login: map[string]any{}, SecureNote: map[string]any{}, Card: map[string]any{}, Identity: map[string]any{}, SSHKey: map[string]any{}, BankAccount: map[string]any{}, DriversLicense: map[string]any{}, Passport: map[string]any{}}
	}
	populateCipherEditor(editor)
	if id == "" {
		for _, collection := range a.collections {
			if a.category == "collection:"+collection.ID {
				if collection.ReadOnly || collection.HidePasswords {
					a.status = vaultwarden.ErrorMessage(vaultwarden.ErrPermission)
					return
				}
				editor.organizationID, editor.collectionID = collection.OrganizationID, collection.ID
			}
		}
		if strings.HasPrefix(a.category, "org:") {
			a.status = i18n.T("vault.editor.err_select_writable_collection")
			return
		}
	}
	a.editor = editor
	a.folderEditor = nil
	if id == "" && strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
		folder := strings.TrimPrefix(a.category, "folder:")
		editor.fields.FolderID = &folder
	}
	a.secretInputVersion++
}

func populateCipherEditor(editor *cipherEditor) {
	editor.inputs, editor.uris, editor.custom = nil, nil, nil
	editor.notes = ""
	editor.inputs = append([]editorField(nil), editorSpecs[editor.fields.Type]...)
	section := sectionFields(&editor.fields)
	for i := range editor.inputs {
		editor.inputs[i].label = i18n.T(editor.inputs[i].label)
		editor.inputs[i].value, _ = section[editor.inputs[i].key].(string)
	}
	if uris, ok := editor.fields.Login["uris"].([]any); ok {
		for _, raw := range uris {
			if uri, ok := raw.(map[string]any); ok {
				value, _ := uri["uri"].(string)
				editor.uris = append(editor.uris, editorURI{source: uri, value: value})
			}
		}
	}
	for _, field := range editor.fields.Fields {
		name, _ := field["name"].(string)
		value, _ := field["value"].(string)
		kind, _ := field["type"].(json.Number)
		linked, _ := field["linkedId"].(json.Number)
		editor.custom = append(editor.custom, editorCustom{source: field, name: name, value: value, hidden: kind == "1", editable: kind == "0" || kind == "1" || kind == "2" || kind == "3", kind: string(kind), linkedID: linked})
	}
	if editor.fields.Notes != nil {
		editor.notes = *editor.fields.Notes
	}
}
func (a *app) cipherEditorView(c *ui.Context) {
	callStorage := a.vaultStorage()
	e := a.editor
	if e.fields.OrganizationID != nil && !e.fields.Edit && e.repromptID == "" {
		a.readOnlyOrganizationCipherView(c, e)
		return
	}
	if e.repromptID != "" && !e.compareAuthorization {
		a.itemAuthorizationView(c)
		return
	}
	if !e.authorizationExpires.IsZero() {
		if !time.Now().Before(e.authorizationExpires) {
			e.shownSecret = ""
			if a.pending == 0 {
				*e = cipherEditor{}
			}
			a.editor = nil
			a.secretInputVersion++
			a.status = i18n.T("vault.editor.err_authorization_expired")
			return
		}
		c.After(time.Until(e.authorizationExpires))
	}
	if e.shownSecret != "" {
		if !time.Now().Before(e.shownSecretExpires) || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
			e.shownSecret = ""
		} else {
			c.After(time.Until(e.shownSecretExpires))
		}
	}
	if e.repromptID != "" {
		a.itemAuthorizationView(c)
		return
	}
	if e.comparison != nil {
		a.cipherComparisonView(c)
		return
	}
	ui.Scroll(c.Key(fmt.Sprintf("cipher-editor-%d", a.secretInputVersion))).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(12).Padding(18).Children(func() {
			title := i18n.Tf("vault.editor.edit_title", i18n.T(cipherTypeNames[e.fields.Type]))
			if e.fields.ID == "" {
				title = i18n.Tf("vault.editor.add_title", i18n.T(cipherTypeNames[e.fields.Type]))
			}
			ui.Text(c, title).FontSize(23).FontWeight(600)
			if e.fields.OrganizationID != nil || e.organizationID != "" {
				ui.Text(c, i18n.T("vault.editor.organization_sync_hint")).FontSize(12)
			}
			if e.organizationID != "" && e.fields.ID == "" {
				a.organizationTypePicker(c, e)
			}
			ui.Text(c, i18n.T("vault.field.title")).FontSize(12)
			ui.TextInput(c, &e.fields.Name).Label(i18n.T("vault.field.title")).Disabled(a.pending != 0 || e.uncertain)
			for i := range e.inputs {
				f := &e.inputs[i]
				ui.Text(c, f.label).FontSize(12)
				ui.Column(c.Key(f.key)).Children(func() {
					var input ui.Element
					if f.key == "privateKey" || f.key == "publicKey" {
						input = ui.TextArea(c, &f.value).MinHeight(100)
					} else {
						input = ui.TextInput(c, &f.value)
					}
					input.Label(f.label).Disabled(a.pending != 0 || e.uncertain)
					if f.secret {
						input.Password()
					}
				})
			}
			if e.fields.Type == 1 {
				if e.fields.ID != "" {
					ui.Row(c).Gap(8).Children(func() {
						if kit.Action(c, i18n.T("vault.editor.show_saved_password"), "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.showPersonalSecret("password", callStorage)
						}
						if kit.Action(c, i18n.T("vault.editor.show_current_code"), "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.showPersonalSecret("totp", callStorage)
						}
						if kit.Action(c, i18n.T("vault.editor.copy_saved_password"), "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.copyPersonalSecret("password", callStorage)
						}
						if kit.Action(c, i18n.T("vault.editor.copy_current_code"), "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.copyPersonalSecret("totp", callStorage)
						}
					})
					if e.shownSecret != "" {
						ui.Text(c, e.shownSecret).FontSize(20)
						if kit.Action(c, i18n.T("common.hide"), "", false, false).Clicked() {
							e.shownSecret = ""
						}
					}
					ui.Text(c, i18n.T("vault.editor.secret_display_hint")).FontSize(12)
				}
				ui.Text(c, i18n.T("vault.field.website")).FontSize(12)
				remove := -1
				for i := range e.uris {
					uri := &e.uris[i]
					ui.Row(c.Key(fmt.Sprintf("uri-%d", i))).Gap(8).Children(func() {
						ui.TextInput(c, &uri.value).Label(i18n.Tf("vault.editor.website_number", i+1)).Grow(1).Disabled(a.pending != 0 || e.uncertain)
						if kit.Action(c, i18n.T("vault.editor.remove"), "", false, a.pending != 0 || e.uncertain).Clicked() {
							remove = i
						}
					})
					a.uriMatchPicker(c, uri, a.pending != 0 || e.uncertain)
				}
				if remove >= 0 {
					e.uris = append(e.uris[:remove], e.uris[remove+1:]...)
				}
				if kit.Action(c, i18n.T("vault.editor.add_website"), "", false, a.pending != 0 || e.uncertain || len(e.uris) >= 128).Clicked() {
					e.uris = append(e.uris, editorURI{source: map[string]any{"match": nil}})
				}
			}
			a.folderPicker(c, &e.fields.FolderID, a.pending != 0 || e.uncertain)
			favorite := i18n.T("vault.editor.add_favorite")
			if e.fields.Favorite {
				favorite = i18n.T("vault.editor.remove_favorite")
			}
			if kit.Action(c, favorite, "star", false, a.pending != 0 || e.uncertain).Clicked() {
				e.fields.Favorite = !e.fields.Favorite
			}
			ui.Text(c, i18n.T("vault.field.custom")).FontSize(12)
			removeCustom := -1
			for i := range e.custom {
				field := &e.custom[i]
				ui.Column(c.Key(fmt.Sprintf("custom-%d", i))).Gap(6).Children(func() {
					ui.TextInput(c, &field.name).Label(i18n.T("vault.field.custom_name")).Disabled(a.pending != 0 || e.uncertain || !field.editable)
					a.customValueEditor(c, e, field)
					if kit.Action(c, i18n.T("vault.editor.delete_field"), "", false, a.pending != 0 || e.uncertain).Clicked() {
						removeCustom = i
					}
				})
			}
			if removeCustom >= 0 {
				e.custom = append(e.custom[:removeCustom], e.custom[removeCustom+1:]...)
			}
			ui.Row(c).Gap(8).Children(func() {
				if kit.Action(c, i18n.T("vault.editor.add_text_field"), "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("0")}, editable: true, kind: "0"})
				}
				if kit.Action(c, i18n.T("vault.editor.add_hidden_field"), "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("1")}, hidden: true, editable: true, kind: "1"})
				}
			})
			ui.Row(c).Gap(8).Children(func() {
				if kit.Action(c, i18n.T("vault.editor.add_boolean_field"), "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("2")}, value: "false", editable: true, kind: "2"})
				}
				if len(linkedFields[e.fields.Type]) > 0 && kit.Action(c, i18n.T("vault.editor.add_linked_field"), "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("3")}, editable: true, kind: "3", linkedID: linkedFields[e.fields.Type][0].id})
				}
			})
			a.passwordHistoryView(c, e)
			a.attachmentView(c, e)
			a.cipherAttachmentMigrationView(c, e)
			ui.Text(c, i18n.T("common.notes")).FontSize(12)
			ui.TextArea(c, &e.notes).Label(i18n.T("common.notes")).MinHeight(100).Disabled(a.pending != 0 || e.uncertain)
			if e.uncertain {
				ui.Text(c, i18n.T("vault.editor.uncertain_hint")).FontSize(12).TextColor(kit.Purple)
			}
			if e.fields.OrganizationID == nil && e.fields.ID != "" && (e.conflict || e.uncertain || e.revision != a.sessionRevision) {
				ui.Text(c, i18n.T("vault.compare.draft_preserved_hint"))
				if kit.Action(c, i18n.T("vault.editor.sync_latest"), "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
				if kit.Action(c, i18n.T("vault.compare.title"), "", false, a.pending != 0 || e.revision == a.sessionRevision).Clicked() {
					a.compareCipher(nil)
				}
			}
			ui.Row(c).Gap(8).Children(func() {
				if kit.Action(c, i18n.T("common.save"), "sync", true, a.pending != 0 || e.conflict || e.revision != a.sessionRevision || e.uncertain || e.fields.Name == "").Clicked() {
					a.saveCipher()
				}
				if kit.Action(c, i18n.T("common.cancel"), "", false, a.pending != 0).Clicked() {
					a.editor = nil
				}
				if e.uncertain && kit.Action(c, i18n.T("vault.editor.sync_verify"), "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			})
			if e.fields.ID != "" && e.fields.OrganizationID == nil {
				if organizationUIEnabled && vaultwarden.CipherShareRequiresRecovery(e.document) {
					ui.Text(c, i18n.T("vault.share_recovery.legacy_attachment_hint"))
				}
				if organizationUIEnabled {
					a.organizationShareView(c, e)
				}
				a.cipherStateButtons(c, e)
			}
		})
	})
}

const copyCipherAction vaultwarden.CipherAction = "copyDraft"

func (a *app) cipherStateButtons(c *ui.Context, e *cipherEditor) {
	if e.confirm != "" {
		text := i18n.T("vault.editor.confirm_trash")
		if e.confirm == vaultwarden.CipherDeletePermanently {
			text = i18n.T("vault.editor.confirm_delete_permanently")
		}
		if e.confirm == copyCipherAction {
			text = i18n.T("vault.copy.confirm_copy")
		}
		ui.Text(c, text).TextColor(kit.Purple)
		ui.Row(c).Gap(8).Children(func() {
			if kit.Action(c, i18n.T("common.confirm"), "", true, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(e.confirm)
			}
			if kit.Action(c, i18n.T("vault.editor.cancel_operation"), "", false, a.pending != 0).Clicked() {
				e.confirm = ""
			}
		})
		return
	}
	ui.Row(c).Gap(8).Children(func() {
		if kit.Action(c, i18n.T("vault.copy.create_item"), "", false, a.pending != 0 || e.uncertain).Clicked() {
			e.confirm = copyCipherAction
		}
		if e.fields.DeletedDate != nil {
			if kit.Action(c, i18n.T("common.restore"), "", false, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(vaultwarden.CipherRestore)
			}
			if kit.Action(c, i18n.T("common.delete_permanently"), "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = vaultwarden.CipherDeletePermanently
			}
		} else {
			label, op := i18n.T("common.archive"), vaultwarden.CipherArchive
			if e.fields.ArchivedDate != nil {
				label, op = i18n.T("common.unarchive"), vaultwarden.CipherUnarchive
			}
			if kit.Action(c, label, "", false, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(op)
			}
			if kit.Action(c, i18n.T("vault.editor.move_to_trash"), "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = vaultwarden.CipherTrash
			}
		}
	})
}
func (a *app) saveCipher() { a.mutateCipher("") }
func (a *app) mutateCipher(action vaultwarden.CipherAction) {
	if a.pending != 0 || a.editor == nil || a.editor.conflict || a.editor.uncertain || !a.sessionOwnsSnapshot() {
		return
	}
	if !a.editor.authorizationExpires.IsZero() && !time.Now().Before(a.editor.authorizationExpires) {
		*a.editor = cipherEditor{}
		a.editor = nil
		a.secretInputVersion++
		a.status = i18n.T("vault.editor.err_authorization_expired")
		return
	}
	if a.editor.revision != a.sessionRevision {
		a.status = i18n.T("vault.editor.err_revision_changed")
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	editor := a.editor
	editor.applyInputs()
	if action == copyCipherAction && editor.fields.OrganizationID == nil && cipherHasAttachments(editor.document) {
		a.startResourceCipherCopy(session, editor)
		return
	}
	vault := a.vault
	scope, prior := *a.liveScope, a.snapshot
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	parent := a.mainWindow
	a.status = i18n.T("vault.editor.status_saving")
	go func() {
		var reply localstore.Reply
		var checkpointState *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpointState = reply.State
			}
			return err
		}
		current := callStorage(localstore.Request{Operation: localstore.OperationStatus})
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			switch {
			case action == shareOrganizationAction:
				_, err = shareCipherWithRecovery(ctx, parent, session, vault, editor, scope, editor.revision, persist, callStorage)
			case editor.organizationID != "":
				_, err = session.CreateOrganizationCipher(ctx, vault, editor.organizationID, editor.collectionID, editor.fields, persist)
			case editor.fields.OrganizationID != nil:
				if action != "" {
					err = vaultwarden.ErrPermission
				} else {
					_, err = session.UpdateOrganizationCipher(ctx, vault, editor.document, editor.fields, editor.authorization, persist)
				}
			case action == copyCipherAction:
				_, err = session.CopyPersonalCipherAuthorized(ctx, scope, editor.document, editor.fields, editor.authorization, persist)
			case action != "":
				err = session.ChangePersonalCipherStateAuthorized(ctx, scope, editor.document, action, editor.authorization, persist)
			case editor.fields.ID == "":
				_, err = session.CreatePersonalCipher(ctx, scope, editor.fields, persist)
			default:
				_, err = session.UpdatePersonalCipherAuthorized(ctx, scope, editor.document, editor.fields, editor.authorization, persist)
			}
		}
		a.dispatchUI(func() { a.completeCipherMutation(epoch, editor, checkpointState, reply, err, cancel) })
	}()
}

func (a *app) completeCipherMutation(epoch uint64, editor *cipherEditor, checkpointState *localstore.SnapshotStatus, reply localstore.Reply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		// This operation has finished using its private draft. A lock/account
		// switch already detached it from the app; release its remaining secrets.
		*editor = cipherEditor{}
		return
	}
	a.cancel = nil
	if checkpointState != nil && !a.adoptSessionCheckpoint(checkpointState) {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
		return
	}
	if err != nil {
		var unknown *vaultwarden.MutationUncertainError
		editor.conflict = errors.Is(err, vaultwarden.ErrConflict)
		editor.uncertain = errors.As(err, &unknown)
		a.syncFailed(reply, err)
		return
	}
	editor.uncertain, editor.saved = true, true
	a.status = i18n.T("vault.editor.status_submitted")
	a.syncVault(false)
}
