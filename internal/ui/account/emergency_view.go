// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// emergencyViewer is deliberately independent from the normal vault/editor and
// offline/AutoFill stores. fetch must call WithEmergencyView with explicit
// consent; the host checks scope/epoch and dispatches completion on the UI thread.
type EmergencyViewer struct {
	contact                             vaultwarden.EmergencyContact
	running, closed, terminal, revealed bool
	generation                          uint64
	selected                            int
	rows                                []vaultwarden.CipherFields
	status                              string
	cancel                              context.CancelFunc
	fetch                               func(context.Context, string) ([]vaultwarden.CipherFields, error)
	dispatch                            func(func())
	Busy                                func(bool)
}

func NewEmergencyViewer(contact vaultwarden.EmergencyContact, fetch func(context.Context, string) ([]vaultwarden.CipherFields, error), dispatch func(func())) *EmergencyViewer {
	return &EmergencyViewer{contact: contact, selected: -1, fetch: fetch, dispatch: dispatch}
}
func (v *EmergencyViewer) cancelLoad() {
	if v.cancel != nil {
		v.cancel()
	}
	v.generation++
	v.running = false
	v.cancel = nil
	clear(v.rows)
	v.rows = nil
	v.selected = -1
	v.revealed = false
	v.status = i18n.T("account.emergency.status_view_cancelled")
}
func (v *EmergencyViewer) Close() {
	v.cancelLoad()
	v.closed = true
	v.status = ""
}
func (v *EmergencyViewer) load() {
	if v.closed || v.running || v.terminal || v.fetch == nil || v.dispatch == nil || !vaultwarden.EmergencyActionAllowed(v.contact, false, "view") {
		return
	}
	v.running = true
	if v.Busy != nil {
		v.Busy(true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	generation := v.generation
	fetch, dispatch, id := v.fetch, v.dispatch, v.contact.ID
	go func() {
		rows, err := fetch(ctx, id)
		cancel()
		dispatch(func() {
			if v.Busy != nil {
				v.Busy(false)
			}
			if v.closed || v.generation != generation {
				clear(rows)
				return
			}
			v.running = false
			v.terminal = true
			v.cancel = nil
			if err != nil {
				clear(rows)
				v.status = i18n.T("account.emergency.err_view_failed")
				return
			}
			v.rows = rows
			v.status = i18n.T("account.emergency.status_read_only")
		})
	}()
}
func emergencyDisplayFields(fields map[string]any) []string {
	labels := map[string]string{
		"username":                     i18n.T("common.username"),
		"password":                     i18n.T("common.password"),
		"totp":                         i18n.T("account.emergency.totp_key"),
		"uri":                          i18n.T("account.emergency.uri"),
		"cardholderName":               i18n.T("account.emergency.cardholder_name"),
		"brand":                        i18n.T("account.emergency.card_brand"),
		"number":                       i18n.T("account.emergency.card_number"),
		"expMonth":                     i18n.T("account.emergency.expiration_month"),
		"expYear":                      i18n.T("account.emergency.expiration_year"),
		"code":                         i18n.T("account.emergency.security_code"),
		"title":                        i18n.T("account.emergency.name_title"),
		"firstName":                    i18n.T("account.emergency.first_name"),
		"middleName":                   i18n.T("account.emergency.middle_name"),
		"lastName":                     i18n.T("account.emergency.last_name"),
		"address1":                     i18n.T("account.emergency.address"),
		"address2":                     i18n.T("account.emergency.address_extra"),
		"address3":                     i18n.T("account.emergency.address_extra"),
		"city":                         i18n.T("account.emergency.city"),
		"state":                        i18n.T("account.emergency.state"),
		"postalCode":                   i18n.T("account.emergency.postal_code"),
		"country":                      i18n.T("account.emergency.country"),
		"company":                      i18n.T("account.emergency.company"),
		"email":                        i18n.T("common.email"),
		"phone":                        i18n.T("account.emergency.phone"),
		"ssn":                          i18n.T("account.emergency.ssn"),
		"passportNumber":               i18n.T("account.emergency.passport_number"),
		"licenseNumber":                i18n.T("account.emergency.license_number"),
		"privateKey":                   i18n.T("account.emergency.private_key"),
		"publicKey":                    i18n.T("account.emergency.public_key"),
		"keyFingerprint":               i18n.T("account.emergency.key_fingerprint"),
		"bankName":                     i18n.T("account.emergency.bank_name"),
		"nameOnAccount":                i18n.T("account.emergency.account_holder"),
		"accountType":                  i18n.T("account.emergency.account_type"),
		"accountNumber":                i18n.T("account.emergency.account_number"),
		"routingNumber":                i18n.T("account.emergency.routing_number"),
		"branchNumber":                 i18n.T("account.emergency.branch_number"),
		"pin":                          "PIN",
		"swiftCode":                    "SWIFT",
		"iban":                         "IBAN",
		"bankContactPhone":             i18n.T("account.emergency.bank_phone"),
		"dateOfBirth":                  i18n.T("account.emergency.birth_date"),
		"issuingCountry":               i18n.T("account.emergency.issuing_country"),
		"issuingState":                 i18n.T("account.emergency.issuing_state"),
		"issueDate":                    i18n.T("account.emergency.issue_date"),
		"expirationDate":               i18n.T("account.emergency.expiration_date"),
		"issuingAuthority":             i18n.T("account.emergency.issuing_authority"),
		"licenseClass":                 i18n.T("account.emergency.license_class"),
		"surname":                      i18n.T("account.emergency.last_name"),
		"givenName":                    i18n.T("account.emergency.first_name"),
		"sex":                          i18n.T("account.emergency.sex"),
		"birthPlace":                   i18n.T("account.emergency.birth_place"),
		"nationality":                  i18n.T("account.emergency.nationality"),
		"passportType":                 i18n.T("account.emergency.passport_type"),
		"nationalIdentificationNumber": i18n.T("account.emergency.national_id"),
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var lines []string
	for _, key := range keys {
		value := fields[key]
		if value == nil || value == "" {
			continue
		}
		if key == "uris" {
			if rows, ok := value.([]any); ok {
				for _, row := range rows {
					if uri, ok := row.(map[string]any); ok && uri["uri"] != nil {
						lines = append(lines, i18n.Tf("account.emergency.uri_value", fmt.Sprint(uri["uri"])))
					}
				}
			}
			continue
		}
		if label, ok := labels[key]; ok {
			lines = append(lines, label+"："+fmt.Sprint(value))
		}
	}
	return lines
}

func (v *EmergencyViewer) View(c *ui.Context) {
	if v.closed {
		return
	}
	ui.Text(c, i18n.T("account.emergency.view_title")).FontSize(22)
	ui.Text(c, v.contact.Name+" · "+v.contact.Email)
	ui.Text(c, i18n.T("account.emergency.view_hint"))
	if kit.Action(c, i18n.T("account.emergency.confirm_view"), "", true, v.running || v.terminal || !vaultwarden.EmergencyActionAllowed(v.contact, false, "view")).Key("emergency-view-consent").Clicked() {
		v.load()
	}
	for i, row := range v.rows {
		if kit.Action(c, row.Name, "", v.selected == i, false).Key("emergency-view-item-" + row.ID).Clicked() {
			v.selected = i
			v.revealed = false
		}
	}
	if v.selected >= 0 && v.selected < len(v.rows) {
		if kit.Action(c, i18n.T("account.emergency.toggle_sensitive_data"), "", v.revealed, false).Key("emergency-view-reveal").Clicked() {
			v.revealed = !v.revealed
		}
		if v.revealed {
			row := v.rows[v.selected]
			if row.Notes != nil {
				ui.Text(c, i18n.Tf("account.emergency.notes_value", *row.Notes))
			}
			for _, section := range []struct {
				title  string
				fields map[string]any
			}{
				{i18n.T("itemtype.login"), row.Login},
				{i18n.T("account.emergency.card"), row.Card},
				{i18n.T("itemtype.identity"), row.Identity},
				{i18n.T("itemtype.ssh_key"), row.SSHKey},
				{i18n.T("itemtype.bank"), row.BankAccount},
				{i18n.T("itemtype.license"), row.DriversLicense},
				{i18n.T("itemtype.passport"), row.Passport},
			} {
				if len(section.fields) == 0 {
					continue
				}
				ui.Text(c, section.title)
				for _, line := range emergencyDisplayFields(section.fields) {
					ui.Text(c, line)
				}
			}
			for _, field := range row.Fields {
				ui.Text(c, fmt.Sprint(field["name"])+"："+fmt.Sprint(field["value"]))
			}
		}
	}
	if v.running && kit.Action(c, i18n.T("account.emergency.cancel_view"), "", false, false).Key("emergency-view-cancel").Clicked() {
		v.cancelLoad()
	}
	if v.status != "" {
		ui.Text(c, v.status)
	}
}
