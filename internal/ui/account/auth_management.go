// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type AuthManagementRequest struct {
	Scope           vaultwarden.Scope
	Epoch, Sequence uint64
	Operation       vaultwarden.MFAManageOperation
	Input           vaultwarden.AccountSensitiveInput
	Fields          map[string]json.RawMessage
	Confirmed       bool
	Context         context.Context
}

func (r *AuthManagementRequest) Close() {
	clear(r.Input.Password)
	r.Input.Password = nil
	r.Input.OTP = ""
	for _, v := range r.Fields {
		clear(v)
	}
	clear(r.Fields)
}

type AuthManagementForm struct {
	scope                                       vaultwarden.Scope
	epoch, sequence                             uint64
	operation                                   vaultwarden.MFAManageOperation
	password, otp, status, result               string
	values                                      map[string]string
	busy, closed, confirming, uncertain, reveal bool
	cancel                                      context.CancelFunc
	Submit                                      func(AuthManagementRequest)
}

func NewAuthManagementForm(scope vaultwarden.Scope, epoch uint64, submit func(AuthManagementRequest)) *AuthManagementForm {
	return &AuthManagementForm{scope: scope, epoch: epoch, operation: vaultwarden.MFAList, values: map[string]string{}, Submit: submit}
}
func (f *AuthManagementForm) clear() {
	f.password = ""
	f.otp = ""
	clear(f.values)
	f.result = ""
	f.reveal = false
}
func (f *AuthManagementForm) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	f.clear()
	f.closed = true
	f.sequence++
	f.busy = false
}
func (f *AuthManagementForm) dispatch() {
	if f.closed || f.busy || (f.uncertain && f.operation != vaultwarden.MFAList) || f.Submit == nil {
		return
	}
	sensitive := f.operation != "list" && f.operation != "request-otp" && f.operation != "verify-otp"
	if sensitive && !f.confirming {
		f.confirming = true
		f.status = i18n.T("account.mfa.confirm_settings_impact")
		return
	}
	fields := map[string]json.RawMessage{}
	for k, v := range f.values {
		if v != "" {
			fields[k], _ = json.Marshal(v)
		}
	}
	if f.operation == "yubikey" {
		fields["nfc"] = json.RawMessage(`false`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.sequence++
	f.busy = true
	request := AuthManagementRequest{Scope: f.scope, Epoch: f.epoch, Sequence: f.sequence, Operation: f.operation, Input: vaultwarden.AccountSensitiveInput{Password: []byte(f.password), OTP: f.otp}, Fields: fields, Confirmed: f.confirming, Context: ctx}
	f.clear()
	f.confirming = false
	f.Submit(request)
}
func (f *AuthManagementForm) Complete(scope vaultwarden.Scope, epoch, sequence uint64, result string, err error) bool {
	if f.closed || scope != f.scope || epoch != f.epoch || sequence != f.sequence {
		return false
	}
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	f.busy = false
	f.clear()
	if err != nil {
		f.uncertain = true
		f.status = i18n.T("account.mfa.err_settings_uncertain")
	} else {
		f.uncertain = false
		f.result = result
		f.status = i18n.T("account.mfa.status_settings_received")
	}
	return true
}

var authManagementOperations = []struct {
	op     vaultwarden.MFAManageOperation
	label  string
	fields []string
}{
	{"list", i18n.T("account.mfa.load_methods"), nil}, {"get-authenticator", i18n.T("account.mfa.prepare_authenticator"), nil}, {"authenticator", i18n.T("account.mfa.enable_authenticator"), []string{"key", "token"}},
	{"get-email", i18n.T("account.mfa.load_email_settings"), nil}, {"send-email", i18n.T("account.mfa.send_email_setup_code"), []string{"email"}}, {"email", i18n.T("account.mfa.enable_email"), []string{"email", "token"}},
	{"get-duo", i18n.T("account.mfa.load_duo"), nil}, {"duo", i18n.T("account.mfa.save_duo"), []string{"host", "clientId", "clientSecret"}},
	{"get-yubikey", i18n.T("account.mfa.load_yubikey"), nil}, {"yubikey", i18n.T("account.mfa.save_yubikey"), []string{"key1", "key2", "key3", "key4", "key5"}},
	{"get-webauthn", i18n.T("account.mfa.load_security_keys"), nil}, {"get-webauthn-challenge", i18n.T("account.mfa.register_security_key"), []string{"id", "name"}}, {"delete-webauthn", i18n.T("account.mfa.delete_security_key"), []string{"id"}},
	{"get-recover", i18n.T("account.mfa.view_recovery_code"), nil}, {"disable", i18n.T("account.mfa.disable_method"), []string{"type"}}, {"request-otp", i18n.T("account.mfa.send_sensitive_otp"), nil}, {"verify-otp", i18n.T("account.mfa.verify_sensitive_otp"), []string{"otp"}},
}

func AuthManagementView(c *ui.Context, f *AuthManagementForm) {
	if f == nil || f.closed {
		return
	}
	for _, entry := range authManagementOperations {
		if ui.Button(c, entry.label).Disabled(f.busy || (f.uncertain && entry.op != vaultwarden.MFAList)).Clicked() {
			f.clear()
			f.confirming = false
			f.operation = entry.op
		}
	}
	ui.TextInput(c, &f.password).Label(i18n.T("account.mfa.master_password_hint")).Password().Disabled(f.busy)
	ui.TextInput(c, &f.otp).Label(i18n.T("account.mfa.sensitive_email_otp")).Password().Disabled(f.busy)
	labels := map[string]string{"name": i18n.T("account.mfa.security_key_name"), "key": i18n.T("account.mfa.authenticator_key"), "token": i18n.T("common.verification_code"), "email": i18n.T("account.mfa.recipient_email"), "host": i18n.T("account.mfa.duo_host"), "clientId": i18n.T("account.mfa.duo_client_id"), "clientSecret": i18n.T("account.mfa.duo_client_secret"), "id": i18n.T("account.mfa.security_key_id"), "type": i18n.T("account.mfa.method_id")}
	for _, entry := range authManagementOperations {
		if entry.op != f.operation {
			continue
		}
		for _, field := range entry.fields {
			value := f.values[field]
			label := labels[field]
			if label == "" {
				label = i18n.Tf("account.mfa.otp_slot", field)
			}
			ui.TextInput(c, &value).Label(label).Password().Disabled(f.busy)
			f.values[field] = value
		}
	}
	label := i18n.T("common.continue")
	if f.confirming {
		label = i18n.T("account.mfa.confirm_operation")
	}
	if ui.Button(c, label).Disabled(f.busy || (f.uncertain && f.operation != vaultwarden.MFAList)).Clicked() {
		f.dispatch()
	}
	if f.result != "" {
		if ui.Button(c, i18n.T("account.mfa.toggle_result")).Clicked() {
			f.reveal = !f.reveal
		}
		field := ui.TextInput(c, &f.result).Label(i18n.T("account.mfa.authentication_result")).Disabled(true)
		if !f.reveal {
			field.Password()
		}
	}
	if ui.Button(c, i18n.T("account.mfa.cancel_clear_authentication")).Clicked() {
		f.Close()
	}
	ui.Text(c, f.status).MaxLines(5)
}
