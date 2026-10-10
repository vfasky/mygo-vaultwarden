// SPDX-License-Identifier: GPL-3.0-only
// Package account provides account, authentication, recovery, and device user interfaces.
package account

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/passwordstrength"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strconv"
)

// accountForm is an independent native component. The app integration owns
// network scheduling and authenticated storage receipts; no global/app state is
// changed here. Every completion carries scope + UI epoch and a request sequence.
type Form struct {
	scope                                                                        vaultwarden.Scope
	epoch, sequence                                                              uint64
	Mode                                                                         string
	Modes                                                                        []string
	RotationRequirements                                                         vaultwarden.RotationTrustRequirements
	rotationTrust                                                                vaultwarden.RecoveryRotationTrust
	legacyRecoveryReviewed                                                       bool
	RotationPreparations                                                         []vaultwarden.RotationCipherPreparation
	OpenRotationPreparation                                                      func(string, bool)
	Email, name, hint, avatar, password, newPassword, repeatPassword, token, otp string
	kdfType, iterations, memory, parallelism                                     string
	policy                                                                       vaultwarden.AccountPasswordPolicy
	score                                                                        int
	Status                                                                       string
	busy, confirming, uncertain, closed                                          bool
	confirmAction                                                                string
	apiKey                                                                       string
	apiKeyVisible                                                                bool
	plan                                                                         *vaultwarden.AccountChangePlan
	Submit                                                                       func(FormRequest)
}
type FormRequest struct {
	Scope                                 vaultwarden.Scope
	Epoch, Sequence                       uint64
	Operation                             string
	Email, Name, Hint, Avatar, Token, OTP string
	Password, NewPassword                 []byte
	KDF                                   vaultcrypto.KDF
	Plan                                  *vaultwarden.AccountChangePlan
	Confirmation                          string
	RotationTrust                         vaultwarden.RecoveryRotationTrust
}

func (r *FormRequest) Close() {
	clear(r.Password)
	clear(r.NewPassword)
	r.Password = nil
	r.NewPassword = nil
	r.Token = ""
	r.OTP = ""
}
func NewForm(scope vaultwarden.Scope, epoch uint64, submit func(FormRequest)) *Form {
	return &Form{scope: scope, epoch: epoch, Mode: "profile", score: -1, kdfType: "0", iterations: "600000", memory: "64", parallelism: "4", Submit: submit, rotationTrust: vaultwarden.RecoveryRotationTrust{Users: map[string]string{}, Organizations: map[string]string{}}}
}
func (f *Form) clearSecrets() {
	f.password = ""
	f.newPassword = ""
	f.repeatPassword = ""
	f.token = ""
	f.otp = ""
	f.apiKey = ""
	f.apiKeyVisible = false
}
func (f *Form) Close() {
	if f == nil {
		return
	}
	f.clearSecrets()
	f.plan.Close()
	f.plan = nil
	f.closed = true
	f.busy = false
	f.confirming = false
	f.sequence++
}
func (f *Form) cancel() {
	f.clearSecrets()
	f.plan.Close()
	f.plan = nil
	f.confirming = false
	f.confirmAction = ""
	f.busy = false
	f.sequence++
	f.Status = i18n.T("account.form.status_cancelled")
}
func (f *Form) accept(scope vaultwarden.Scope, epoch, sequence uint64) bool {
	return f != nil && !f.closed && f.scope == scope && f.epoch == epoch && f.sequence == sequence
}
func (f *Form) Prepared(scope vaultwarden.Scope, epoch, sequence uint64, plan *vaultwarden.AccountChangePlan, err error) bool {
	if !f.accept(scope, epoch, sequence) {
		plan.Close()
		return false
	}
	f.busy = false
	f.clearSecrets()
	if err != nil {
		plan.Close()
		f.Status = i18n.T("account.form.err_preparation_failed_hint")
		return false
	}
	if plan == nil {
		f.Status = i18n.T("account.form.err_preparation_failed")
		return false
	}
	f.plan = plan
	f.confirming = true
	f.Status = i18n.T("account.form.status_review_impact")
	return true
}
func (f *Form) Completed(scope vaultwarden.Scope, epoch, sequence uint64, result vaultwarden.AccountChangeResult, err error) bool {
	if !f.accept(scope, epoch, sequence) {
		return false
	}
	f.busy = false
	f.clearSecrets()
	f.plan.Close()
	f.plan = nil
	f.confirming = false
	f.confirmAction = ""
	if result.Dispatched {
		f.uncertain = true
		if result.Confirmed {
			f.Status = i18n.T("account.form.status_confirmed")
		} else {
			f.Status = i18n.T("account.form.status_partially_executed")
		}
		return true
	}
	if err != nil {
		var uncertain *vaultwarden.MutationUncertainError
		if errors.As(err, &uncertain) {
			f.uncertain = true
			f.Status = i18n.T("account.form.status_result_unknown")
			return true
		}
		f.Status = i18n.T("account.form.status_not_submitted")
	} else {
		f.Status = i18n.T("account.form.status_completed")
	}
	return true
}
func (f *Form) Registration(scope vaultwarden.Scope, epoch, sequence uint64, r vaultwarden.AccountRegistrationVerification, err error) bool {
	if !f.accept(scope, epoch, sequence) {
		return false
	}
	f.busy = false
	if err != nil {
		f.clearSecrets()
		f.Status = i18n.T("account.form.err_registration_request")
		return true
	}
	if r.EmailSent {
		f.Status = i18n.T("account.form.status_registration_email_requested")
	} else {
		f.token = r.Token
		f.Status = i18n.T("account.form.status_registration_token_received")
	}
	return true
}
func (f *Form) dispatch(operation string) {
	if f.closed || f.busy || f.uncertain || f.Submit == nil {
		return
	}
	if (operation == "prepare-delete" || operation == "prepare-rotate-user-key") && !f.legacyRecoveryReviewed {
		f.Status = i18n.T("account.rotation.err_pending_share_recovery")
		return
	}
	if operation == "commit" && (!f.confirming || f.plan == nil) {
		return
	}
	if (operation == "api-key" || operation == "rotate-api-key") && (!f.confirming || f.confirmAction != operation) {
		return
	}
	kdf := vaultcrypto.KDF{}
	if operation == "prepare-kdf" || operation == "register-finish" {
		var err error
		kdf.Type, err = strconv.Atoi(f.kdfType)
		if err != nil {
			f.Status = i18n.T("account.form.err_kdf_type")
			return
		}
		kdf.Iterations, err = strconv.Atoi(f.iterations)
		if err != nil {
			f.Status = i18n.T("account.form.err_kdf_iterations")
			return
		}
		if kdf.Type == 1 {
			kdf.Memory, err = strconv.Atoi(f.memory)
			if err != nil {
				f.Status = i18n.T("account.form.err_kdf_memory")
				return
			}
			kdf.Parallelism, err = strconv.Atoi(f.parallelism)
			if err != nil {
				f.Status = i18n.T("account.form.err_kdf_parallelism")
				return
			}
		}
	}
	if operation == "prepare-password" || operation == "register-finish" {
		password := f.newPassword
		if password != f.repeatPassword {
			f.Status = i18n.T("account.form.err_password_mismatch")
			return
		}
		if err := f.policy.Check(context.Background(), []byte(password), f.Email, false); err != nil {
			f.Status = i18n.T("account.form.err_password_policy")
			return
		}
	}
	f.sequence++
	r := FormRequest{Scope: f.scope, Epoch: f.epoch, Sequence: f.sequence, Operation: operation, Email: f.Email, Name: f.name, Hint: f.hint, Avatar: f.avatar, Token: f.token, OTP: f.otp, Password: []byte(f.password), NewPassword: []byte(f.newPassword), KDF: kdf, Plan: f.plan}
	r.RotationTrust = vaultwarden.RecoveryRotationTrust{Users: map[string]string{}, Organizations: map[string]string{}}
	for id, key := range f.rotationTrust.Users {
		r.RotationTrust.Users[id] = key
	}
	for id, key := range f.rotationTrust.Organizations {
		r.RotationTrust.Organizations[id] = key
	}
	if operation == "api-key" || operation == "rotate-api-key" {
		if !f.confirming || f.confirmAction != operation {
			return
		}
		r.Confirmation = operation
	}
	if operation == "commit" {
		if !f.confirming || f.plan == nil {
			return
		}
		r.Confirmation = f.plan.ConfirmationText()
	}
	f.busy = true
	f.clearSecrets()
	if operation == "commit" {
		f.plan = nil
	} // worker exclusively owns the submitted plan
	f.Submit(r) // ownership of sensitive byte slices transfers to scheduler
}
func (f *Form) evaluate() {
	r, err := passwordstrength.Evaluate(context.Background(), f.newPassword, f.Email, nil)
	if err != nil {
		f.score = -1
		f.Status = i18n.T("account.form.err_password_evaluation")
		return
	}
	f.score = r.Score
}
func FormView(c *ui.Context, f *Form) {
	if f == nil || f.closed {
		return
	}
	ui.Text(c, i18n.T("account.form.title")).FontSize(20)
	disabled := f.busy || f.uncertain
	if f.confirming {
		if f.confirmAction != "" {
			ui.Text(c, i18n.T("account.apikey.confirm_impact")).MaxLines(4)
		} else {
			ui.Text(c, accountImpact(f.plan.Kind())).MaxLines(6)
		}
		ui.Text(c, i18n.T("account.form.confirm_submission_impact")).MaxLines(4)
		if ui.Button(c, i18n.T("account.form.confirm_security_change")).Disabled(disabled).Clicked() {
			if f.confirmAction != "" {
				f.dispatch(f.confirmAction)
			} else {
				f.dispatch("commit")
			}
		}
		if ui.Button(c, i18n.T("common.cancel")).Disabled(f.busy).Clicked() {
			f.cancel()
		}
	} else {
		modes := f.Modes
		if modes == nil {
			modes = []string{"register", "profile", "password", "email", "kdf", "api-key", "security-stamp", "purge", "delete", "rotate-user-key"}
		}
		for _, mode := range modes {
			if ui.Button(c, accountModeLabel(mode)).Disabled(disabled).Clicked() {
				f.cancel()
				f.Mode = mode
			}
		}
		switch f.Mode {
		case "profile":
			ui.TextInput(c, &f.name).Label(i18n.T("account.form.profile_name")).Disabled(disabled)
			ui.TextInput(c, &f.avatar).Label(i18n.T("account.form.avatar_color")).Disabled(disabled)
			if ui.Button(c, i18n.T("account.form.save_profile")).Disabled(disabled).Clicked() {
				f.dispatch("profile")
			}
			if ui.Button(c, i18n.T("account.form.save_avatar")).Disabled(disabled).Clicked() {
				f.dispatch("avatar")
			}
			if ui.Button(c, i18n.T("account.form.request_email_verification")).Disabled(disabled).Clicked() {
				f.dispatch("verify-email")
			}
			ui.TextInput(c, &f.token).Label(i18n.T("account.form.verification_email_token")).Password().Disabled(disabled)
			if ui.Button(c, i18n.T("account.form.confirm_email_token")).Disabled(disabled || f.token == "").Clicked() {
				f.dispatch("verify-email-token")
			}
		case "register":
			ui.TextInput(c, &f.Email).Label(i18n.T("account.form.registration_email")).Disabled(disabled)
			ui.TextInput(c, &f.name).Label(i18n.T("account.form.display_name")).Disabled(disabled)
			if ui.Button(c, i18n.T("account.form.send_password_hint")).Disabled(disabled || f.Email == "").Clicked() {
				f.dispatch("password-hint")
			}
			if ui.Button(c, i18n.T("account.form.send_registration_email")).Disabled(disabled).Clicked() {
				f.dispatch("register-send")
			}
			ui.TextInput(c, &f.token).Label(i18n.T("account.form.registration_token")).Password().Disabled(disabled)
			accountNewPasswordView(c, f, disabled)
			accountKDFView(c, f, disabled)
			if ui.Button(c, i18n.T("account.form.finish_registration")).Disabled(disabled || f.token == "").Clicked() {
				f.dispatch("register-finish")
			}
		default:
			ui.TextInput(c, &f.password).Label(i18n.T("common.current_master_password")).Password().Disabled(disabled)
			switch f.Mode {
			case "password":
				accountNewPasswordView(c, f, disabled)
			case "email":
				ui.TextInput(c, &f.Email).Label(i18n.T("account.form.new_email")).Disabled(disabled)
				if ui.Button(c, i18n.T("account.form.request_email_change_code")).Disabled(disabled).Clicked() {
					f.dispatch("email-token")
				}
				ui.TextInput(c, &f.token).Label(i18n.T("account.form.email_change_code")).Password().Disabled(disabled)
			case "kdf":
				accountKDFView(c, f, disabled)
			case "rotate-user-key":
				if ui.Button(c, i18n.T("account.rotation.load_recipients")).Disabled(disabled).Clicked() {
					f.dispatch("rotation-recipients")
				}
				ui.Text(c, i18n.T("account.rotation.trusted_keys_hint")).MaxLines(4)
				for _, recipient := range f.RotationRequirements.Users {
					value := f.rotationTrust.Users[recipient.ID]
					ui.TextInput(c, &value).Label(i18n.Tf("account.rotation.trustee_public_key", recipient.Email, recipient.ID)).Disabled(disabled)
					f.rotationTrust.Users[recipient.ID] = value
				}
				for _, recipient := range f.RotationRequirements.Organizations {
					value := f.rotationTrust.Organizations[recipient.ID]
					ui.TextInput(c, &value).Label(i18n.Tf("account.rotation.organization_public_key", recipient.Name, recipient.ID)).Disabled(disabled)
					f.rotationTrust.Organizations[recipient.ID] = value
				}
			case "api-key", "security-stamp", "purge", "delete":
				ui.TextInput(c, &f.otp).Label(i18n.T("account.form.protected_email_otp")).Password().Disabled(disabled)
			}
			if f.Mode == "rotate-user-key" || f.Mode == "delete" {
				ui.Text(c, i18n.T("account.rotation.share_recovery_hint")).MaxLines(6)
				label := i18n.T("account.rotation.confirm_share_recovery")
				if f.legacyRecoveryReviewed {
					label = i18n.T("account.rotation.revoke_share_recovery_confirmation")
				}
				if ui.Button(c, label).Disabled(disabled).Clicked() {
					f.legacyRecoveryReviewed = !f.legacyRecoveryReviewed
				}
			}
			ui.Text(c, accountImpact(vaultwarden.AccountChangeKind(f.Mode))).MaxLines(5)
			if f.Mode == "api-key" {
				if ui.Button(c, i18n.T("account.apikey.view")).Disabled(disabled).Clicked() {
					f.confirmAction = "api-key"
					f.confirming = true
				}
				if ui.Button(c, i18n.T("account.apikey.rotate")).Disabled(disabled).Clicked() {
					f.confirmAction = "rotate-api-key"
					f.confirming = true
				}
			} else if ui.Button(c, i18n.T("account.form.continue_review_impact")).Disabled(disabled).Clicked() {
				f.dispatch("prepare-" + f.Mode)
			}
		}
		if ui.Button(c, i18n.T("account.form.cancel_clear_secrets")).Disabled(f.busy).Clicked() {
			f.cancel()
		}
	}
	if f.apiKey != "" {
		field := ui.TextInput(c, &f.apiKey).Label(i18n.T("account.apikey.secret_value")).Disabled(true)
		if !f.apiKeyVisible {
			field.Password()
		}
		label := i18n.T("account.apikey.show")
		if f.apiKeyVisible {
			label = i18n.T("account.apikey.hide")
		}
		if ui.Button(c, label).Clicked() {
			f.apiKeyVisible = !f.apiKeyVisible
		}
	}
	for _, preparation := range f.RotationPreparations {
		ui.Text(c, i18n.Tf("account.rotation.attachment_to_migrate", preparation.CipherID, preparation.AttachmentID)).MaxLines(3)
		if preparation.Deleted {
			ui.Text(c, i18n.T("account.rotation.trash_attachment_hint")).MaxLines(4)
		}
		if f.OpenRotationPreparation != nil && ui.Button(c.Key(preparation.CipherID+"/"+preparation.AttachmentID), i18n.T("account.rotation.open_item_migration")).Disabled(f.busy).Clicked() {
			f.OpenRotationPreparation(preparation.CipherID, preparation.Deleted)
		}
	}
	ui.Text(c, f.Status).MaxLines(5)
}
func accountNewPasswordView(c *ui.Context, f *Form, disabled bool) {
	ui.TextInput(c, &f.newPassword).Label(i18n.T("account.form.new_password")).Password().Disabled(disabled)
	ui.TextInput(c, &f.repeatPassword).Label(i18n.T("account.form.repeat_password")).Password().Disabled(disabled)
	ui.TextInput(c, &f.hint).Label(i18n.T("account.form.password_hint")).Disabled(disabled)
	if ui.Button(c, i18n.T("account.form.evaluate_password")).Disabled(disabled).Clicked() {
		f.evaluate()
	}
	if f.score >= 0 {
		ui.Text(c, i18n.Tf("account.form.password_strength", f.score))
	}
	ui.Text(c, i18n.Tf("account.form.password_policy_hint", f.policy.MinComplexity, f.policy.MinLength)).MaxLines(4)
}
func accountKDFView(c *ui.Context, f *Form, disabled bool) {
	ui.TextInput(c, &f.kdfType).Label("KDF：0 PBKDF2 / 1 Argon2id").Disabled(disabled)
	ui.TextInput(c, &f.iterations).Label(i18n.T("account.form.kdf_iterations")).Disabled(disabled)
	if f.kdfType == "1" {
		ui.TextInput(c, &f.memory).Label(i18n.T("account.form.kdf_memory")).Disabled(disabled)
		ui.TextInput(c, &f.parallelism).Label(i18n.T("account.form.kdf_parallelism")).Disabled(disabled)
	}
}
func accountModeLabel(mode string) string {
	switch mode {
	case "register":
		return i18n.T("account.form.register")
	case "profile":
		return i18n.T("account.form.profile")
	case "password":
		return i18n.T("account.form.change_password")
	case "email":
		return i18n.T("account.form.change_email")
	case "kdf":
		return i18n.T("account.form.change_kdf")
	case "api-key":
		return i18n.T("account.apikey.title")
	case "security-stamp":
		return i18n.T("account.form.revoke_sessions")
	case "purge":
		return i18n.T("account.form.purge_vault")
	case "delete":
		return i18n.T("account.form.delete_account")
	case "rotate-user-key":
		return i18n.T("account.rotation.rotate_user_key")
	}
	return i18n.T("account.form.operation_title")
}
func accountImpact(kind vaultwarden.AccountChangeKind) string {
	switch kind {
	case vaultwarden.AccountDelete:
		return i18n.T("account.form.confirm_delete_impact")
	case vaultwarden.AccountPurge:
		return i18n.T("account.form.confirm_purge_impact")
	case vaultwarden.AccountRotateKey:
		return i18n.T("account.rotation.confirm_impact")
	case vaultwarden.AccountSecurityStamp:
		return i18n.T("account.form.confirm_revoke_sessions_impact")
	default:
		return i18n.T("account.form.credentials_change_hint")
	}
}
