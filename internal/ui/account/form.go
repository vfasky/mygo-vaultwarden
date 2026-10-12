// SPDX-License-Identifier: GPL-3.0-only
// Package account provides account, authentication, recovery, and device user interfaces.
package account

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/passwordstrength"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strconv"
	"unicode/utf8"
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
	step                                                                         int  // registration step
	tokenFromServer, kdfOpen                                                     bool // registration
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
	if err != nil && f.Mode == "register" && f.step == registerPassword {
		// The token was cleared on submission; ask for it again.
		f.step = registerVerify
		if f.tokenFromServer {
			f.step = registerDetails
		}
	}
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
	f.Status = ""
	if r.EmailSent {
		f.step, f.tokenFromServer = registerVerify, false
	} else {
		// Servers without email verification return the token directly.
		f.token = r.Token
		f.step, f.tokenFromServer = registerPassword, true
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
		if utf8.RuneCountInString(password) < minMasterPassword {
			f.Status = i18n.T("account.register.err_password_too_short")
			return
		}
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
	deleting := f.confirming && f.plan != nil && (f.plan.Kind() == vaultwarden.AccountDelete || f.plan.Kind() == vaultwarden.AccountPurge)
	kit.Section(c, accountModeLabel(f.Mode), func() {
		disabled := f.busy || f.uncertain || deleting
		if f.confirming && !deleting {
			if f.confirmAction != "" {
				kit.Notice(c, kit.ToneWarning, i18n.T("account.apikey.confirm_impact"))
			} else {
				kit.Notice(c, kit.ToneWarning, accountImpact(f.plan.Kind()))
			}
			kit.Notice(c, kit.ToneWarning, i18n.T("account.form.confirm_submission_impact"))
		} else {
			modes := f.Modes
			if modes == nil {
				modes = []string{"profile", "password", "email", "kdf", "api-key", "security-stamp", "purge", "delete", "rotate-user-key"}
			}
			labels := make([]string, len(modes))
			for i, mode := range modes {
				labels[i] = accountModeLabel(mode)
			}
			selected := accountModeLabel(f.Mode)
			chosen := false
			kit.Field(c, i18n.T("account.form.operation_title"), "", func() {
				// Changed applies the choice to selected: Select sets it after the input.
				chosen = ui.Select(c, &selected, labels).Label(i18n.T("account.form.operation_title")).Disabled(disabled).Changed()
			})
			for i, mode := range modes {
				if chosen && selected == labels[i] && mode != f.Mode {
					f.cancel()
					f.Mode = mode
				}
			}
			switch f.Mode {
			case "profile":
				accountInput(c, &f.name, i18n.T("account.form.profile_name")).Disabled(disabled)
				accountInput(c, &f.avatar, i18n.T("account.form.avatar_color")).Disabled(disabled)
				if accountButton(c, i18n.T("account.form.save_avatar"), kit.ButtonSecondary).Disabled(disabled).Clicked() {
					f.dispatch("avatar")
				}
				if accountButton(c, i18n.T("account.form.request_email_verification"), kit.ButtonSecondary).Disabled(disabled).Clicked() {
					f.dispatch("verify-email")
				}
				accountInput(c, &f.token, i18n.T("account.form.verification_email_token")).Password().Disabled(disabled)
				if accountButton(c, i18n.T("account.form.confirm_email_token"), kit.ButtonSecondary).Disabled(disabled || f.token == "").Clicked() {
					f.dispatch("verify-email-token")
				}
			default:
				accountInput(c, &f.password, i18n.T("common.current_master_password")).Password().Disabled(disabled)
				switch f.Mode {
				case "password":
					accountNewPasswordView(c, f, disabled)
				case "email":
					accountInput(c, &f.Email, i18n.T("account.form.new_email")).Disabled(disabled)
					if accountButton(c, i18n.T("account.form.request_email_change_code"), kit.ButtonSecondary).Disabled(disabled).Clicked() {
						f.dispatch("email-token")
					}
					accountInput(c, &f.token, i18n.T("account.form.email_change_code")).Password().Disabled(disabled)
				case "kdf":
					accountKDFView(c, f, disabled)
				case "rotate-user-key":
					if accountButton(c, i18n.T("account.rotation.load_recipients"), kit.ButtonSecondary).Disabled(disabled).Clicked() {
						f.dispatch("rotation-recipients")
					}
					kit.Notice(c, kit.ToneInfo, i18n.T("account.rotation.trusted_keys_hint"))
					for _, recipient := range f.RotationRequirements.Users {
						value := f.rotationTrust.Users[recipient.ID]
						accountInput(c, &value, i18n.Tf("account.rotation.trustee_public_key", recipient.Email, recipient.ID)).Disabled(disabled)
						f.rotationTrust.Users[recipient.ID] = value
					}
					for _, recipient := range f.RotationRequirements.Organizations {
						value := f.rotationTrust.Organizations[recipient.ID]
						accountInput(c, &value, i18n.Tf("account.rotation.organization_public_key", recipient.Name, recipient.ID)).Disabled(disabled)
						f.rotationTrust.Organizations[recipient.ID] = value
					}
				case "api-key", "security-stamp", "purge", "delete":
					accountInput(c, &f.otp, i18n.T("account.form.protected_email_otp")).Password().Disabled(disabled)
				}
				if f.Mode == "rotate-user-key" || f.Mode == "delete" {
					kit.Notice(c, kit.ToneWarning, i18n.T("account.rotation.share_recovery_hint"))
					label := i18n.T("account.rotation.confirm_share_recovery")
					if f.legacyRecoveryReviewed {
						label = i18n.T("account.rotation.revoke_share_recovery_confirmation")
					}
					kit.Checkbox(c, &f.legacyRecoveryReviewed, label, disabled)
				}
				kit.Notice(c, kit.ToneWarning, accountImpact(vaultwarden.AccountChangeKind(f.Mode)))
			}
		}
		if f.apiKey != "" {
			field := accountInput(c, &f.apiKey, i18n.T("account.apikey.secret_value")).Disabled(true)
			if !f.apiKeyVisible {
				field.Password()
			}
			label := i18n.T("account.apikey.show")
			if f.apiKeyVisible {
				label = i18n.T("account.apikey.hide")
			}
			if accountButton(c, label, kit.ButtonQuiet).Clicked() {
				f.apiKeyVisible = !f.apiKeyVisible
			}
		}
		for _, preparation := range f.RotationPreparations {
			ui.Text(c, i18n.Tf("account.rotation.attachment_to_migrate", preparation.CipherID, preparation.AttachmentID)).MaxLines(3)
			if preparation.Deleted {
				kit.Notice(c, kit.ToneWarning, i18n.T("account.rotation.trash_attachment_hint"))
			}
			if f.OpenRotationPreparation != nil && accountButton(c.Key(preparation.CipherID+"/"+preparation.AttachmentID), i18n.T("account.rotation.open_item_migration"), kit.ButtonQuiet).Disabled(f.busy).Clicked() {
				f.OpenRotationPreparation(preparation.CipherID, preparation.Deleted)
			}
		}
	})
	kit.ActionBar(c, func() {
		ui.Text(c, f.Status).FontSize(12).TextColor(kit.Muted).Grow(1).MinWidth(0)
		disabled := f.busy || f.uncertain
		if f.confirming && !deleting {
			if kit.Button(c, i18n.T("common.cancel"), "", kit.ButtonSecondary, f.busy).Clicked() {
				f.cancel()
			}
			if kit.Button(c, i18n.T("account.form.confirm_security_change"), "", kit.ButtonDanger, disabled).Clicked() {
				if f.confirmAction != "" {
					f.dispatch(f.confirmAction)
				} else {
					f.dispatch("commit")
				}
			}
		} else if !f.confirming {
			if kit.Button(c, i18n.T("account.form.cancel_clear_secrets"), "", kit.ButtonSecondary, f.busy).Clicked() {
				f.cancel()
			}
			switch f.Mode {
			case "profile":
				if kit.Button(c, i18n.T("account.form.save_profile"), "", kit.ButtonPrimary, disabled).Clicked() {
					f.dispatch("profile")
				}
			case "api-key":
				if kit.Button(c, i18n.T("account.apikey.rotate"), "", kit.ButtonDanger, disabled).Clicked() {
					f.confirmAction = "rotate-api-key"
					f.confirming = true
				}
				if kit.Button(c, i18n.T("account.apikey.view"), "", kit.ButtonPrimary, disabled).Clicked() {
					f.confirmAction = "api-key"
					f.confirming = true
				}
			default:
				if kit.Button(c, i18n.T("account.form.continue_review_impact"), "", accountOperationKind(f.Mode), disabled).Clicked() {
					f.dispatch("prepare-" + f.Mode)
				}
			}
		}
	})
	if deleting {
		kit.ConfirmDialog(c, "account-delete", accountModeLabel(f.Mode), accountImpact(f.plan.Kind())+"\n\n"+i18n.T("account.form.confirm_submission_impact"), i18n.T("account.form.confirm_security_change"), i18n.T("common.cancel"), f.busy || f.uncertain,
			func() { f.dispatch("commit") }, func() {
				if !f.busy {
					f.cancel()
				}
			})
	}
}

// accountInput keeps page fields labeled while allowing callers to preserve
// their password and disabled policies on the underlying input.
func accountInput(c *ui.Context, value *string, label string, hints ...string) ui.Element {
	var input ui.Element
	hint := ""
	if len(hints) != 0 {
		hint = hints[0]
	}
	kit.Field(c, label, hint, func() {
		input = kit.Input(ui.TextInput(c, value).Label(label))
	})
	return input
}

// accountButton gives standalone form actions their natural content width.
func accountButton(c *ui.Context, label string, kind kit.ButtonKind) ui.Element {
	var button ui.Element
	ui.Row(c).Children(func() { button = kit.Button(c, label, "", kind, false) })
	return button
}
func accountNewPasswordView(c *ui.Context, f *Form, disabled bool) {
	accountInput(c, &f.newPassword, i18n.T("account.form.new_password"), i18n.T("account.form.new_password_hint")).Password().Disabled(disabled)
	accountInput(c, &f.repeatPassword, i18n.T("account.form.repeat_password")).Password().Disabled(disabled)
	accountInput(c, &f.hint, i18n.T("account.form.password_hint"), i18n.T("account.form.password_hint_help")).Disabled(disabled)
	if accountButton(c, i18n.T("account.form.evaluate_password"), kit.ButtonQuiet).Disabled(disabled).Clicked() {
		f.evaluate()
	}
	if f.score >= 0 {
		ui.Text(c, i18n.Tf("account.form.password_strength", f.score))
	}
	kit.Notice(c, kit.ToneInfo, i18n.Tf("account.form.password_policy_hint", f.policy.MinComplexity, f.policy.MinLength))
}
func accountKDFView(c *ui.Context, f *Form, disabled bool) {
	accountInput(c, &f.kdfType, i18n.T("account.form.kdf_type")).Disabled(disabled)
	accountInput(c, &f.iterations, i18n.T("account.form.kdf_iterations")).Disabled(disabled)
	if f.kdfType == "1" {
		accountInput(c, &f.memory, i18n.T("account.form.kdf_memory")).Disabled(disabled)
		accountInput(c, &f.parallelism, i18n.T("account.form.kdf_parallelism")).Disabled(disabled)
	}
}
func accountOperationKind(mode string) kit.ButtonKind {
	switch mode {
	case "purge", "delete", "security-stamp", "rotate-user-key":
		return kit.ButtonDanger
	default:
		return kit.ButtonPrimary
	}
}

func accountModeLabel(mode string) string {
	switch mode {
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
