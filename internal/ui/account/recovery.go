// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"fmt"
	"strconv"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// recoveryFormRequest is owned by the worker until prepare returns. The host
// binds callbacks to the current scope/epoch and durable checkpoint/target
// invalidation adapter. No form is authority to recover an account.
type RecoveryFormRequest struct {
	Action, OrganizationID, MemberID, TrustedPublicKey string
	Emergency                                          vaultwarden.EmergencyRequest
	Password, NewPassword                              []byte
	OTP                                                string
	ResetPassword, ResetTwoFactor                      bool
}

func (r *RecoveryFormRequest) Close() {
	clear(r.Password)
	clear(r.NewPassword)
	r.Password = nil
	r.NewPassword = nil
	r.OTP = ""
	r.Emergency.Token = ""
}

type RecoveryMemberChoice struct {
	OrganizationID, MemberID, Label string
	Administrator                   bool
}
type RecoveryPanel struct {
	contacts                                                                              []vaultwarden.EmergencyContact
	trusted, emergency                                                                    bool
	members                                                                               []RecoveryMemberChoice
	selected                                                                              int
	operation, Email, token, public, password, otp, newPassword, repeatPassword, waitDays string
	accessType                                                                            int
	resetPassword, resetMFA                                                               bool
	running, submitting, terminal, closed                                                 bool
	generation                                                                            uint64
	cancel                                                                                context.CancelFunc
	Plan                                                                                  *vaultwarden.RecoveryPlan
	Status                                                                                string
	prepare                                                                               func(context.Context, RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error)
	commit                                                                                func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error)
	dispatch                                                                              func(func())
	Busy                                                                                  func(bool)
}

type PrepareEmergencyRecovery func(context.Context, RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error)
type CommitEmergencyRecovery func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error)

func NewEmergencyPanel(contacts []vaultwarden.EmergencyContact, trusted bool, prepare PrepareEmergencyRecovery, commit CommitEmergencyRecovery, dispatch func(func())) *RecoveryPanel {
	return &RecoveryPanel{contacts: append([]vaultwarden.EmergencyContact(nil), contacts...), trusted: trusted, emergency: true, selected: -1, operation: "invite", waitDays: "7", prepare: prepare, commit: commit, dispatch: dispatch}
}
func NewRecoveryPanel(members []RecoveryMemberChoice, prepare func(context.Context, RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error), commit func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error), dispatch func(func())) *RecoveryPanel {
	return &RecoveryPanel{members: append([]RecoveryMemberChoice(nil), members...), selected: -1, operation: "enroll", resetPassword: true, prepare: prepare, commit: commit, dispatch: dispatch}
}
func (p *RecoveryPanel) clearSecrets() {
	p.password = ""
	p.newPassword = ""
	p.repeatPassword = ""
	p.token = ""
	p.otp = ""
}

// cancelOperation invalidates preparation only. A dispatched commit remains
// owned by its worker and host callback until its result has been recorded.
func (p *RecoveryPanel) cancelOperation() {
	if p.cancel != nil {
		p.cancel()
	}
	p.clearSecrets()
	if p.submitting {
		p.Status = i18n.T("account.recovery.status_cancelling")
		return
	}
	p.generation++
	p.running = false
	p.cancel = nil
	if p.Plan != nil {
		p.Plan.Close()
		p.Plan = nil
	}
	p.Status = i18n.T("account.recovery.status_cancelled")
}
func (p *RecoveryPanel) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.generation++
	p.closed = true
	p.running = false
	p.cancel = nil
	p.clearSecrets()
	p.contacts = nil
	p.members = nil
	p.public = ""
	if p.Plan != nil {
		p.Plan.Close()
	}
	p.Plan = nil
	p.Status = ""
}
func (p *RecoveryPanel) blocked() bool { return p.closed || p.running || p.terminal }
func (p *RecoveryPanel) request() (RecoveryFormRequest, error) {
	r := RecoveryFormRequest{Action: p.operation, TrustedPublicKey: p.public, ResetPassword: p.resetPassword, ResetTwoFactor: p.resetMFA}
	if p.emergency {
		days, err := strconv.Atoi(p.waitDays)
		if err != nil {
			return r, vaultwarden.ErrValidation
		}
		r.Emergency = vaultwarden.EmergencyRequest{Action: p.operation, Trusted: p.trusted, Email: p.Email, Token: p.token, TrustedPublicKey: p.public, Type: p.accessType, WaitTimeDays: days}
		if p.operation == "accept" {
			r.Emergency.ID = p.Email
		} else if p.operation != "invite" {
			if p.selected < 0 || p.selected >= len(p.contacts) {
				return r, vaultwarden.ErrValidation
			}
			r.Emergency.ID = p.contacts[p.selected].ID
		}
	} else {
		if p.selected < 0 || p.selected >= len(p.members) {
			return r, vaultwarden.ErrValidation
		}
		m := p.members[p.selected]
		r.OrganizationID = m.OrganizationID
		r.MemberID = m.MemberID
		if p.operation == "administrator" && !m.Administrator {
			return r, vaultwarden.ErrPermission
		}
	}
	if p.operation == "takeover" || (p.operation == "administrator" && p.resetPassword) {
		if p.newPassword == "" || p.newPassword != p.repeatPassword {
			return r, vaultwarden.ErrValidation
		}
	}
	r.Password = []byte(p.password)
	r.NewPassword = []byte(p.newPassword)
	r.OTP = p.otp
	return r, nil
}
func (p *RecoveryPanel) PreparePlan() {
	if p.blocked() || p.Plan != nil || p.prepare == nil || p.dispatch == nil {
		return
	}
	r, err := p.request()
	if err != nil {
		p.Status = i18n.T("account.recovery.err_invalid_input")
		return
	}
	p.running = true
	if p.Busy != nil {
		p.Busy(true)
	}
	p.clearSecrets()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	generation := p.generation
	prepare, dispatch := p.prepare, p.dispatch
	go func() {
		plan, err := prepare(ctx, r)
		r.Close()
		cancel()
		dispatch(func() {
			if p.Busy != nil {
				p.Busy(false)
			}
			if p.closed || p.generation != generation {
				if plan != nil {
					plan.Close()
				}
				return
			}
			p.running = false
			p.cancel = nil
			if err != nil {
				if plan != nil {
					plan.Close()
				}
				p.Status = i18n.T("account.recovery.err_verification_failed")
				return
			}
			p.Plan = plan
			p.Status = i18n.T("account.recovery.status_verified")
		})
	}()
}
func (p *RecoveryPanel) CommitPlan() {
	if p.blocked() || p.Plan == nil || p.commit == nil || p.dispatch == nil {
		return
	}
	plan := p.Plan
	p.Plan = nil
	p.running = true
	if p.Busy != nil {
		p.Busy(true)
	}
	p.submitting = true
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	generation := p.generation
	commit, dispatch := p.commit, p.dispatch
	go func() {
		result, err := commit(ctx, plan, plan.ConfirmationText())
		plan.Close()
		cancel()
		dispatch(func() {
			if p.Busy != nil {
				p.Busy(false)
			}
			if p.closed || p.generation != generation {
				return
			}
			p.running = false
			p.submitting = false
			p.terminal = true
			p.cancel = nil
			p.clearSecrets()
			switch {
			case result.Unknown:
				p.Status = i18n.T("account.recovery.status_result_unknown")
			case err != nil:
				p.Status = i18n.T("account.recovery.status_unconfirmed")
			case result.Confirmed && result.RequireTargetLogin:
				p.Status = i18n.T("account.recovery.status_target_login_required")
			case result.Confirmed:
				p.Status = i18n.T("account.recovery.status_access_confirmed")
			default:
				p.Status = i18n.T("account.recovery.status_unreliable_result")
			}
		})
	}()
}
func (p *RecoveryPanel) View(c *ui.Context) {
	if p.closed {
		return
	}
	title := i18n.T("account.recovery.title")
	if p.emergency {
		title = i18n.T("account.emergency.title")
	}
	ui.Column(c).Gap(16).Children(func() {
		kit.Section(c, title, func() {
			disabled := p.blocked() || p.Plan != nil
			if p.emergency {
				if p.trusted {
					ui.Text(c, i18n.T("account.emergency.trusted_contacts"))
				} else {
					ui.Text(c, i18n.T("account.emergency.grantors"))
				}
				kit.Notice(c, kit.ToneInfo, i18n.T("account.emergency.approval_required_hint"))
				if len(p.contacts) == 0 {
					kit.EmptyState(c, "user", i18n.T("account.emergency.empty_contacts"), "")
				}
				for i, row := range p.contacts {
					states := []string{i18n.T("account.emergency.status_invited"), i18n.T("account.emergency.status_accepted"), i18n.T("account.emergency.status_confirmed"), i18n.T("account.emergency.status_awaiting_approval"), i18n.T("account.emergency.status_approved")}
					state := i18n.T("account.emergency.status_unknown")
					if row.Status >= 0 && row.Status < len(states) {
						state = states[row.Status]
					}
					kind := i18n.T("account.emergency.read_only")
					if row.Type == 1 {
						kind = i18n.T("account.emergency.take_over")
					}
					ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
						kit.Icon(c, "user", 20).TextColor(kit.Purple)
						ui.Column(c).Grow(1).MinWidth(0).Gap(4).Children(func() {
							ui.Text(c, row.Name).FontWeight(600).SingleLine()
							ui.Text(c, row.Email).FontSize(12).TextColor(kit.Muted).SingleLine()
							ui.Text(c, i18n.Tf("account.emergency.contact_access", kind, row.WaitTimeDays)).FontSize(12).TextColor(kit.Muted)
						})
						kit.Pill(c, state, kit.Selected, kit.Purple)
						kind := kit.ButtonQuiet
						if p.selected == i {
							kind = kit.ButtonSecondary
						}
						if kit.Button(c, i18n.T("account.emergency.select_contact"), "", kind, disabled).Key("emergency-contact-" + row.ID).Clicked() {
							p.selected = i
						}
					})
				}
				options := []struct{ action, label string }{
					{"invite", i18n.T("account.emergency.invite_contact")},
					{"accept", i18n.T("account.emergency.accept_invitation")},
					{"reinvite", i18n.T("account.emergency.resend_invitation")},
					{"confirm", i18n.T("account.emergency.confirm_distribute_keys")},
					{"initiate", i18n.T("account.emergency.request_access")},
					{"approve", i18n.T("account.emergency.approve_request")},
					{"reject", i18n.T("account.emergency.reject_revoke_approval")},
					{"update", i18n.T("account.emergency.change_type_wait")},
					{"delete", i18n.T("account.emergency.remove_access")},
					{"takeover", i18n.T("account.emergency.take_over_reset_password")},
				}
				ui.Row(c).Gap(8).Wrap().Children(func() {
					for _, o := range options {
						allowed := o.action == "invite" || o.action == "accept"
						if p.selected >= 0 && p.selected < len(p.contacts) {
							a := o.action
							if a == "takeover" {
								a = "password"
							}
							allowed = allowed || vaultwarden.EmergencyActionAllowed(p.contacts[p.selected], p.trusted, a)
						}
						kind := kit.ButtonQuiet
						if p.operation == o.action {
							kind = kit.ButtonSecondary
						}
						if o.action == "delete" || o.action == "reject" {
							kind = kit.ButtonDanger
						}
						if kit.Button(c, o.label, "", kind, disabled || !allowed).Key("emergency-action-" + o.action).Clicked() {
							p.operation = o.action
							p.clearSecrets()
						}
					}
				})
				if p.operation == "invite" {
					accountInput(c, &p.Email, i18n.T("account.emergency.contact_email")).Disabled(disabled)
				}
				if p.operation == "accept" {
					accountInput(c, &p.Email, i18n.T("account.emergency.invitation_id")).Disabled(disabled)
					accountInput(c, &p.token, i18n.T("account.emergency.email_token")).Password().Disabled(disabled)
				}
				if p.operation == "invite" || p.operation == "update" {
					kit.ChoiceGroup(c, i18n.T("account.emergency.access_type"), func() {
						for i, label := range []string{i18n.T("account.emergency.read_only"), i18n.T("account.emergency.take_over_reset_hint")} {
							kit.Choice(c.Key(fmt.Sprintf("emergency-type-%d", i)), &p.accessType, i, label, "", "shield", disabled)
						}
					})
					accountInput(c, &p.waitDays, i18n.T("account.emergency.wait_days")).Disabled(disabled)
				}
			} else {
				kit.ChoiceGroup(c, i18n.T("account.recovery.title"), func() {
					for i, m := range p.members {
						kit.Choice(c.Key("recovery-member-"+m.OrganizationID+"-"+m.MemberID), &p.selected, i, m.Label, "", "user", disabled)
					}
				})
				ui.Row(c).Gap(8).Wrap().Children(func() {
					for _, o := range []struct{ action, label string }{{"enroll", i18n.T("account.recovery.enroll")}, {"withdraw", i18n.T("account.recovery.withdraw")}, {"administrator", i18n.T("account.recovery.recover_member")}} {
						kind := kit.ButtonQuiet
						if p.operation == o.action {
							kind = kit.ButtonSecondary
						}
						if o.action == "withdraw" {
							kind = kit.ButtonDanger
						}
						if kit.Button(c, o.label, "", kind, disabled).Key("recovery-action-" + o.action).Clicked() {
							p.operation = o.action
							p.clearSecrets()
						}
					}
				})
				if p.operation == "enroll" {
					accountInput(c, &p.password, i18n.T("common.current_master_password")).Password().Disabled(disabled)
					accountInput(c, &p.otp, i18n.T("account.recovery.protected_email_otp")).Password().Disabled(disabled)
				}
				if p.operation == "administrator" {
					kit.Checkbox(c.Key("recovery-reset-password"), &p.resetPassword, i18n.T("account.recovery.reset_password"), disabled)
					kit.Checkbox(c.Key("recovery-reset-mfa"), &p.resetMFA, i18n.T("account.recovery.reset_mfa"), disabled)
				}
			}
			if p.operation == "confirm" || p.operation == "enroll" || p.operation == "administrator" {
				accountInput(c, &p.public, i18n.T("account.recovery.trusted_public_key")).Disabled(disabled)
			}
			if p.operation == "takeover" || (p.operation == "administrator" && p.resetPassword) {
				accountInput(c, &p.newPassword, i18n.T("account.recovery.target_new_password")).Password().Disabled(disabled)
				accountInput(c, &p.repeatPassword, i18n.T("account.form.repeat_password")).Password().Disabled(disabled)
			}
			if p.Plan != nil {
				summary := p.Plan.Summary()
				ui.Text(c, i18n.Tf("account.recovery.verified_target", summary.TargetEmail, summary.Target.Account))
				if summary.OrganizationID != "" {
					ui.Text(c, i18n.Tf("account.recovery.target_membership", summary.OrganizationID, summary.MembershipID))
				}
				if summary.CounterpartyEmail != "" {
					kind := i18n.T("account.emergency.read_only")
					if summary.EmergencyType == 1 {
						kind = i18n.T("account.emergency.take_over")
					}
					ui.Text(c, i18n.Tf("account.emergency.verified_contact", summary.CounterpartyEmail, kind, summary.WaitTimeDays))
				}
				kit.Notice(c, kit.ToneWarning, p.Plan.Impact())
			}
		})
		kit.ActionBar(c, func() {
			ui.Text(c, p.Status).FontSize(12).TextColor(kit.Muted).Grow(1).MinWidth(0)
			kind := kit.ButtonPrimary
			if p.operation == "delete" || p.operation == "reject" || p.operation == "withdraw" || p.operation == "takeover" {
				kind = kit.ButtonDanger
			}
			if p.Plan != nil {
				if kit.Button(c, i18n.T("account.recovery.confirm_authorization"), "", kind, p.blocked()).Key("recovery-confirm").Clicked() {
					p.CommitPlan()
				}
				if kit.Button(c, i18n.T("account.recovery.cancel_plan"), "", kit.ButtonSecondary, p.blocked()).Key("recovery-discard").Clicked() {
					p.Plan.Close()
					p.Plan = nil
					p.Status = i18n.T("account.recovery.status_cancelled")
				}
			} else if kit.Button(c, i18n.T("account.recovery.prepare"), "", kind, p.blocked()).Key("recovery-prepare").Clicked() {
				p.PreparePlan()
			}
			if p.running && kit.Button(c, i18n.T("account.recovery.cancel_check_result"), "", kit.ButtonSecondary, false).Key("recovery-cancel").Clicked() {
				p.cancelOperation()
			}
		})
	})
}
