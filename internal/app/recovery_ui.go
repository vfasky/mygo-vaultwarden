// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"fmt"
	"strconv"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// recoveryFormRequest is owned by the worker until prepare returns. The host
// binds callbacks to the current scope/epoch and durable checkpoint/target
// invalidation adapter. No form is authority to recover an account.
type recoveryFormRequest struct {
	Action, OrganizationID, MemberID, TrustedPublicKey string
	Emergency                                          vaultwarden.EmergencyRequest
	Password, NewPassword                              []byte
	OTP                                                string
	ResetPassword, ResetTwoFactor                      bool
}

func (r *recoveryFormRequest) Close() {
	clear(r.Password)
	clear(r.NewPassword)
	r.Password = nil
	r.NewPassword = nil
	r.OTP = ""
	r.Emergency.Token = ""
}

type recoveryMemberChoice struct {
	OrganizationID, MemberID, Label string
	Administrator                   bool
}
type recoveryPanel struct {
	contacts                                                                              []vaultwarden.EmergencyContact
	trusted, emergency                                                                    bool
	members                                                                               []recoveryMemberChoice
	selected                                                                              int
	operation, email, token, public, password, otp, newPassword, repeatPassword, waitDays string
	accessType                                                                            int
	resetPassword, resetMFA                                                               bool
	running, submitting, terminal, closed                                                 bool
	generation                                                                            uint64
	cancel                                                                                context.CancelFunc
	plan                                                                                  *vaultwarden.RecoveryPlan
	status                                                                                string
	prepare                                                                               func(context.Context, recoveryFormRequest) (*vaultwarden.RecoveryPlan, error)
	commit                                                                                func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error)
	dispatch                                                                              func(func())
	busy                                                                                  func(bool)
}

func newEmergencyPanel(contacts []vaultwarden.EmergencyContact, trusted bool, prepare func(context.Context, recoveryFormRequest) (*vaultwarden.RecoveryPlan, error), commit func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error), dispatch func(func())) *recoveryPanel {
	return &recoveryPanel{contacts: append([]vaultwarden.EmergencyContact(nil), contacts...), trusted: trusted, emergency: true, selected: -1, operation: "invite", waitDays: "7", prepare: prepare, commit: commit, dispatch: dispatch}
}
func newRecoveryPanel(members []recoveryMemberChoice, prepare func(context.Context, recoveryFormRequest) (*vaultwarden.RecoveryPlan, error), commit func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error), dispatch func(func())) *recoveryPanel {
	return &recoveryPanel{members: append([]recoveryMemberChoice(nil), members...), selected: -1, operation: "enroll", resetPassword: true, prepare: prepare, commit: commit, dispatch: dispatch}
}
func (p *recoveryPanel) clearSecrets() {
	p.password = ""
	p.newPassword = ""
	p.repeatPassword = ""
	p.token = ""
	p.otp = ""
}

// cancelOperation invalidates preparation only. A dispatched commit remains
// owned by its worker and host callback until its result has been recorded.
func (p *recoveryPanel) cancelOperation() {
	if p.cancel != nil {
		p.cancel()
	}
	p.clearSecrets()
	if p.submitting {
		p.status = "正在取消；已发送操作不会自动回滚。"
		return
	}
	p.generation++
	p.running = false
	p.cancel = nil
	if p.plan != nil {
		p.plan.Close()
		p.plan = nil
	}
	p.status = "已取消；未提交。"
}
func (p *recoveryPanel) Close() {
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
	if p.plan != nil {
		p.plan.Close()
	}
	p.plan = nil
	p.status = ""
}
func (p *recoveryPanel) blocked() bool { return p.closed || p.running || p.terminal }
func (p *recoveryPanel) request() (recoveryFormRequest, error) {
	r := recoveryFormRequest{Action: p.operation, TrustedPublicKey: p.public, ResetPassword: p.resetPassword, ResetTwoFactor: p.resetMFA}
	if p.emergency {
		days, err := strconv.Atoi(p.waitDays)
		if err != nil {
			return r, vaultwarden.ErrValidation
		}
		r.Emergency = vaultwarden.EmergencyRequest{Action: p.operation, Trusted: p.trusted, Email: p.email, Token: p.token, TrustedPublicKey: p.public, Type: p.accessType, WaitTimeDays: days}
		if p.operation == "accept" {
			r.Emergency.ID = p.email
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
func (p *recoveryPanel) preparePlan() {
	if p.blocked() || p.plan != nil || p.prepare == nil || p.dispatch == nil {
		return
	}
	r, err := p.request()
	if err != nil {
		p.status = "请核对对象、必填项及两次新密码。"
		return
	}
	p.running = true
	if p.busy != nil {
		p.busy(true)
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
			if p.busy != nil {
				p.busy(false)
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
				p.status = "核验失败，未创建确认计划。请重新读取状态并检查公钥、权限及策略。"
				return
			}
			p.plan = plan
			p.status = "已核验；请阅读影响后确认。"
		})
	}()
}
func (p *recoveryPanel) commitPlan() {
	if p.blocked() || p.plan == nil || p.commit == nil || p.dispatch == nil {
		return
	}
	plan := p.plan
	p.plan = nil
	p.running = true
	if p.busy != nil {
		p.busy(true)
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
			if p.busy != nil {
				p.busy(false)
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
				p.status = "结果未知或可能部分完成。请核对持久记录及服务器状态，禁止重复提交。"
			case err != nil:
				p.status = "操作未获得确认。请核对记录；重新读取后再开始新的流程。"
			case result.Confirmed && result.RequireTargetLogin:
				p.status = "服务器确认恢复。目标旧会话与 AutoFill 不得继续使用；需要重新登录、完整同步与核验。"
			case result.Confirmed:
				p.status = "服务器已确认，请重新读取最新授权状态。"
			default:
				p.status = "未取得可靠结果，请核对状态。"
			}
		})
	}()
}
func (p *recoveryPanel) View(c *ui.Context) {
	if p.closed {
		return
	}
	title := "组织账号恢复"
	if p.emergency {
		title = "紧急访问"
	}
	ui.Text(c, title).FontSize(22)
	disabled := p.blocked() || p.plan != nil
	if p.emergency {
		if p.trusted {
			ui.Text(c, "我信任的联系人（我授予访问权限）")
		} else {
			ui.Text(c, "授予我访问权限的人")
		}
		ui.Text(c, "等待期仅作展示，必须由服务器批准后才能查看或接管。")
		for i, row := range p.contacts {
			states := []string{"已邀请", "已接受，待确认", "已确认", "等待批准", "已批准"}
			state := "未知状态"
			if row.Status >= 0 && row.Status < len(states) {
				state = states[row.Status]
			}
			kind := "只读查看"
			if row.Type == 1 {
				kind = "接管账号"
			}
			label := fmt.Sprintf("%s · %s · %s · %s · 等待 %d 天", row.Name, row.Email, state, kind, row.WaitTimeDays)
			if kit.Action(c, label, "", p.selected == i, disabled).Key("emergency-contact-" + row.ID).Clicked() {
				p.selected = i
			}
		}
		options := []struct{ action, label string }{{"invite", "邀请联系人"}, {"accept", "接受邮件邀请"}, {"reinvite", "重新发送邀请"}, {"confirm", "确认并分发密钥"}, {"initiate", "请求访问"}, {"approve", "批准请求"}, {"reject", "拒绝或撤回批准"}, {"update", "更改类型与等待期"}, {"delete", "移除授权"}, {"takeover", "接管并重置密码"}}
		for _, o := range options {
			allowed := o.action == "invite" || o.action == "accept"
			if p.selected >= 0 && p.selected < len(p.contacts) {
				a := o.action
				if a == "takeover" {
					a = "password"
				}
				allowed = allowed || vaultwarden.EmergencyActionAllowed(p.contacts[p.selected], p.trusted, a)
			}
			if kit.Action(c, o.label, "", p.operation == o.action, disabled || !allowed).Key("emergency-action-" + o.action).Clicked() {
				p.operation = o.action
				p.clearSecrets()
			}
		}
		if p.operation == "invite" {
			ui.TextInput(c, &p.email).Label("联系人邮箱").Disabled(disabled)
		}
		if p.operation == "accept" {
			ui.TextInput(c, &p.email).Label("邮件中的紧急访问 ID").Disabled(disabled)
			ui.TextInput(c, &p.token).Label("邮件令牌").Password().Disabled(disabled)
		}
		if p.operation == "invite" || p.operation == "update" {
			for i, label := range []string{"只读查看", "接管账号（重置密码和 MFA）"} {
				if kit.Action(c, label, "", p.accessType == i, disabled).Key(fmt.Sprintf("emergency-type-%d", i)).Clicked() {
					p.accessType = i
				}
			}
			ui.TextInput(c, &p.waitDays).Label("等待天数（0–365）").Disabled(disabled)
		}
	} else {
		for i, m := range p.members {
			if kit.Action(c, m.Label, "", p.selected == i, disabled).Key("recovery-member-" + m.OrganizationID + "-" + m.MemberID).Clicked() {
				p.selected = i
			}
		}
		for _, o := range []struct{ action, label string }{{"enroll", "登记自身账号恢复"}, {"withdraw", "退出自身账号恢复"}, {"administrator", "管理员恢复成员"}} {
			if kit.Action(c, o.label, "", p.operation == o.action, disabled).Key("recovery-action-" + o.action).Clicked() {
				p.operation = o.action
				p.clearSecrets()
			}
		}
		if p.operation == "enroll" {
			ui.TextInput(c, &p.password).Label("当前主密码").Password().Disabled(disabled)
			ui.TextInput(c, &p.otp).Label("或受保护操作邮件 OTP（二选一）").Password().Disabled(disabled)
		}
		if p.operation == "administrator" {
			if kit.Action(c, "重置主密码", "", p.resetPassword, disabled).Key("recovery-reset-password").Clicked() {
				p.resetPassword = !p.resetPassword
			}
			if kit.Action(c, "重置 MFA", "", p.resetMFA, disabled).Key("recovery-reset-mfa").Clicked() {
				p.resetMFA = !p.resetMFA
			}
		}
	}
	if p.operation == "confirm" || p.operation == "enroll" || p.operation == "administrator" {
		ui.TextInput(c, &p.public).Label("独立可信渠道核验的完整 SPKI 公钥").Disabled(disabled)
	}
	if p.operation == "takeover" || (p.operation == "administrator" && p.resetPassword) {
		ui.TextInput(c, &p.newPassword).Label("目标账号新主密码（至少12字符）").Password().Disabled(disabled)
		ui.TextInput(c, &p.repeatPassword).Label("再次输入新主密码").Password().Disabled(disabled)
	}
	if p.plan != nil {
		summary := p.plan.Summary()
		ui.Text(c, "已核验目标："+summary.TargetEmail+" · "+summary.Target.Account)
		if summary.OrganizationID != "" {
			ui.Text(c, "组织："+summary.OrganizationID+" · 成员："+summary.MembershipID)
		}
		if summary.CounterpartyEmail != "" {
			kind := "只读查看"
			if summary.EmergencyType == 1 {
				kind = "接管账号"
			}
			ui.Text(c, fmt.Sprintf("联系人：%s · %s · 等待 %d 天", summary.CounterpartyEmail, kind, summary.WaitTimeDays))
		}
		ui.Text(c, p.plan.Impact())
		if kit.Action(c, "我已核对对象并授权执行", "", true, p.blocked()).Key("recovery-confirm").Clicked() {
			p.commitPlan()
		}
		if kit.Action(c, "取消此计划", "", false, p.blocked()).Key("recovery-discard").Clicked() {
			p.plan.Close()
			p.plan = nil
			p.status = "已取消；未提交。"
		}
	} else if kit.Action(c, "读取核验并准备确认", "", true, p.blocked()).Key("recovery-prepare").Clicked() {
		p.preparePlan()
	}
	if p.running && kit.Action(c, "取消并核对结果", "", false, false).Key("recovery-cancel").Clicked() {
		p.cancelOperation()
	}
	if p.status != "" {
		ui.Text(c, p.status)
	}
}
