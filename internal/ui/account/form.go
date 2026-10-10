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
	f.Status = i18n.T("已取消；尚未派发的操作不会提交")
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
		f.Status = i18n.T("准备失败，请核对身份、密码、策略及同步状态")
		return false
	}
	if plan == nil {
		f.Status = i18n.T("准备失败")
		return false
	}
	f.plan = plan
	f.confirming = true
	f.Status = i18n.T("核对影响后再次确认")
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
			f.Status = i18n.T("服务器已确认。请重新登录并同步；恢复记录在核验完成前保留")
		} else {
			f.Status = i18n.T("结果未知，可能已部分执行。恢复材料已保留，请核验服务器；不要重试")
		}
		return true
	}
	if err != nil {
		var uncertain *vaultwarden.MutationUncertainError
		if errors.As(err, &uncertain) {
			f.uncertain = true
			f.Status = i18n.T("结果未知，请先核验服务器状态，不要重复提交")
			return true
		}
		f.Status = i18n.T("操作未提交，请重新准备")
	} else {
		f.Status = i18n.T("已完成")
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
		f.Status = i18n.T("请求失败或结果未知，请检查邮箱后再继续")
		return true
	}
	if r.EmailSent {
		f.Status = i18n.Key("验证邮件已请求发送，请输入邮件中的注册令牌")
	} else {
		f.token = r.Token
		f.Status = i18n.T("服务器已返回注册验证令牌，可以完成注册")
	}
	return true
}
func (f *Form) dispatch(operation string) {
	if f.closed || f.busy || f.uncertain || f.Submit == nil {
		return
	}
	if (operation == "prepare-delete" || operation == "prepare-rotate-user-key") && !f.legacyRecoveryReviewed {
		f.Status = i18n.T("请先处理未决旧附件共享恢复文件，并确认其依赖当前user key的限制。")
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
			f.Status = i18n.T("KDF 类型无效")
			return
		}
		kdf.Iterations, err = strconv.Atoi(f.iterations)
		if err != nil {
			f.Status = i18n.T("KDF 迭代数无效")
			return
		}
		if kdf.Type == 1 {
			kdf.Memory, err = strconv.Atoi(f.memory)
			if err != nil {
				f.Status = i18n.T("KDF 内存无效")
				return
			}
			kdf.Parallelism, err = strconv.Atoi(f.parallelism)
			if err != nil {
				f.Status = i18n.T("KDF 并行度无效")
				return
			}
		}
	}
	if operation == "prepare-password" || operation == "register-finish" {
		password := f.newPassword
		if password != f.repeatPassword {
			f.Status = i18n.T("两次主密码不一致")
			return
		}
		if err := f.policy.Check(context.Background(), []byte(password), f.Email, false); err != nil {
			f.Status = i18n.T("主密码不符合组织策略")
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
		f.Status = i18n.T("无法评估主密码")
		return
	}
	f.score = r.Score
}
func FormView(c *ui.Context, f *Form) {
	if f == nil || f.closed {
		return
	}
	ui.Text(c, i18n.T("账号与安全")).FontSize(20)
	disabled := f.busy || f.uncertain
	if f.confirming {
		if f.confirmAction != "" {
			ui.Text(c, i18n.T("个人 API key 是敏感凭据；轮换会使旧 key 失效。请确认后继续。")).MaxLines(4)
		} else {
			ui.Text(c, accountImpact(f.plan.Kind())).MaxLines(6)
		}
		ui.Text(c, i18n.T("提交前必须安全保存恢复材料并暂停旧离线访问。服务器可能部分执行；提交后不能取消远端结果。")).MaxLines(4)
		if ui.Button(c, i18n.T("确认执行")).Disabled(disabled).Clicked() {
			if f.confirmAction != "" {
				f.dispatch(f.confirmAction)
			} else {
				f.dispatch("commit")
			}
		}
		if ui.Button(c, i18n.T("取消")).Disabled(f.busy).Clicked() {
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
			ui.TextInput(c, &f.name).Label(i18n.T("显示名称（最多 50 字节）")).Disabled(disabled)
			ui.TextInput(c, &f.avatar).Label(i18n.T("头像颜色 #RRGGBB")).Disabled(disabled)
			if ui.Button(c, i18n.T("保存资料")).Disabled(disabled).Clicked() {
				f.dispatch("profile")
			}
			if ui.Button(c, i18n.T("保存头像")).Disabled(disabled).Clicked() {
				f.dispatch("avatar")
			}
			if ui.Button(c, i18n.T("请求验证邮箱")).Disabled(disabled).Clicked() {
				f.dispatch("verify-email")
			}
			ui.TextInput(c, &f.token).Label(i18n.T("验证邮件令牌")).Password().Disabled(disabled)
			if ui.Button(c, i18n.T("确认邮件验证令牌")).Disabled(disabled || f.token == "").Clicked() {
				f.dispatch("verify-email-token")
			}
		case "register":
			ui.TextInput(c, &f.Email).Label(i18n.T("注册邮箱")).Disabled(disabled)
			ui.TextInput(c, &f.name).Label(i18n.T("显示名称")).Disabled(disabled)
			if ui.Button(c, i18n.T("发送主密码提示")).Disabled(disabled || f.Email == "").Clicked() {
				f.dispatch("password-hint")
			}
			if ui.Button(c, i18n.T("发送注册验证邮件")).Disabled(disabled).Clicked() {
				f.dispatch("register-send")
			}
			ui.TextInput(c, &f.token).Label(i18n.T("注册验证令牌")).Password().Disabled(disabled)
			accountNewPasswordView(c, f, disabled)
			accountKDFView(c, f, disabled)
			if ui.Button(c, i18n.T("完成注册")).Disabled(disabled || f.token == "").Clicked() {
				f.dispatch("register-finish")
			}
		default:
			ui.TextInput(c, &f.password).Label(i18n.T("当前主密码")).Password().Disabled(disabled)
			switch f.Mode {
			case "password":
				accountNewPasswordView(c, f, disabled)
			case "email":
				ui.TextInput(c, &f.Email).Label(i18n.T("新邮箱")).Disabled(disabled)
				if ui.Button(c, i18n.T("请求邮箱变更验证码")).Disabled(disabled).Clicked() {
					f.dispatch("email-token")
				}
				ui.TextInput(c, &f.token).Label(i18n.T("邮箱验证码")).Password().Disabled(disabled)
			case "kdf":
				accountKDFView(c, f, disabled)
			case "rotate-user-key":
				if ui.Button(c, i18n.T("读取轮换收件人与组织恢复登记")).Disabled(disabled).Clicked() {
					f.dispatch("rotation-recipients")
				}
				ui.Text(c, i18n.T("从可信独立渠道取得下列完整SPKI公钥；不把本次服务器返回值直接当成信任依据。")).MaxLines(4)
				for _, recipient := range f.RotationRequirements.Users {
					value := f.rotationTrust.Users[recipient.ID]
					ui.TextInput(c, &value).Label(i18n.Tf("受托人 %s · %s 的可信公钥", recipient.Email, recipient.ID)).Disabled(disabled)
					f.rotationTrust.Users[recipient.ID] = value
				}
				for _, recipient := range f.RotationRequirements.Organizations {
					value := f.rotationTrust.Organizations[recipient.ID]
					ui.TextInput(c, &value).Label(i18n.Tf("组织 %s · %s 的可信公钥", recipient.Name, recipient.ID)).Disabled(disabled)
					f.rotationTrust.Organizations[recipient.ID] = value
				}
			case "api-key", "security-stamp", "purge", "delete":
				ui.TextInput(c, &f.otp).Label(i18n.T("或受保护操作邮件 OTP（与主密码二选一）")).Password().Disabled(disabled)
			}
			if f.Mode == "rotate-user-key" || f.Mode == "delete" {
				ui.Text(c, i18n.T(".mygoshare-recovery 文件只依赖当时user key，不能仅用旧主密码独立解锁。请先通过导入导出的共享恢复入口处理所有未决迁移；轮换或删除后旧文件可能无法恢复。")).MaxLines(6)
				label := i18n.T("确认已处理未决共享恢复文件")
				if f.legacyRecoveryReviewed {
					label = i18n.T("已确认旧恢复文件限制（点击撤回）")
				}
				if ui.Button(c, label).Disabled(disabled).Clicked() {
					f.legacyRecoveryReviewed = !f.legacyRecoveryReviewed
				}
			}
			ui.Text(c, accountImpact(vaultwarden.AccountChangeKind(f.Mode))).MaxLines(5)
			if f.Mode == "api-key" {
				if ui.Button(c, i18n.T("查看 API key")).Disabled(disabled).Clicked() {
					f.confirmAction = "api-key"
					f.confirming = true
				}
				if ui.Button(c, i18n.T("轮换 API key")).Disabled(disabled).Clicked() {
					f.confirmAction = "rotate-api-key"
					f.confirming = true
				}
			} else if ui.Button(c, i18n.T("继续并核对影响")).Disabled(disabled).Clicked() {
				f.dispatch("prepare-" + f.Mode)
			}
		}
		if ui.Button(c, i18n.T("取消并清除敏感输入")).Disabled(f.busy).Clicked() {
			f.cancel()
		}
	}
	if f.apiKey != "" {
		field := ui.TextInput(c, &f.apiKey).Label(i18n.T("个人 API key（离开或取消后清除）")).Disabled(true)
		if !f.apiKeyVisible {
			field.Password()
		}
		label := i18n.T("显示 API key")
		if f.apiKeyVisible {
			label = i18n.T("隐藏 API key")
		}
		if ui.Button(c, label).Clicked() {
			f.apiKeyVisible = !f.apiKeyVisible
		}
	}
	for _, preparation := range f.RotationPreparations {
		ui.Text(c, i18n.Tf("需迁移条目 %s / 附件 %s", preparation.CipherID, preparation.AttachmentID)).MaxLines(3)
		if preparation.Deleted {
			ui.Text(c, i18n.T("此项在回收站：只有明确恢复并重新同步后才能升级旧附件；不会自动恢复或删除。")).MaxLines(4)
		}
		if f.OpenRotationPreparation != nil && ui.Button(c.Key(preparation.CipherID+"/"+preparation.AttachmentID), i18n.T("打开对应条目进行明确迁移")).Disabled(f.busy).Clicked() {
			f.OpenRotationPreparation(preparation.CipherID, preparation.Deleted)
		}
	}
	ui.Text(c, i18n.T(f.Status)).MaxLines(5)
}
func accountNewPasswordView(c *ui.Context, f *Form, disabled bool) {
	ui.TextInput(c, &f.newPassword).Label(i18n.T("新主密码（至少 12 字符）")).Password().Disabled(disabled)
	ui.TextInput(c, &f.repeatPassword).Label(i18n.T("再次输入新主密码")).Password().Disabled(disabled)
	ui.TextInput(c, &f.hint).Label(i18n.T("主密码提示（不要填写密码本身）")).Disabled(disabled)
	if ui.Button(c, i18n.T("评估密码强度")).Disabled(disabled).Clicked() {
		f.evaluate()
	}
	if f.score >= 0 {
		ui.Text(c, i18n.Tf("密码强度 %d/4", f.score))
	}
	ui.Text(c, i18n.Tf("组织策略：最低评分 %d，最短 %d；大小写、数字和符号要求在提交前验证。服务器将重新返回当前适用策略。", f.policy.MinComplexity, f.policy.MinLength)).MaxLines(4)
}
func accountKDFView(c *ui.Context, f *Form, disabled bool) {
	ui.TextInput(c, &f.kdfType).Label("KDF：0 PBKDF2 / 1 Argon2id").Disabled(disabled)
	ui.TextInput(c, &f.iterations).Label(i18n.T("迭代次数")).Disabled(disabled)
	if f.kdfType == "1" {
		ui.TextInput(c, &f.memory).Label(i18n.T("内存 MiB（16–256）")).Disabled(disabled)
		ui.TextInput(c, &f.parallelism).Label(i18n.T("并行度（1–16）")).Disabled(disabled)
	}
}
func accountModeLabel(mode string) string {
	switch mode {
	case "register":
		return i18n.T("注册账号")
	case "profile":
		return i18n.T("账号资料")
	case "password":
		return i18n.T("更改主密码")
	case "email":
		return i18n.T("更改邮箱")
	case "kdf":
		return i18n.T("更改 KDF")
	case "api-key":
		return i18n.T("个人 API key")
	case "security-stamp":
		return i18n.T("注销所有会话")
	case "purge":
		return i18n.T("清空个人密码库")
	case "delete":
		return i18n.T("删除账号")
	case "rotate-user-key":
		return i18n.T("轮换用户密钥")
	}
	return i18n.T("账号操作")
}
func accountImpact(kind vaultwarden.AccountChangeKind) string {
	switch kind {
	case vaultwarden.AccountDelete:
		return i18n.T("删除账号将删除个人数据，无法撤销。请先确认备份与组织所有权。")
	case vaultwarden.AccountPurge:
		return i18n.T("清空全部个人密码库，包括非回收站条目及文件夹；无法撤销。")
	case vaultwarden.AccountRotateKey:
		return i18n.T("必须转换全部个人条目、文件夹、Send、紧急访问与组织恢复包装。缺少任何转换器都不能提交；中断可能导致部分数据使用新密钥。")
	case vaultwarden.AccountSecurityStamp:
		return i18n.T("重置安全戳将注销现有会话，随后必须重新登录。")
	default:
		return i18n.T("凭据变更会使旧会话失效。新登录、完整同步和安全存储核验完成前保留旧恢复材料。")
	}
}
