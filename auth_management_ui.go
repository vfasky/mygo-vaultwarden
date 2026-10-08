// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type authManagementRequest struct {
	Scope           vaultwarden.Scope
	Epoch, Sequence uint64
	Operation       vaultwarden.MFAManageOperation
	Input           vaultwarden.AccountSensitiveInput
	Fields          map[string]json.RawMessage
	Confirmed       bool
	Context         context.Context
}

func (r *authManagementRequest) Close() {
	clear(r.Input.Password)
	r.Input.Password = nil
	r.Input.OTP = ""
	for _, v := range r.Fields {
		clear(v)
	}
	clear(r.Fields)
}

type authManagementForm struct {
	scope                                       vaultwarden.Scope
	epoch, sequence                             uint64
	operation                                   vaultwarden.MFAManageOperation
	password, otp, status, result               string
	values                                      map[string]string
	busy, closed, confirming, uncertain, reveal bool
	cancel                                      context.CancelFunc
	submit                                      func(authManagementRequest)
}

func newAuthManagementForm(scope vaultwarden.Scope, epoch uint64, submit func(authManagementRequest)) *authManagementForm {
	return &authManagementForm{scope: scope, epoch: epoch, operation: vaultwarden.MFAList, values: map[string]string{}, submit: submit}
}
func (f *authManagementForm) clear() {
	f.password = ""
	f.otp = ""
	clear(f.values)
	f.result = ""
	f.reveal = false
}
func (f *authManagementForm) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	f.clear()
	f.closed = true
	f.sequence++
	f.busy = false
}
func (f *authManagementForm) dispatch() {
	if f.closed || f.busy || (f.uncertain && f.operation != vaultwarden.MFAList) || f.submit == nil {
		return
	}
	sensitive := f.operation != "list" && f.operation != "request-otp" && f.operation != "verify-otp"
	if sensitive && !f.confirming {
		f.confirming = true
		f.status = "确认读取认证秘密或更改双重验证设置。关闭最后一种方式将降低账号保护；请先保管恢复码。"
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
	request := authManagementRequest{Scope: f.scope, Epoch: f.epoch, Sequence: f.sequence, Operation: f.operation, Input: vaultwarden.AccountSensitiveInput{Password: []byte(f.password), OTP: f.otp}, Fields: fields, Confirmed: f.confirming, Context: ctx}
	f.clear()
	f.confirming = false
	f.submit(request)
}
func (f *authManagementForm) complete(scope vaultwarden.Scope, epoch, sequence uint64, result string, err error) bool {
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
		f.status = "操作失败或结果未知。请重新读取服务器设置核验，避免重复启停或注册。"
	} else {
		f.uncertain = false
		f.result = result
		f.status = "服务器已返回结果；认证秘密默认隐藏。"
	}
	return true
}

var authManagementOperations = []struct {
	op     vaultwarden.MFAManageOperation
	label  string
	fields []string
}{
	{"list", "读取双重验证列表", nil}, {"get-authenticator", "准备验证器", nil}, {"authenticator", "启用验证器", []string{"key", "token"}},
	{"get-email", "读取邮件验证设置", nil}, {"send-email", "发送邮件设置验证码", []string{"email"}}, {"email", "启用邮件验证", []string{"email", "token"}},
	{"get-duo", "读取 Duo 设置", nil}, {"duo", "保存 Duo 设置", []string{"host", "clientId", "clientSecret"}},
	{"get-yubikey", "读取 YubiKey 设置", nil}, {"yubikey", "保存 YubiKey OTP", []string{"key1", "key2", "key3", "key4", "key5"}},
	{"get-webauthn", "读取安全密钥列表", nil}, {"get-webauthn-challenge", "注册平台安全密钥", []string{"id", "name"}}, {"delete-webauthn", "删除安全密钥", []string{"id"}},
	{"get-recover", "查看恢复码", nil}, {"disable", "关闭一种双重验证", []string{"type"}}, {"request-otp", "发送敏感操作邮件 OTP", nil}, {"verify-otp", "一次性核验敏感 OTP", []string{"otp"}},
}

func authManagementView(c *ui.Context, f *authManagementForm) {
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
	ui.TextInput(c, &f.password).Label("主密码（仅在本机生成验证证明）").Password().Disabled(f.busy)
	ui.TextInput(c, &f.otp).Label("或敏感操作邮件 OTP；与主密码二选一").Password().Disabled(f.busy)
	labels := map[string]string{"name": "安全密钥名称", "key": "验证器密钥", "token": "验证码", "email": "接收邮箱", "host": "Duo 主机", "clientId": "Duo 客户端 ID", "clientSecret": "Duo 客户端秘密", "id": "安全密钥编号（1–5）", "type": "验证方式编号（0/1/2/3/7）"}
	for _, entry := range authManagementOperations {
		if entry.op != f.operation {
			continue
		}
		for _, field := range entry.fields {
			value := f.values[field]
			label := labels[field]
			if label == "" {
				label = "OTP / YubiKey 槽位 " + field
			}
			ui.TextInput(c, &value).Label(label).Password().Disabled(f.busy)
			f.values[field] = value
		}
	}
	label := "继续"
	if f.confirming {
		label = "确认操作"
	}
	if ui.Button(c, label).Disabled(f.busy || (f.uncertain && f.operation != vaultwarden.MFAList)).Clicked() {
		f.dispatch()
	}
	if f.result != "" {
		if ui.Button(c, "显示 / 隐藏认证结果").Clicked() {
			f.reveal = !f.reveal
		}
		field := ui.TextInput(c, &f.result).Label("认证结果").Disabled(true)
		if !f.reveal {
			field.Password()
		}
	}
	if ui.Button(c, "取消并清除认证信息").Clicked() {
		f.Close()
	}
	ui.Text(c, f.status).MaxLines(5)
}
