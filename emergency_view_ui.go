// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// emergencyViewer is deliberately independent from the normal vault/editor and
// offline/AutoFill stores. fetch must call WithEmergencyView with explicit
// consent; the host checks scope/epoch and dispatches completion on the UI thread.
type emergencyViewer struct {
	contact                             vaultwarden.EmergencyContact
	running, closed, terminal, revealed bool
	generation                          uint64
	selected                            int
	rows                                []vaultwarden.CipherFields
	status                              string
	cancel                              context.CancelFunc
	fetch                               func(context.Context, string) ([]vaultwarden.CipherFields, error)
	dispatch                            func(func())
}

func newEmergencyViewer(contact vaultwarden.EmergencyContact, fetch func(context.Context, string) ([]vaultwarden.CipherFields, error), dispatch func(func())) *emergencyViewer {
	return &emergencyViewer{contact: contact, selected: -1, fetch: fetch, dispatch: dispatch}
}
func (v *emergencyViewer) Close() {
	if v.cancel != nil {
		v.cancel()
	}
	v.generation++
	v.closed = true
	clear(v.rows)
	v.rows = nil
	v.revealed = false
	v.status = ""
}
func (v *emergencyViewer) load() {
	if v.closed || v.running || v.terminal || v.fetch == nil || v.dispatch == nil || !vaultwarden.EmergencyActionAllowed(v.contact, false, "view") {
		return
	}
	v.running = true
	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	generation := v.generation
	fetch, dispatch, id := v.fetch, v.dispatch, v.contact.ID
	go func() {
		rows, err := fetch(ctx, id)
		cancel()
		dispatch(func() {
			if v.closed || v.generation != generation {
				clear(rows)
				return
			}
			v.running = false
			v.terminal = true
			v.cancel = nil
			if err != nil {
				clear(rows)
				v.status = "查看失败，请重新读取授权状态。"
				return
			}
			v.rows = rows
			v.status = "仅本次只读查看；离开或锁定即清除。"
		})
	}()
}
func emergencyDisplayFields(fields map[string]any) []string {
	labels := map[string]string{"username": "用户名", "password": "密码", "totp": "验证码密钥", "uri": "网址", "cardholderName": "持卡人", "brand": "卡种", "number": "卡号", "expMonth": "到期月", "expYear": "到期年", "code": "安全码", "title": "称谓", "firstName": "名", "middleName": "中间名", "lastName": "姓", "address1": "地址", "address2": "地址补充", "address3": "地址补充", "city": "城市", "state": "省份", "postalCode": "邮编", "country": "国家", "company": "公司", "email": "邮箱", "phone": "电话", "ssn": "社会保障号码", "passportNumber": "护照号", "licenseNumber": "证件号", "privateKey": "私钥", "publicKey": "公钥", "keyFingerprint": "指纹", "bankName": "银行", "nameOnAccount": "户名", "accountType": "账户类型", "accountNumber": "账号", "routingNumber": "路由号码", "branchNumber": "支行号码", "pin": "PIN", "swiftCode": "SWIFT", "iban": "IBAN", "bankContactPhone": "银行电话", "dateOfBirth": "出生日期", "issuingCountry": "签发国家", "issuingState": "签发地区", "issueDate": "签发日期", "expirationDate": "到期日期", "issuingAuthority": "签发机关", "licenseClass": "证件类别", "surname": "姓", "givenName": "名", "sex": "性别", "birthPlace": "出生地", "nationality": "国籍", "passportType": "护照类别", "nationalIdentificationNumber": "身份号码"}
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
						lines = append(lines, "网址："+fmt.Sprint(uri["uri"]))
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

func (v *emergencyViewer) View(c *ui.Context) {
	if v.closed {
		return
	}
	ui.Text(c, "紧急访问 · 只读查看").FontSize(22)
	ui.Text(c, v.contact.Name+" · "+v.contact.Email)
	ui.Text(c, "必须已获服务器批准。此处不会导入个人库或启用 AutoFill。")
	if action(c, "我确认查看此人的个人密码库", "", true, v.running || v.terminal || !vaultwarden.EmergencyActionAllowed(v.contact, false, "view")).Key("emergency-view-consent").Clicked() {
		v.load()
	}
	for i, row := range v.rows {
		if action(c, row.Name, "", v.selected == i, false).Key("emergency-view-item-" + row.ID).Clicked() {
			v.selected = i
			v.revealed = false
		}
	}
	if v.selected >= 0 && v.selected < len(v.rows) {
		if action(c, "显示或隐藏此条目的敏感内容", "", v.revealed, false).Key("emergency-view-reveal").Clicked() {
			v.revealed = !v.revealed
		}
		if v.revealed {
			row := v.rows[v.selected]
			if row.Notes != nil {
				ui.Text(c, "备注："+*row.Notes)
			}
			for _, section := range []struct {
				title  string
				fields map[string]any
			}{{"登录", row.Login}, {"银行卡", row.Card}, {"身份", row.Identity}, {"SSH 密钥", row.SSHKey}, {"银行账户", row.BankAccount}, {"驾驶证", row.DriversLicense}, {"护照", row.Passport}} {
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
	if v.running && action(c, "取消查看", "", false, false).Key("emergency-view-cancel").Clicked() {
		v.cancel()
	}
	if v.status != "" {
		ui.Text(c, v.status)
	}
}
