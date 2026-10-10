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
	v.status = i18n.T("已取消查看。")
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
				v.status = i18n.T("查看失败，请重新读取授权状态。")
				return
			}
			v.rows = rows
			v.status = i18n.T("仅本次只读查看；离开或锁定即清除。")
		})
	}()
}
func emergencyDisplayFields(fields map[string]any) []string {
	labels := map[string]string{"username": i18n.T("用户名"), "password": i18n.T("密码"), "totp": i18n.T("验证码密钥"), "uri": i18n.T("网址"), "cardholderName": i18n.T("持卡人"), "brand": i18n.T("卡种"), "number": i18n.T("卡号"), "expMonth": i18n.T("到期月"), "expYear": i18n.T("到期年"), "code": i18n.T("安全码"), "title": i18n.T("称谓"), "firstName": i18n.T("名"), "middleName": i18n.T("中间名"), "lastName": i18n.T("姓"), "address1": i18n.T("地址"), "address2": i18n.T("地址补充"), "address3": i18n.T("地址补充"), "city": i18n.T("城市"), "state": i18n.T("省份"), "postalCode": i18n.T("邮编"), "country": i18n.T("国家"), "company": i18n.T("公司"), "email": i18n.T("邮箱"), "phone": i18n.T("电话"), "ssn": i18n.T("社会保障号码"), "passportNumber": i18n.T("护照号"), "licenseNumber": i18n.T("证件号"), "privateKey": i18n.T("私钥"), "publicKey": i18n.T("公钥"), "keyFingerprint": i18n.T("指纹"), "bankName": i18n.T("银行"), "nameOnAccount": i18n.T("户名"), "accountType": i18n.T("账户类型"), "accountNumber": i18n.T("账号"), "routingNumber": i18n.T("路由号码"), "branchNumber": i18n.T("支行号码"), "pin": "PIN", "swiftCode": "SWIFT", "iban": "IBAN", "bankContactPhone": i18n.T("银行电话"), "dateOfBirth": i18n.T("出生日期"), "issuingCountry": i18n.T("签发国家"), "issuingState": i18n.T("签发地区"), "issueDate": i18n.T("签发日期"), "expirationDate": i18n.T("到期日期"), "issuingAuthority": i18n.T("签发机关"), "licenseClass": i18n.T("证件类别"), "surname": i18n.T("姓"), "givenName": i18n.T("名"), "sex": i18n.T("性别"), "birthPlace": i18n.T("出生地"), "nationality": i18n.T("国籍"), "passportType": i18n.T("护照类别"), "nationalIdentificationNumber": i18n.T("身份号码")}
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
						lines = append(lines, i18n.Tf("网址：%s", fmt.Sprint(uri["uri"])))
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
	ui.Text(c, i18n.T("紧急访问 · 只读查看")).FontSize(22)
	ui.Text(c, v.contact.Name+" · "+v.contact.Email)
	ui.Text(c, i18n.T("必须已获服务器批准。此处不会导入个人库或启用 AutoFill。"))
	if kit.Action(c, i18n.T("我确认查看此人的个人密码库"), "", true, v.running || v.terminal || !vaultwarden.EmergencyActionAllowed(v.contact, false, "view")).Key("emergency-view-consent").Clicked() {
		v.load()
	}
	for i, row := range v.rows {
		if kit.Action(c, row.Name, "", v.selected == i, false).Key("emergency-view-item-" + row.ID).Clicked() {
			v.selected = i
			v.revealed = false
		}
	}
	if v.selected >= 0 && v.selected < len(v.rows) {
		if kit.Action(c, i18n.T("显示或隐藏此条目的敏感内容"), "", v.revealed, false).Key("emergency-view-reveal").Clicked() {
			v.revealed = !v.revealed
		}
		if v.revealed {
			row := v.rows[v.selected]
			if row.Notes != nil {
				ui.Text(c, i18n.Tf("备注：%s", *row.Notes))
			}
			for _, section := range []struct {
				title  string
				fields map[string]any
			}{{i18n.T("登录"), row.Login}, {i18n.T("银行卡"), row.Card}, {i18n.T("身份"), row.Identity}, {i18n.T("SSH 密钥"), row.SSHKey}, {i18n.T("银行账户"), row.BankAccount}, {i18n.T("驾驶证"), row.DriversLicense}, {i18n.T("护照"), row.Passport}} {
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
	if v.running && kit.Action(c, i18n.T("取消查看"), "", false, false).Key("emergency-view-cancel").Clicked() {
		v.cancelLoad()
	}
	if v.status != "" {
		ui.Text(c, v.status)
	}
}
