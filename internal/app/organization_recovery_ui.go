// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) organizationRecoveryKeyView(c *ui.Context, e *organizationEditor, disabled bool) {
	ui.Text(c, i18n.T("账号恢复公钥")).FontSize(18)
	ui.Text(c, i18n.T("所有者可将完整公钥通过独立可信渠道交给受邀人核验。初始化只为此组织建立恢复密钥，不会替任何成员加入账号恢复。")).MaxLines(4)
	if kit.Action(c, i18n.T("查看组织恢复公钥"), "", false, disabled).Key("organization-recovery-key-load").Clicked() {
		a.runOrganizationManagement("recovery-key-load")
	}
	if e.organizationRecoveryKey != "" {
		ui.TextInput(c, &e.organizationRecoveryKey).Label(i18n.T("组织恢复公钥（完整 DER/SPKI，可选择复制）")).Disabled(disabled)
	} else {
		if e.confirmation != "recovery-key-create" {
			if kit.Action(c, i18n.T("初始化缺失的恢复密钥"), "", false, disabled).Key("organization-recovery-key-create").Clicked() {
				e.confirmation = "recovery-key-create"
			}
		} else {
			ui.Text(c, i18n.T("将生成仅此组织使用的 RSA 密钥。私钥由组织密钥加密后上传；已有密钥不会被替换。成员加入恢复后，组织管理员可恢复该成员账号并访问其个人密码库。")).MaxLines(6)
			if kit.Action(c, i18n.T("确认初始化恢复密钥"), "", true, disabled).Key("organization-recovery-key-confirm").Clicked() {
				a.runOrganizationManagement("recovery-key-create")
			}
			if kit.Action(c, i18n.T("取消初始化"), "", false, disabled).Clicked() {
				e.confirmation = ""
			}
		}
	}
}
