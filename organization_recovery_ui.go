// SPDX-License-Identifier: GPL-3.0-only
package main

import "github.com/egoist/mygo/ui"

func (a *app) organizationRecoveryKeyView(c *ui.Context, e *organizationEditor, disabled bool) {
	ui.Text(c, "账号恢复公钥").FontSize(18)
	ui.Text(c, "所有者可将完整公钥通过独立可信渠道交给受邀人核验。初始化只为此组织建立恢复密钥，不会替任何成员加入账号恢复。").MaxLines(4)
	if action(c, "查看组织恢复公钥", "", false, disabled).Key("organization-recovery-key-load").Clicked() {
		a.runOrganizationManagement("recovery-key-load")
	}
	if e.organizationRecoveryKey != "" {
		ui.TextInput(c, &e.organizationRecoveryKey).Label("组织恢复公钥（完整 DER/SPKI，可选择复制）").Disabled(disabled)
	} else {
		if e.confirmation != "recovery-key-create" {
			if action(c, "初始化缺失的恢复密钥", "", false, disabled).Key("organization-recovery-key-create").Clicked() {
				e.confirmation = "recovery-key-create"
			}
		} else {
			ui.Text(c, "将生成仅此组织使用的 RSA 密钥。私钥由组织密钥加密后上传；已有密钥不会被替换。成员加入恢复后，组织管理员可恢复该成员账号并访问其个人密码库。").MaxLines(6)
			if action(c, "确认初始化恢复密钥", "", true, disabled).Key("organization-recovery-key-confirm").Clicked() {
				a.runOrganizationManagement("recovery-key-create")
			}
			if action(c, "取消初始化", "", false, disabled).Clicked() {
				e.confirmation = ""
			}
		}
	}
}
