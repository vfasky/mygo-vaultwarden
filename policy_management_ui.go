// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strconv"
)

func policyManagementOperation(op string) bool {
	return op == "policy-list" || op == "policy-load" || op == "policy-save" || op == "policy-review" || op == "policy-restore"
}

// adoptPolicyRecoveryPreview is the UI-thread half of the two-stage recovery.
// It installs the authenticated publish receipt before binding its network proof;
// neither an unadopted preview nor a late editor may authorize the next sync.
func (a *app) adoptPolicyRecoveryPreview(epoch uint64, e *organizationEditor, state *snapshotStatus, vault *vaultwarden.VaultData, review *vaultwarden.PolicyRecoveryReview) bool {
	if a.epoch != epoch || e == nil || a.organizationEditor != e || review == nil || review.Record().OrganizationID != e.id {
		return false
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return false
	}
	a.organizationEditor = nil // Preserve this form while replacing its snapshot.
	if !a.adoptOrganizationIsolation(state, vault, e.id) {
		a.organizationEditor = e
		return false
	}
	e.revision = a.sessionRevision
	a.organizationEditor = e
	if session.BindPolicyRecoveryReview(review, a.vault, a.sessionRevision) != nil {
		return false
	}
	e.policyRecovery.Close()
	e.policyRecovery = review
	e.confirmation = "policy-restore"
	return true
}

func (a *app) hasPendingPolicy(orgID string) bool {
	if a.vault != nil {
		for _, p := range a.vault.PendingPolicyMutations {
			if p.OrganizationID == orgID {
				return true
			}
		}
	}
	return false
}
func (a *app) pendingPolicyRecoveryView(c *ui.Context, e *organizationEditor, disabled bool) {
	if !a.hasPendingPolicy(e.id) {
		return
	}
	ui.Text(c, "此组织策略修改待核验。受限类型修改期间暂停个人条目读取与填充；个人所有权修改仅暂停个人保存；默认 URI 修改暂停所有继承默认的 URI 填充，明确设置的规则保留。其他组织仍按自身权限访问。普通同步不会解除待核验状态。").MaxLines(5)
	if e.policyRecovery == nil {
		if action(c, "读取服务器当前策略以核验", "sync", false, disabled).Key("policy-review").Clicked() {
			a.runOrganizationManagement("policy-review")
		}
		return
	}
	for _, line := range e.policyRecovery.Summary() {
		ui.Text(c, line).MaxLines(3)
	}
	ui.Text(c, collectionPermissionLabel("当前服务器策略启用", e.policyRecovery.Enabled()))
	ui.Text(c, "请核对以上当前状态。确认将再次连接服务器比对策略和成员身份后恢复本机访问；不会重试原修改，也不会自动恢复已撤销成员。先前未知请求仍可能迟到执行，恢复不能保证消除服务器并发窗口。").MaxLines(6)
	if action(c, "确认当前策略并重新核验访问", "", true, disabled).Key("policy-restore").Clicked() {
		e.confirmation = "policy-restore"
		a.runOrganizationManagement("policy-restore")
	}
	if action(c, "取消策略恢复", "", false, disabled).Clicked() {
		e.policyRecovery.Close()
		e.policyRecovery = nil
		e.confirmation = ""
	}
}
func (a *app) policyManagementView(c *ui.Context, e *organizationEditor, disabled bool) {
	allowed := false
	for _, org := range a.organizations {
		if org.ID == e.id && (org.Type == 0 || org.Type == 1) {
			allowed = true
		}
	}
	if !allowed {
		return
	}
	ui.Text(c, "组织策略").FontSize(18)
	defs := vaultwarden.OrganizationPolicyDefinitions()
	if e.policyDraft == nil {
		if action(c, "加载组织策略", "", false, disabled).Key("policy-list").Clicked() {
			a.runOrganizationManagement("policy-list")
		}
		for _, entry := range e.policies {
			for _, def := range defs {
				if def.Type != entry.Type {
					continue
				}
				if action(c, collectionPermissionLabel(def.Name, entry.Enabled), "", false, disabled).Key("policy-edit-" + strconv.Itoa(entry.Type)).Clicked() {
					e.policyType = entry.Type
					a.runOrganizationManagement("policy-load")
				}
			}
		}
		return
	}
	d := e.policyDraft
	confirming := e.confirmation == "policy-save"
	for _, def := range defs {
		if def.Type == d.Type() {
			ui.Text(c, def.Name).FontSize(17)
			ui.Text(c, def.Consumption).MaxLines(5)
		}
	}
	ui.Text(c, "未编辑字段和未知扩展数据按原值保留。字段选“默认”会明确写入空值；启用状态仅表示服务器配置，实际执行范围见上方说明。").MaxLines(4)
	if action(c, collectionPermissionLabel("启用策略", d.Enabled), "", false, disabled || confirming).Key("policy-enabled").Clicked() {
		d.Enabled = !d.Enabled
	}
	for i := range d.Fields {
		f := &d.Fields[i]
		ui.Text(c, f.Label)
		if f.Kind == "uri" && (f.Value == "2" || f.Value == "4") {
			label := "以此开头"
			if f.Value == "4" {
				label = "正则表达式"
			}
			ui.Text(c, "服务器当前规则："+label+"。未选择新规则时保留原值；固定客户端新表单不提供此选项。").MaxLines(3)
		}
		if f.Kind == "number" {
			ui.TextInput(c, &f.Value).Label("整数 " + strconv.Itoa(f.Min) + "–" + strconv.Itoa(f.Max) + "；空白表示默认").Disabled(disabled || confirming)
			continue
		}
		options := []struct{ value, label string }{{"", "默认"}}
		switch f.Kind {
		case "bool":
			options = append(options, struct{ value, label string }{"true", "是"}, struct{ value, label string }{"false", "否"})
		case "generator":
			options = append(options, struct{ value, label string }{"password", "密码"}, struct{ value, label string }{"passphrase", "密码短语"})
		case "uri":
			for n, label := range []string{"基础域名", "主机", "以此开头", "完全匹配", "正则表达式", "从不匹配"} {
				if n == 2 || n == 4 {
					continue
				}
				options = append(options, struct{ value, label string }{strconv.Itoa(n), label})
			}
		}
		for _, option := range options {
			if action(c, collectionPermissionLabel(option.label, f.Value == option.value), "", false, disabled || confirming).Key("policy-field-" + f.Key + "-" + option.value).Clicked() {
				f.Value = option.value
			}
		}
	}
	if !confirming {
		if action(c, "保存策略", "", true, disabled).Key("policy-save").Clicked() {
			e.policyConsent.Close()
			e.policyConsent = d.Confirm()
			if e.policyConsent == nil {
				a.status = "策略字段无效，请核对数字范围与选项"
			} else {
				e.confirmation = "policy-save"
			}
		}
	} else {
		ui.Text(c, "确认上述策略及影响：保存前重新读取策略与成员身份，但服务器没有版本比较，仍存在并发窗口。所有策略保存前会持久隔离本机此组织；普通同步不会恢复访问，需要显式重新核验。").MaxLines(6)
		ui.Text(c, "启用双因素或单一组织策略可能先撤销不符合条件的成员，再保存策略；即使返回错误，也可能已撤销部分成员。未知结果不重试，请核对成员和策略，关闭策略不会自动恢复成员。").MaxLines(6)
		if action(c, "确认保存组织策略", "", true, disabled).Key("policy-confirm").Clicked() {
			a.runOrganizationManagement("policy-save")
		}
		if action(c, "取消策略确认", "", false, disabled).Clicked() {
			e.policyConsent.Close()
			e.policyConsent = nil
			e.confirmation = ""
		}
	}
	if action(c, "返回策略列表", "", false, disabled).Clicked() {
		e.policyDraft.Close()
		e.policyDraft = nil
		e.policyConsent.Close()
		e.policyConsent = nil
		e.confirmation = ""
	}
}
