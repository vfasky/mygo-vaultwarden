// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strconv"
)

func policyManagementOperation(op string) bool {
	return op == "policy-list" || op == "policy-load" || op == "policy-save" || op == "policy-review" || op == "policy-restore"
}

// adoptPolicyRecoveryPreview is the UI-thread half of the two-stage recovery.
// It installs the authenticated publish receipt before binding its network proof;
// neither an unadopted preview nor a late editor may authorize the next sync.
func (a *app) adoptPolicyRecoveryPreview(epoch uint64, e *organizationEditor, state *localstore.SnapshotStatus, vault *vaultwarden.VaultData, review *vaultwarden.PolicyRecoveryReview) bool {
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
	ui.Text(c, i18n.T("org.policy.pending_recovery_hint")).MaxLines(5)
	if e.policyRecovery == nil {
		if kit.Action(c, i18n.T("org.policy.review_server_policy"), "sync", false, disabled).Key("policy-review").Clicked() {
			a.runOrganizationManagement("policy-review")
		}
		return
	}
	for _, line := range e.policyRecovery.Summary() {
		ui.Text(c, line).MaxLines(3)
	}
	ui.Text(c, collectionPermissionLabel(i18n.T("org.policy.server_policy_enabled"), e.policyRecovery.Enabled()))
	ui.Text(c, i18n.T("org.policy.confirm_recovery_hint")).MaxLines(6)
	if kit.Action(c, i18n.T("org.policy.confirm_restore_access"), "", true, disabled).Key("policy-restore").Clicked() {
		e.confirmation = "policy-restore"
		a.runOrganizationManagement("policy-restore")
	}
	if kit.Action(c, i18n.T("org.policy.cancel_recovery"), "", false, disabled).Clicked() {
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
	ui.Text(c, i18n.T("org.policy.title")).FontSize(18)
	defs := vaultwarden.OrganizationPolicyDefinitions()
	if e.policyDraft == nil {
		if kit.Action(c, i18n.T("org.policy.load_policies"), "", false, disabled).Key("policy-list").Clicked() {
			a.runOrganizationManagement("policy-list")
		}
		for _, entry := range e.policies {
			for _, def := range defs {
				if def.Type != entry.Type {
					continue
				}
				if kit.Action(c, collectionPermissionLabel(def.Name, entry.Enabled), "", false, disabled).Key("policy-edit-" + strconv.Itoa(entry.Type)).Clicked() {
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
	ui.Text(c, i18n.T("org.policy.fields_hint")).MaxLines(4)
	if kit.Action(c, collectionPermissionLabel(i18n.T("org.policy.enable_policy"), d.Enabled), "", false, disabled || confirming).Key("policy-enabled").Clicked() {
		d.Enabled = !d.Enabled
	}
	for i := range d.Fields {
		f := &d.Fields[i]
		ui.Text(c, f.Label)
		if f.Kind == "uri" && (f.Value == "2" || f.Value == "4") {
			label := i18n.T("urimatch.starts_with")
			if f.Value == "4" {
				label = i18n.T("urimatch.regular_expression")
			}
			ui.Text(c, i18n.Tf("org.policy.current_uri_rule_hint", label)).MaxLines(3)
		}
		if f.Kind == "number" {
			ui.TextInput(c, &f.Value).Label(i18n.Tf("org.policy.number_range_hint", f.Min, f.Max)).Disabled(disabled || confirming)
			continue
		}
		options := []struct{ value, label string }{{"", i18n.T("common.default")}}
		switch f.Kind {
		case "bool":
			options = append(options, struct{ value, label string }{"true", i18n.T("common.yes")}, struct{ value, label string }{"false", i18n.T("common.no")})
		case "generator":
			options = append(options, struct{ value, label string }{"password", i18n.T("common.password")}, struct{ value, label string }{"passphrase", i18n.T("policy.value.passphrase")})
		case "uri":
			for n, label := range []string{i18n.T("urimatch.base_domain"), i18n.T("urimatch.host"), i18n.T("urimatch.starts_with"), i18n.T("urimatch.exact"), i18n.T("urimatch.regular_expression"), i18n.T("urimatch.never")} {
				if n == 2 || n == 4 {
					continue
				}
				options = append(options, struct{ value, label string }{strconv.Itoa(n), label})
			}
		}
		for _, option := range options {
			if kit.Action(c, collectionPermissionLabel(option.label, f.Value == option.value), "", false, disabled || confirming).Key("policy-field-" + f.Key + "-" + option.value).Clicked() {
				f.Value = option.value
			}
		}
	}
	if !confirming {
		if kit.Action(c, i18n.T("org.policy.save_policy"), "", true, disabled).Key("policy-save").Clicked() {
			e.policyConsent.Close()
			e.policyConsent = d.Confirm()
			if e.policyConsent == nil {
				a.status = i18n.T("org.policy.err_invalid_fields")
			} else {
				e.confirmation = "policy-save"
			}
		}
	} else {
		ui.Text(c, i18n.T("org.policy.confirm_save_hint")).MaxLines(6)
		ui.Text(c, i18n.T("org.policy.member_revocation_hint")).MaxLines(6)
		if kit.Action(c, i18n.T("org.policy.confirm_save"), "", true, disabled).Key("policy-confirm").Clicked() {
			a.runOrganizationManagement("policy-save")
		}
		if kit.Action(c, i18n.T("org.policy.cancel_confirmation"), "", false, disabled).Clicked() {
			e.policyConsent.Close()
			e.policyConsent = nil
			e.confirmation = ""
		}
	}
	if kit.Action(c, i18n.T("org.policy.back_to_list"), "", false, disabled).Clicked() {
		e.policyDraft.Close()
		e.policyDraft = nil
		e.policyConsent.Close()
		e.policyConsent = nil
		e.confirmation = ""
	}
}
