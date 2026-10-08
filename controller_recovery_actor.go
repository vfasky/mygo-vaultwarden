// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (c *orgServicesController) emergencyView(view *ui.Context) {
	ui.Text(view, "紧急访问").FontSize(22)
	if ui.Button(view, "我授权的紧急联系人").Disabled(c.owner.pending != 0).Clicked() {
		c.loadEmergency(true)
	}
	if ui.Button(view, "授予我的紧急访问").Disabled(c.owner.pending != 0).Clicked() {
		c.loadEmergency(false)
	}
	if !c.emergencyTrusted {
		for _, contact := range c.emergencyContacts {
			if vaultwarden.EmergencyActionAllowed(contact, false, "view") {
				if ui.Button(view, "只读查看："+contact.Name+" · "+contact.Email).Disabled(c.owner.pending != 0).Clicked() {
					c.openEmergencyView(contact)
				}
			}
		}
	}
	if c.panel != nil {
		c.panel.View(view)
	}
	if env, err := c.environment(); err == nil {
		if warning := c.owner.targetOutcomeWarnings[env.vault.Scope]; warning != "" {
			ui.Text(view, warning).MaxLines(5)
		}
	}
	ui.Text(view, c.status).MaxLines(8)
}

func (a *app) noteTargetOutcome(scope vaultwarden.Scope, message string) {
	if a.targetOutcomeWarnings == nil {
		a.targetOutcomeWarnings = map[vaultwarden.Scope]string{}
	}
	if len(a.targetOutcomeWarnings) >= 64 {
		for key := range a.targetOutcomeWarnings {
			delete(a.targetOutcomeWarnings, key)
			break
		}
	}
	a.targetOutcomeWarnings[scope] = message
}
func (c *orgServicesController) prepareRecovery(ctx context.Context, request recoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
	ctx, done, env, err := c.operation(ctx)
	defer done()
	if err != nil {
		return nil, err
	}
	switch request.Action {
	case "administrator":
		return env.session.PrepareAdministratorRecovery(ctx, env.vault, request.OrganizationID, request.MemberID, request.TrustedPublicKey, request.NewPassword, request.ResetPassword, request.ResetTwoFactor, c.checkpoint(env))
	case "enroll", "withdraw":
		return env.session.PrepareRecoveryEnrollment(ctx, env.vault, request.OrganizationID, request.Action == "enroll", request.TrustedPublicKey, vaultwarden.AccountSensitiveInput{Password: request.Password, OTP: request.OTP}, c.checkpoint(env))
	case "takeover":
		return env.session.PrepareEmergencyTakeover(ctx, env.vault, request.Emergency.ID, request.NewPassword, c.checkpoint(env))
	default:
		return env.session.PrepareEmergencyOperation(ctx, env.vault, request.Emergency, c.checkpoint(env))
	}
}

// The adapter's lifetime belongs to this already-owned operation, so a late
// result can update ONLY its original metadata journal. Begin separately checks
// the actual UI lease, and native scope/revision/binding still gate every write.
func (c *orgServicesController) recoveryAdapter(env orgServiceSnapshot, description vaultwarden.RecoveryDispatch, active *atomic.Bool) (*targetRecoveryStorage, func(), error) {
	current := func() uint64 {
		if active.Load() {
			return env.epoch
		}
		return 0
	}
	if !env.runtime {
		state, valid := env.lease.state()
		if !valid {
			return nil, func() {}, vaultwarden.ErrExpired
		}
		var adapter *targetRecoveryStorage
		err := env.session.WithTargetRecoveryStorageKey(env.vault, state.Revision, func(scope vaultwarden.Scope, key []byte) error {
			if state.Scope == nil || scope != *state.Scope {
				return vaultwarden.ErrIdentity
			}
			var err error
			adapter, err = newTargetRecoveryStorage(&state, env.epoch, current, key, c.baseStorage)
			return err
		})
		return adapter, func() {
			if adapter != nil {
				adapter.Close()
			}
		}, err
	}
	runtime := c.runtime
	if runtime == nil {
		return nil, func() {}, vaultwarden.ErrExpired
	}
	runtime.mu.Lock()
	cap, source, backend := runtime.authority, runtime.source, runtime.native
	runtime.mu.Unlock()
	native, ok := backend.(*nativeRuntimeSecrets)
	if !ok {
		return nil, func() {}, errRuntimeSecretUnavailable
	}
	raw, err := json.Marshal(description)
	if err != nil {
		return nil, func() {}, err
	}
	var deadline time.Time
	if err = cap.WithProtection(env.vault, func(value time.Time) error { deadline = value; return nil }); err != nil {
		return nil, func() {}, err
	}
	// Native activation may wait for the UI thread; never call it under Session.mu.
	binding, err := native.activateBound(cap.Scope(), "recovery", deadline, func(uint64, int64) (string, string) { return description.OperationID, targetRecoveryHash(raw) })
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { native.Revoke() }
	if cap.CheckLease() != nil || env.lease.clock.Load() != env.epoch {
		cleanup()
		return nil, func() {}, vaultwarden.ErrCancelled
	}
	authority := targetRecoveryRuntimeAuthority{Scope: binding.Scope, Generation: binding.Generation, DeadlineUnixMS: binding.DeadlineUnixMS, LeaseID: binding.LeaseID, OperationID: binding.OperationID, SummaryHash: binding.SummaryHash}
	adapter, err := newTargetRecoveryRuntimeStorage(&source, env.epoch, current, authority, c.baseStorage)
	return adapter, func() {
		if adapter != nil {
			adapter.Close()
		}
		cleanup()
	}, err
}
func (c *orgServicesController) commitRecovery(ctx context.Context, plan *vaultwarden.RecoveryPlan, confirmation string) (vaultwarden.RecoveryOperationResult, error) {
	ctx, done, env, err := c.operation(ctx)
	defer done()
	if err != nil {
		return vaultwarden.RecoveryOperationResult{}, err
	}
	description := plan.Summary()
	var active atomic.Bool
	active.Store(true)
	defer active.Store(false)
	adapter, cleanup, err := c.recoveryAdapter(env, description, &active)
	defer cleanup()
	if err != nil {
		return vaultwarden.RecoveryOperationResult{}, err
	}
	result, operationErr := env.session.CommitRecoveryOperation(ctx, plan, confirmation, c.checkpoint(env), func(record vaultwarden.RecoveryDispatch) error {
		if err := env.lease.check(env.storage); err != nil {
			return err
		}
		return adapter.Begin(record)
	})
	recordErr := adapter.Result(result)
	receipt := adapter.Receipt()
	var observed storageReply
	if result.IsolationAttempted && receipt == nil {
		observed = c.baseStorage(storageRequest{Operation: "status"})
		if observed.OK {
			receipt = observed.State
		}
	}
	if recordErr != nil && operationErr == nil {
		operationErr = recordErr
	}
	if result.IsolationAttempted {
		message := fmt.Sprintf("恢复操作 %s 已建立持久隔离；请核对原账号的恢复记录，不会重放。", description.OperationID)
		if result.Confirmed && recordErr == nil {
			message = "恢复请求及服务器确认已记录；目标仍须本人重新登录、同步和核验。"
		} else if !result.Dispatched && recordErr == nil {
			message = "原操作确定未派发；若已隔离目标，须由其本人重新认证解除本机预隔离。"
		} else if recordErr != nil {
			message = "原恢复操作的最终持久结果未确认；保留日志/隔离，勿重新提交。"
		}
		c.dispatch(func() {
			a := c.owner
			a.noteTargetOutcome(description.Actor, message)
			if a.orgServices != c || a.epoch != env.epoch {
				return
			}
			if env.runtime || (description.RequireTargetLogin && description.Target == description.Actor) {
				a.stopNetwork()
				if receipt != nil {
					a.snapshot = receipt
				}
				a.status = message + " 请重新登录。"
				return
			}
			if receipt != nil && a.adoptSessionCheckpoint(receipt) {
				a.advanceEpoch()
				a.status = message
			} else {
				a.stopNetwork()
				if receipt != nil {
					a.snapshot = receipt
				}
				a.status = message
			}
		})
	}
	return result, operationErr
}
func (c *orgServicesController) loadEmergency(trusted bool) {
	c.busy(true)
	go func() {
		ctx, done, env, err := c.operation(c.ctx)
		defer done()
		var contacts []vaultwarden.EmergencyContact
		if err == nil {
			contacts, err = env.session.EmergencyContacts(ctx, env.vault, trusted, c.checkpoint(env))
		}
		c.deliver(func() {
			c.busy(false)
			if c.owner.orgServices != c || c.owner.epoch != env.epoch {
				return
			}
			if err != nil {
				c.status = err.Error()
				return
			}
			c.emergencyContacts = contacts
			c.emergencyTrusted = trusted
			c.replacePanel(newEmergencyPanel(contacts, trusted, c.prepareRecovery, c.commitRecovery, c.deliver))
		})
	}()
}
func (c *orgServicesController) loadRecoveryMembers() {
	organizations := append([]vaultwarden.Organization(nil), c.organizations...)
	c.busy(true)
	go func() {
		ctx, done, env, err := c.operation(c.ctx)
		defer done()
		var choices []recoveryMemberChoice
		if err == nil {
			for _, org := range organizations {
				choices = append(choices, recoveryMemberChoice{OrganizationID: org.ID, MemberID: org.OrganizationUserID, Label: org.Name + " · 自身恢复登记"})
				if org.Type != 0 && org.Type != 1 {
					continue
				}
				directory, e := env.session.OrganizationMembers(ctx, env.vault, org.ID, c.checkpoint(env))
				if e != nil {
					err = e
					break
				}
				for _, member := range directory.Members() {
					choices = append(choices, recoveryMemberChoice{OrganizationID: org.ID, MemberID: member.ID, Label: org.Name + " · " + member.Email, Administrator: true})
				}
				directory.Close()
			}
		}
		c.deliver(func() {
			c.busy(false)
			if c.owner.orgServices != c || c.owner.epoch != env.epoch {
				return
			}
			if err != nil {
				c.status = err.Error()
				return
			}
			c.replacePanel(newRecoveryPanel(choices, c.prepareRecovery, c.commitRecovery, c.deliver))
		})
	}()
}
func (c *orgServicesController) openEmergencyView(contact vaultwarden.EmergencyContact) {
	c.replacePanel(newEmergencyViewer(contact, func(ctx context.Context, id string) ([]vaultwarden.CipherFields, error) {
		ctx, done, env, err := c.operation(ctx)
		defer done()
		if err != nil {
			return nil, err
		}
		var rows []vaultwarden.CipherFields
		err = env.session.WithEmergencyView(ctx, env.vault, id, true, c.checkpoint(env), func(fields []vaultwarden.CipherFields) error {
			rows = append([]vaultwarden.CipherFields(nil), fields...)
			return nil
		})
		if err != nil {
			clear(rows)
			return nil, err
		}
		return rows, nil
	}, c.deliver))
}
