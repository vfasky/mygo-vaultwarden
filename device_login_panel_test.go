// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestDeviceLoginPanelRecoveryFailureAndLateCompletion(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://example.invalid", Account: "fixture"}
	client, _ := vaultwarden.NewClient(scope.Server, "fixture-device-id")
	adopted := 0
	p := NewDeviceLoginPanel(client, "fixture@example.invalid", scope, 7, DeviceLoginHost{
		Dispatch: func(f func()) { f() }, Check: func(vaultwarden.Scope, uint64) error { return nil },
		Accept: func(*vaultwarden.DeviceLogin, vaultwarden.DeviceLoginResult) error { adopted++; return nil },
	})
	p.auth = newAuthForm(scope, 7, func(authRequest) {})
	secret := p.auth
	secret.token = "synthetic secret"
	r := vaultwarden.DeviceLoginRecovery{Scope: scope, Email: "fixture@example.invalid", Epoch: 7, RequestID: "request-a", State: vaultwarden.DeviceLoginRecoverySubmitted}
	p.finish(0, nil, vaultwarden.DeviceLoginResult{Recovery: r}, vaultwarden.ErrIdentity)
	if adopted != 0 || p.auth != nil || secret.token != "" || !secret.closed {
		t.Fatal("failed result adopted or secrets retained")
	}
	if got := p.RecoveryOutcomes(); len(got) != 1 || deviceLoginRecoveryWarning(got[0]) != "可能已关闭全部两步验证，需核验并重新设置。" {
		t.Fatal("failure warning missing")
	}
	p.Cancel()
	p.Close()
	r.State = vaultwarden.DeviceLoginRecoveryConfirmed
	p.finish(0, nil, vaultwarden.DeviceLoginResult{Recovery: r}, vaultwarden.ErrCancelled)
	r.State = vaultwarden.DeviceLoginRecoverySubmitted
	p.finish(0, nil, vaultwarden.DeviceLoginResult{Recovery: r}, vaultwarden.ErrCancelled)
	r.Scope.Account = "other-account"
	p.finish(0, nil, vaultwarden.DeviceLoginResult{Recovery: r}, vaultwarden.ErrIdentity)
	got := p.RecoveryOutcomes()
	if len(got) != 1 || got[0].State != vaultwarden.DeviceLoginRecoveryConfirmed || deviceLoginRecoveryWarning(got[0]) != "已关闭全部两步验证，需核验并重新设置。" || adopted != 0 {
		t.Fatal("late completion lost warning or resurrected login")
	}
	got[0].State = vaultwarden.DeviceLoginRecoveryNotSubmitted
	if p.RecoveryOutcomes()[0].State != vaultwarden.DeviceLoginRecoveryConfirmed {
		t.Fatal("metadata alias")
	}
}

func TestDeviceLoginPanelCancellationAndLateMFA(t *testing.T) {
	dispatch := make(chan func(), 8)
	scope := vaultwarden.Scope{Server: "https://example.invalid", Account: "fixture"}
	client, _ := vaultwarden.NewClient(scope.Server, "fixture-device-id")
	adopted := 0
	p := NewDeviceLoginPanel(client, "fixture@example.invalid", scope, 7, DeviceLoginHost{Dispatch: func(f func()) { dispatch <- f }, Check: func(v vaultwarden.Scope, e uint64) error {
		if v != scope || e != 7 {
			return errors.New("stale")
		}
		return nil
	}, Accept: func(*vaultwarden.DeviceLogin, vaultwarden.DeviceLoginResult) error { adopted++; return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.busy = true
	done := make(chan error, 1)
	seq := p.sequence
	go func() { _, err := p.prompt(ctx, seq, vaultwarden.MFAChallenge{}); done <- err }()
	callback := <-dispatch
	p.Cancel()
	callback()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled prompt succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("prompt leaked")
	}
	if p.auth != nil || p.busy || p.fingerprint != "" || adopted != 0 {
		t.Fatal("late UI revived")
	}
	p.finish(0, nil, vaultwarden.DeviceLoginResult{}, nil)
	if adopted != 0 {
		t.Fatal("stale result adopted")
	}
}
func TestDeviceLoginPanelMFATokenAndRecoveryConfirmation(t *testing.T) {
	dispatch := make(chan func(), 8)
	scope := vaultwarden.Scope{Server: "https://example.invalid", Account: "fixture"}
	client, _ := vaultwarden.NewClient(scope.Server, "fixture-device-id")
	p := NewDeviceLoginPanel(client, "fixture@example.invalid", scope, 1, DeviceLoginHost{Dispatch: func(f func()) { dispatch <- f }, Check: func(vaultwarden.Scope, uint64) error { return nil }, Accept: func(*vaultwarden.DeviceLogin, vaultwarden.DeviceLoginResult) error { return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replies := make(chan vaultwarden.MFAResponse, 1)
	go func() { r, _ := p.prompt(ctx, 0, vaultwarden.MFAChallenge{}); replies <- r }()
	(<-dispatch)()
	p.auth.provider = 8
	p.auth.token = "synthetic-recovery"
	p.auth.dispatch()
	if !p.auth.confirming || p.auth.busy {
		t.Fatal("recovery lacked confirmation")
	}
	p.auth.dispatch()
	select {
	case r := <-replies:
		defer clear(r.Token)
		if !r.ConfirmRemoveAllMFA || string(r.Token) != "synthetic-recovery" {
			t.Fatal("wrong MFA response")
		}
	case <-time.After(time.Second):
		t.Fatal("missing response")
	}
	p.Close()
	if p.auth != nil {
		t.Fatal("form secrets retained")
	}
}
func TestDeviceLoginPanelFailureStatesAndHostRecheck(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://example.invalid", Account: "fixture"}
	client, _ := vaultwarden.NewClient(scope.Server, "fixture-device-id")
	p := NewDeviceLoginPanel(client, "fixture@example.invalid", scope, 1, DeviceLoginHost{Dispatch: func(f func()) { f() }, Check: func(vaultwarden.Scope, uint64) error { return nil }, Accept: func(*vaultwarden.DeviceLogin, vaultwarden.DeviceLoginResult) error {
		t.Fatal("failure adopted")
		return nil
	}})
	p.finish(0, nil, vaultwarden.DeviceLoginResult{}, vaultwarden.ErrDeviceUnknown)
	if p.status != "服务器不认识此账号的当前设备。请先使用主密码登录登记设备。" {
		t.Fatal("unknown device not explained")
	}
	p.finish(0, nil, vaultwarden.DeviceLoginResult{}, &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork})
	if p.status != "服务器操作结果未知；本次交换不会重放。请核验设备会话后手动发起新请求。" {
		t.Fatal("unknown exchange hidden")
	}
	p.Close()
	p.Start()
	if p.busy {
		t.Fatal("closed panel restarted")
	}
}
