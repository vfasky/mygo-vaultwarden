// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func recoveryUIReceive(t *testing.T, q chan func()) {
	t.Helper()
	select {
	case f := <-q:
		f()
	case <-time.After(time.Second):
		t.Fatal("missing completion")
	}
}
func TestRecoveryPanelPrepareConfirmUnknownNoRetry(t *testing.T) {
	q := make(chan func(), 2)
	prepared, committed := 0, 0
	p := newRecoveryPanel([]recoveryMemberChoice{{OrganizationID: "org-a", MemberID: "member-a", Label: "Fixture", Administrator: true}}, func(ctx context.Context, r recoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
		prepared++
		if r.OrganizationID != "org-a" || r.MemberID != "member-a" || string(r.NewPassword) != "new fixture password" {
			t.Error("request binding")
		}
		return &vaultwarden.RecoveryPlan{}, nil
	}, func(context.Context, *vaultwarden.RecoveryPlan, string) (vaultwarden.RecoveryOperationResult, error) {
		committed++
		return vaultwarden.RecoveryOperationResult{Dispatched: true, Unknown: true}, errors.New("secret must not reach UI")
	}, func(f func()) { q <- f })
	p.selected = 0
	p.operation = "administrator"
	p.newPassword = "new fixture password"
	p.repeatPassword = "different"
	p.preparePlan()
	if p.running {
		t.Fatal("mismatch accepted")
	}
	p.repeatPassword = p.newPassword
	p.commitPlan()
	if committed != 0 {
		t.Fatal("skipped prepare")
	}
	p.preparePlan()
	if p.newPassword != "" || p.repeatPassword != "" {
		t.Fatal("secret retained")
	}
	recoveryUIReceive(t, q)
	if prepared != 1 || p.plan == nil || committed != 0 {
		t.Fatal("prepare auto committed")
	}
	p.commitPlan()
	recoveryUIReceive(t, q)
	if !p.terminal || !strings.Contains(p.status, "未知") || strings.Contains(p.status, "secret") {
		t.Fatal("uncertain result UI")
	}
	p.preparePlan()
	p.commitPlan()
	if prepared != 1 || committed != 1 {
		t.Fatal("retry")
	}
}
func TestRecoveryPanelCloseCancelsLatePreparation(t *testing.T) {
	q := make(chan func(), 1)
	started := make(chan struct{})
	p := newEmergencyPanel(nil, true, func(ctx context.Context, r recoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
		close(started)
		<-ctx.Done()
		return &vaultwarden.RecoveryPlan{}, nil
	}, nil, func(f func()) { q <- f })
	p.email = "fixture@example.invalid"
	p.preparePlan()
	<-started
	p.Close()
	recoveryUIReceive(t, q)
	if p.plan != nil || p.status != "" || !p.closed {
		t.Fatal("late preparation restored state")
	}
}
func TestEmergencyViewerWaitGateAndClose(t *testing.T) {
	q := make(chan func(), 1)
	called := false
	v := newEmergencyViewer(vaultwarden.EmergencyContact{ID: "emergency", Status: 3, Type: 0}, func(ctx context.Context, id string) ([]vaultwarden.CipherFields, error) {
		called = true
		return []vaultwarden.CipherFields{{ID: "item", Name: "Secret"}}, nil
	}, func(f func()) { q <- f })
	v.load()
	if called || v.running {
		t.Fatal("local waiting bypass")
	}
	v.contact.Status = 4
	v.load()
	recoveryUIReceive(t, q)
	if len(v.rows) != 1 || v.revealed {
		t.Fatal("not masked initially")
	}
	v.Close()
	if v.rows != nil || v.revealed {
		t.Fatal("secret retained")
	}
}
