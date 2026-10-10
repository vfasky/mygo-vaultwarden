// SPDX-License-Identifier: GPL-3.0-only
package account

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
	p := NewRecoveryPanel([]RecoveryMemberChoice{{OrganizationID: "org-a", MemberID: "member-a", Label: "Fixture", Administrator: true}}, func(ctx context.Context, r RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
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
	p.PreparePlan()
	if p.running {
		t.Fatal("mismatch accepted")
	}
	p.repeatPassword = p.newPassword
	p.CommitPlan()
	if committed != 0 {
		t.Fatal("skipped prepare")
	}
	p.PreparePlan()
	if p.newPassword != "" || p.repeatPassword != "" {
		t.Fatal("secret retained")
	}
	recoveryUIReceive(t, q)
	if prepared != 1 || p.Plan == nil || committed != 0 {
		t.Fatal("prepare auto committed")
	}
	p.CommitPlan()
	recoveryUIReceive(t, q)
	if !p.terminal || !strings.Contains(p.Status, "未知") || strings.Contains(p.Status, "secret") {
		t.Fatal("uncertain result UI")
	}
	p.PreparePlan()
	p.CommitPlan()
	if prepared != 1 || committed != 1 {
		t.Fatal("retry")
	}
}
func TestRecoveryPanelCloseCancelsLatePreparation(t *testing.T) {
	q := make(chan func(), 1)
	started := make(chan struct{})
	p := NewEmergencyPanel(nil, true, func(ctx context.Context, r RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
		close(started)
		<-ctx.Done()
		return &vaultwarden.RecoveryPlan{}, nil
	}, nil, func(f func()) { q <- f })
	p.Email = "fixture@example.invalid"
	p.PreparePlan()
	<-started
	p.Close()
	recoveryUIReceive(t, q)
	if p.Plan != nil || p.Status != "" || !p.closed {
		t.Fatal("late preparation restored state")
	}
}
func TestEmergencyViewerWaitGateAndClose(t *testing.T) {
	q := make(chan func(), 1)
	called := false
	v := NewEmergencyViewer(vaultwarden.EmergencyContact{ID: "emergency", Status: 3, Type: 0}, func(ctx context.Context, id string) ([]vaultwarden.CipherFields, error) {
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
