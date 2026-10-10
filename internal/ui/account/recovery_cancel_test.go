// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Take completion out of dispatch without executing it: cancellation happens
// after the worker succeeded, precisely before the UI accepts its result.
func recoveryQueuedCompletion(t *testing.T, q <-chan func()) func() {
	t.Helper()
	select {
	case f := <-q:
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("missing queued completion")
		return nil
	}
}

func TestRecoveryCancelQueuedPreparation(t *testing.T) {
	for _, lateError := range []bool{false, true} {
		for _, next := range []string{"cancel", "restart", "lock"} {
			t.Run(next+map[bool]string{false: "/success", true: "/error"}[lateError], func(t *testing.T) {
				q := make(chan func(), 2)
				plans := make(chan *vaultwarden.RecoveryPlan, 2)
				p := NewEmergencyPanel(nil, true, func(context.Context, RecoveryFormRequest) (*vaultwarden.RecoveryPlan, error) {
					plan := &vaultwarden.RecoveryPlan{}
					plans <- plan
					if lateError {
						return plan, errors.New("private failure")
					}
					return plan, nil
				}, nil, func(f func()) { q <- f })
				p.PreparePlan()
				old := recoveryQueuedCompletion(t, q)
				oldPlan := <-plans
				p.password = "secret"
				p.token = "token"
				p.cancelOperation()
				if p.running || p.cancel != nil || p.Plan != nil || p.password != "" || p.token != "" {
					t.Fatal("cancel retained preparation state")
				}
				if next == "restart" {
					p.PreparePlan()
				}
				if next == "lock" {
					p.Close()
				}
				status := p.Status
				old()
				if p.Plan != nil || p.Status != status {
					t.Fatal("cancelled preparation restored plan or status")
				}
				// No exported closed accessor exists; inspect only the consumed bit to
				// prove a discarded late plan was closed, without exposing its secrets.
				if !reflect.ValueOf(oldPlan).Elem().FieldByName("consumed").Bool() {
					t.Fatal("late plan not closed")
				}
				if next == "restart" {
					if !p.running || p.cancel == nil {
						t.Fatal("old completion disturbed new attempt")
					}
					recoveryQueuedCompletion(t, q)()
					<-plans
					if !lateError && p.Plan == nil {
						t.Fatal("fresh attempt not accepted")
					}
				}
				p.Close()
			})
		}
	}
}

func TestEmergencyCancelQueuedView(t *testing.T) {
	for _, lateError := range []bool{false, true} {
		for _, next := range []string{"cancel", "restart", "lock"} {
			t.Run(next+map[bool]string{false: "/success", true: "/error"}[lateError], func(t *testing.T) {
				q := make(chan func(), 2)
				results := make(chan []vaultwarden.CipherFields, 2)
				v := NewEmergencyViewer(vaultwarden.EmergencyContact{ID: "fixture", Status: 4, Type: 0}, func(context.Context, string) ([]vaultwarden.CipherFields, error) {
					rows := []vaultwarden.CipherFields{{ID: "item", Name: "secret", Login: map[string]any{"password": "fixture secret"}}}
					results <- rows
					if lateError {
						return rows, errors.New("private failure")
					}
					return rows, nil
				}, func(f func()) { q <- f })
				v.load()
				old := recoveryQueuedCompletion(t, q)
				oldRows := <-results
				v.rows = []vaultwarden.CipherFields{{Name: "held secret"}}
				heldRows := v.rows
				v.revealed = true
				v.selected = 0
				v.cancelLoad()
				if v.running || v.cancel != nil || v.rows != nil || v.revealed || v.selected != -1 || heldRows[0].Name != "" {
					t.Fatal("cancel retained sensitive view state")
				}
				if next == "restart" {
					v.load()
				}
				if next == "lock" {
					v.Close()
				}
				status := v.status
				old()
				if v.rows != nil || v.revealed || v.status != status || oldRows[0].Name != "" || oldRows[0].Login != nil {
					t.Fatal("cancelled fetch restored or retained sensitive rows")
				}
				if next == "restart" {
					if !v.running || v.cancel == nil {
						t.Fatal("old completion disturbed new view")
					}
					recoveryQueuedCompletion(t, q)()
					<-results
					if !lateError && len(v.rows) != 1 {
						t.Fatal("fresh view not accepted")
					}
				}
				v.Close()
			})
		}
	}
}

func TestRecoveryCancelSubmitPreservesHostResult(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		for _, lock := range []bool{false, true} {
			t.Run(map[bool]string{false: "confirmed", true: "unknown"}[unknown]+map[bool]string{false: "/cancel", true: "/lock"}[lock], func(t *testing.T) {
				q := make(chan func(), 1)
				started := make(chan struct{})
				recorded := make(chan vaultwarden.RecoveryOperationResult, 1)
				p := NewEmergencyPanel(nil, true, nil, func(ctx context.Context, plan *vaultwarden.RecoveryPlan, _ string) (vaultwarden.RecoveryOperationResult, error) {
					close(started)
					<-ctx.Done()
					result := vaultwarden.RecoveryOperationResult{Dispatched: true, Confirmed: !unknown, Unknown: unknown}
					result.OperationID = "fixture-operation"
					result.Actor = vaultwarden.Scope{Account: "actor"}
					result.Target = vaultwarden.Scope{Account: "target"}
					// Host recording is inside the commit adapter, independent of UI dispatch.
					recorded <- result
					return result, nil
				}, func(f func()) { q <- f })
				p.Plan = &vaultwarden.RecoveryPlan{}
				p.CommitPlan()
				<-started
				generation := p.generation
				p.cancelOperation()
				if !p.running || !p.submitting || p.generation != generation {
					t.Fatal("submit cancellation reopened preparation or invalidated result")
				}
				if lock {
					p.Close()
				}
				recoveryQueuedCompletion(t, q)()
				result := <-recorded
				if result.OperationID != "fixture-operation" || result.Actor.Account != "actor" || result.Target.Account != "target" || result.Unknown != unknown || result.Confirmed == unknown {
					t.Fatal("host lost operation result")
				}
				if lock {
					if p.Status != "" || !p.closed {
						t.Fatal("late submit restored closed UI")
					}
				} else if !p.terminal || p.running || p.submitting {
					t.Fatal("submit result not settled")
				}
				p.Close()
			})
		}
	}
}
