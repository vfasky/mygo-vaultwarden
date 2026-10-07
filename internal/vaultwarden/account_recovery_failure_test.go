// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecoveryRefreshCheckpointFailurePreventsMutation(t *testing.T) {
	var writes, refresh atomic.Int32
	s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
		if r.URL.Path == "/identity/connect/token" {
			refresh.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "bearer", "key": s.wrapped})
			return
		}
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(emergencyTestList(2, 0, false))
			return
		}
		writes.Add(1)
	})
	p, err := s.PrepareEmergencyOperation(context.Background(), v, EmergencyRequest{Action: "initiate", ID: "emergency-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s.expires = time.Time{}
	checkpoint := errors.New("fixture checkpoint failure")
	result, err := s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), func(SessionCheckpoint) error { return checkpoint }, func(RecoveryDispatch) error { t.Error("isolation after failed checkpoint"); return nil })
	if err == nil || writes.Load() != 0 || refresh.Load() != 1 || result.Dispatched {
		t.Fatal("checkpoint barrier failed", writes.Load(), refresh.Load(), result, err)
	}
}
func TestRecoveryCloseDuringDispatchIsUnknown(t *testing.T) {
	reached := make(chan struct{})
	done := make(chan struct{})
	s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(emergencyTestList(2, 0, false))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(reached)
		<-r.Context().Done()
	})
	p, err := s.PrepareEmergencyOperation(context.Background(), v, EmergencyRequest{Action: "initiate", ID: "emergency-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var result RecoveryOperationResult
	var dispatchError error
	go func() {
		result, dispatchError = s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil })
		close(done)
	}()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("missing dispatch")
	}
	s.Close()
	<-done
	if dispatchError == nil || !result.Dispatched || !result.Unknown || !result.IsolationAttempted {
		t.Fatal("unknown dispatch lost", result, dispatchError)
	}
	if _, err = s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil }); err == nil {
		t.Fatal("replayed closed operation")
	}
}
