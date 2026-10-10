// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type accountRoundTrip func(*http.Request) (*http.Response, error)

func (f accountRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestAccountRechecksPolicyAndIdentityBeforeCommit(t *testing.T) {
	for _, scenario := range []string{"policy-change", "identity-change", "unknown-policy-field", "null-policy"} {
		t.Run(scenario, func(t *testing.T) {
			writes := 0
			s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, _ *Session, _ *VaultData) { writes++; w.WriteHeader(200) })
			plan, err := s.PrepareAccountCredentials(context.Background(), v, AccountChangePassword, accountTestPassword, []byte("Brand-New-Fixture-872!"), "", vaultcrypto.KDF{}, "", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			original := s.client.http.Transport
			s.client.http.Transport = accountRoundTrip(func(r *http.Request) (*http.Response, error) {
				resp, err := original.RoundTrip(r)
				if err != nil {
					return resp, err
				}
				replacement := ""
				if r.URL.Path == "/api/accounts/verify-password" {
					switch scenario {
					case "policy-change":
						replacement = `{"Object":"masterPasswordPolicy","minLength":128}`
					case "unknown-policy-field":
						replacement = `{"Object":"masterPasswordPolicy","newRequirement":true}`
					case "null-policy":
						replacement = `null`
					}
				}
				if r.URL.Path == "/api/accounts/profile" && scenario == "identity-change" {
					replacement = `{"id":"other","email":"wrong@example.invalid","key":"wrong"}`
				}
				if replacement != "" {
					_ = resp.Body.Close()
					resp.Body = io.NopCloser(strings.NewReader(replacement))
				}
				return resp, nil
			})
			result, err := s.CommitAccountChange(context.Background(), plan, "password", nil, func(AccountRecovery) error { t.Error("persisted after failed preflight"); return nil })
			if err == nil || writes != 0 || result.Dispatched {
				t.Fatal("changed policy/identity dispatched")
			}
		})
	}
}
func TestAccountCloseDuringDispatchRetainsDurableRecovery(t *testing.T) {
	reached := make(chan struct{})
	finished := make(chan struct{})
	var saved []byte
	s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, _ *Session, _ *VaultData) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(reached)
		<-r.Context().Done()
	})
	plan, err := s.PrepareAccountDestructive(context.Background(), v, AccountDelete, AccountSensitiveInput{Password: accountTestPassword}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	var result AccountChangeResult
	var operationError error
	go func() {
		result, operationError = s.CommitAccountChange(context.Background(), plan, "delete", nil, func(r AccountRecovery) error { saved, _ = json.Marshal(r); return nil })
		close(finished)
	}()
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch missing")
	}
	s.Close()
	<-finished
	defer clear(saved)
	if operationError == nil || !result.Unknown || !result.RequireLogin || len(saved) == 0 {
		t.Fatal("close lost unknown/recovery state")
	}
	var recovery AccountRecovery
	_ = json.Unmarshal(saved, &recovery)
	defer recovery.Close()
	if len(recovery.OldSession) == 0 || len(recovery.OldVault) == 0 || recovery.OperationID != result.OperationID {
		t.Fatal("incomplete durable recovery")
	}
}
