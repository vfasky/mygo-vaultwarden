// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func emergencyTestList(status, kind int, trusted bool) map[string]any {
	row := map[string]any{"id": "emergency-a", "status": status, "type": kind, "waitTimeDays": 7, "email": "other@example.invalid", "name": "Fixture"}
	if trusted {
		row["object"] = "emergencyAccessGranteeDetails"
		row["granteeId"] = "account-b"
	} else {
		row["object"] = "emergencyAccessGrantorDetails"
		row["grantorId"] = "account-b"
	}
	return map[string]any{"object": "list", "data": []any{row}, "continuationToken": nil}
}
func TestEmergencyStrictListsAndStateMatrix(t *testing.T) {
	for status := 0; status <= 4; status++ {
		for kind := 0; kind <= 1; kind++ {
			for _, trusted := range []bool{false, true} {
				raw, _ := json.Marshal(emergencyTestList(status, kind, trusted))
				rows, err := decodeEmergencyContacts(raw, trusted, "account-a")
				if err != nil || len(rows) != 1 {
					t.Fatal(err)
				}
				if EmergencyActionAllowed(rows[0], trusted, "view") != (!trusted && status == 4 && kind == 0) {
					t.Fatal("view matrix")
				}
				if EmergencyActionAllowed(rows[0], trusted, "takeover") != (!trusted && status == 4 && kind == 1) {
					t.Fatal("takeover matrix")
				}
				if EmergencyActionAllowed(rows[0], trusted, "approve") != (trusted && status == 3) {
					t.Fatal("approve matrix")
				}
			}
		}
	}
	for _, change := range []func(map[string]any){
		func(l map[string]any) { l["continuationToken"] = "next" }, func(l map[string]any) { delete(l, "continuationToken") },
		func(l map[string]any) { delete(l["data"].([]any)[0].(map[string]any), "status") },
		func(l map[string]any) { l["data"].([]any)[0].(map[string]any)["granteeId"] = "account-a" },
		func(l map[string]any) { l["data"] = append(l["data"].([]any), l["data"].([]any)[0]) },
	} {
		l := emergencyTestList(2, 0, true)
		change(l)
		raw, _ := json.Marshal(l)
		if _, err := decodeEmergencyContacts(raw, true, "account-a"); err == nil {
			t.Fatal("accepted malformed list")
		}
	}
}
func TestEmergencyPlanGuardUnknownAndNoRetry(t *testing.T) {
	for _, mode := range []string{"success", "partial", "state-change", "checkpoint", "barrier", "cancel", "cross-session", "lock"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int32
			state := 2
			s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
				if r.Method == "GET" {
					_ = json.NewEncoder(w).Encode(emergencyTestList(state, 0, false))
					return
				}
				writes.Add(1)
				if mode == "partial" {
					w.WriteHeader(503)
				} else {
					w.WriteHeader(200)
				}
			})
			p, err := s.PrepareEmergencyOperation(context.Background(), v, EmergencyRequest{Action: "initiate", ID: "emergency-a"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := func(r RecoveryDispatch) error {
				if r.Actor != v.Scope || r.Target.Account != "account-b" || r.Target.Server != v.Scope.Server || r.AuthorizationEpoch == 0 || r.OperationID == "" {
					t.Error("bad binding")
				}
				if mode == "barrier" {
					return errors.New("fixture storage failure")
				}
				return nil
			}
			switch mode {
			case "state-change":
				state = 3
			case "checkpoint":
				s.expires = time.Now().Add(-time.Hour)
			case "cancel":
				cancel()
			case "cross-session":
				p.owner = nil
			case "lock":
				s.Close()
			}
			result, err := s.CommitRecoveryOperation(ctx, p, p.ConfirmationText(), nil, before)
			switch mode {
			case "success":
				if err != nil || !result.Confirmed || writes.Load() != 1 {
					t.Fatal(result, err)
				}
			case "partial":
				if err == nil || !result.Unknown || !result.Dispatched || writes.Load() != 1 {
					t.Fatal(result, err)
				}
			default:
				if err == nil || writes.Load() != 0 {
					t.Fatal("guard failed", result, err, writes.Load())
				}
			}
			_, _ = s.CommitRecoveryOperation(ctx, p, p.ConfirmationText(), nil, before)
			if writes.Load() > 1 {
				t.Fatal("replayed")
			}
		})
	}
}
func TestEmergencyConfirmRequiresTrustedKeyAndRevalidates(t *testing.T) {
	recipientKey := bytes.Repeat([]byte{34}, 64)
	pair, err := makeOrganizationKeyPair(recipientKey)
	if err != nil {
		t.Fatal(err)
	}
	privateJSON, _ := json.Marshal(map[string]string{"privateKey": pair.EncryptedPrivateKey})
	private, err := accountPrivateKey(privateJSON, recipientKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clearAccountPrivateKey(private)
	writes := 0
	changed := false
	s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, s *Session, v *VaultData) {
		switch r.URL.Path {
		case "/api/emergency-access/trusted":
			_ = json.NewEncoder(w).Encode(emergencyTestList(1, 0, true))
		case "/api/users/account-b/public-key":
			pub := pair.PublicKey
			if changed {
				pub = "invalid"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"userId": "account-b", "publicKey": pub})
		default:
			writes++
			var req struct{ Key string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			key, e := unwrapOrganizationKey(req.Key, private)
			if e != nil || !bytes.Equal(key, s.key) {
				t.Error("not target user key", e)
			}
			clear(key)
		}
	})
	request := EmergencyRequest{Action: "confirm", ID: "emergency-a", Trusted: true, TrustedPublicKey: "bad"}
	if _, err = s.PrepareEmergencyOperation(context.Background(), v, request, nil); err == nil || writes != 0 {
		t.Fatal("untrusted key accepted")
	}
	request.TrustedPublicKey = pair.PublicKey
	p, err := s.PrepareEmergencyOperation(context.Background(), v, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed = true
	if _, err = s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil }); err == nil || writes != 0 {
		t.Fatal("changed key accepted")
	}
	p.Close()
	changed = false
	p, err = s.PrepareEmergencyOperation(context.Background(), v, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil }); err != nil || writes != 1 {
		t.Fatal(err)
	}
}
func TestRecoveryAvailabilityDoesNotTrustOrdinary400(t *testing.T) {
	for _, row := range []struct {
		status int
		body   string
		ok     bool
	}{{400, `{"message":"Emergency access not valid.","errorModel":{"message":"Emergency access not valid."}}`, true}, {400, `{"message":"Emergency access is not enabled.","errorModel":{"message":"Emergency access is not enabled."}}`, false}, {400, `{"message":"Emergency access not valid."}`, false}, {401, `{}`, false}, {200, `{}`, false}, {400, `{"message":"proxy failure","errorModel":{"message":"proxy failure"}}`, false}} {
		_, err := recoveryAvailabilityResponse(row.status, []byte(row.body))
		if (err == nil) != row.ok {
			t.Fatal(row.status, row.ok, err)
		}
	}
}
func TestRecoveryRotationEnumeratesEmptyAndRevalidates(t *testing.T) {
	input := AccountRotationInput{Scope: Scope{Server: "http://localhost", Account: "account-a"}, Revision: "rev", Epoch: 1, NewUserKey: bytes.Repeat([]byte{1}, 64), Sync: json.RawMessage(`{"profile":{"id":"account-a","organizations":[]}}`)}
	enabled := true
	input.Read = func(ctx context.Context, path string) (json.RawMessage, error) {
		if path == emergencyAvailabilityPath {
			if !enabled {
				return nil, ErrEmergencyUnavailable
			}
			return json.RawMessage(`{"emergencyAccessEnabled":true}`), nil
		}
		if path == "/api/emergency-access/trusted" {
			return json.RawMessage(`{"data":[],"object":"list","continuationToken":null}`), nil
		}
		return nil, ErrPermission
	}
	conversion, err := RewrapRecoveryRotation(context.Background(), input, RecoveryRotationTrust{})
	if err != nil || !conversion.Coverage.EmergencyComplete || !conversion.Coverage.RecoveryComplete {
		t.Fatal(err)
	}
	enabled = false
	if err = conversion.Revalidate(context.Background(), input.Read); !errors.Is(err, ErrEmergencyUnavailable) {
		t.Fatal(err)
	}
	if _, err = RewrapRecoveryRotation(context.Background(), input, RecoveryRotationTrust{}); err == nil {
		t.Fatal("hidden empty grants accepted")
	}
}
