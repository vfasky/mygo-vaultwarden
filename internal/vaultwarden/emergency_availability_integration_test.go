// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLiveDisabledEmergencyHistory(t *testing.T, ctx context.Context, dir, id string, s *Session) {
	t.Helper()
	// Only a freshly created fixture's full ID and ownership label are accepted.
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "mygo-recovery-") {
		t.Fatal("feature fixture ownership", err)
	}
	change := func(enabled bool) {
		t.Helper()
		body, _ := json.Marshal(map[string]bool{"emergency_access_allowed": enabled})
		path := filepath.Join(dir, "emergency-config.json")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.CommandContext(ctx, "docker", "cp", path, id+":/data/config.json").CombinedOutput(); err != nil {
			t.Fatalf("owned config copy: %s %v", out, err)
		}
		if out, err := exec.CommandContext(ctx, "docker", "restart", id).CombinedOutput(); err != nil {
			t.Fatalf("owned restart: %s %v", out, err)
		}
		httpClient := &http.Client{Timeout: time.Second}
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
			r, e := httpClient.Get(s.client.base.String() + "/alive")
			if e == nil {
				_ = r.Body.Close()
				if r.StatusCode == 200 {
					return
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(150 * time.Millisecond):
			}
		}
		t.Fatal("owned restart readiness")
	}
	read := func(ctx context.Context, path string) (json.RawMessage, error) {
		status, body, err := s.client.request(ctx, "GET", path, "", "", s.access)
		if err != nil {
			return nil, err
		}
		if path == emergencyAvailabilityPath {
			return recoveryAvailabilityResponse(status, body)
		}
		if status != 200 {
			return nil, statusError(status)
		}
		return body, nil
	}
	body, err := read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		t.Fatal(err)
	}
	before, err := decodeEmergencyContacts(body, true, s.account)
	if err != nil || len(before) == 0 {
		t.Fatal("historical confirmed grant missing", err)
	}
	change(false)
	body, err = read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := decodeEmergencyContacts(body, true, s.account)
	if err != nil || len(hidden) != 0 {
		t.Fatal("disabled listing", err)
	}
	_, err = RewrapRecoveryRotation(ctx, AccountRotationInput{Scope: Scope{Server: s.client.base.String(), Account: s.account}, Epoch: 1, Revision: "fixture", NewUserKey: make([]byte, 64), Read: read}, RecoveryRotationTrust{})
	if err != ErrEmergencyUnavailable {
		t.Fatal("disabled historical grants not blocked", err)
	}
	change(true)
	body, err = read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		t.Fatal(err)
	}
	after, err := decodeEmergencyContacts(body, true, s.account)
	if err != nil || len(after) != len(before) || after[0].ID != before[0].ID {
		t.Fatal("history did not survive toggled feature", err)
	}
	t.Log("real disabled feature hides existing grant; probe blocks false empty coverage; re-enabled historical grant verified")
}
