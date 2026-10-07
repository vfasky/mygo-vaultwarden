// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt-in: exclusively owned volatile loopback container, no production secrets.
func TestDeviceNotificationLive1374(t *testing.T) {
	if os.Getenv("MYGO_VW_NOTIFICATION_TEST") != "1" {
		t.Skip("opt-in owned Docker fixture MYGO_VW_NOTIFICATION_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "mygo-notification-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	out, e := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server:1.37.4").CombinedOutput()
	if e != nil {
		t.Fatalf("owned fixture create: %s %v", out, e)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("ownership check failed", e)
			return
		}
		if out, e = exec.CommandContext(cleanup, "docker", "rm", "-fv", id).CombinedOutput(); e != nil {
			t.Errorf("cleanup: %s %v", out, e)
		}
	})
	if out, e = exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); e != nil {
		t.Fatalf("start: %s %v", out, e)
	}
	health := http.Client{Timeout: time.Second}
	ready := false
	for until := time.Now().Add(40 * time.Second); time.Now().Before(until); {
		r, e := health.Get(base + "/alive")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("readiness")
	}
	s, _ := liveOrganizationMember(t, ctx, base)
	defer s.Close()
	result, e := s.Sync(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AcceptAuthenticatedSnapshot(result.Vault, fixtureUUID()); e != nil {
		t.Fatal(e)
	}
	scope := result.Vault.Scope
	if devices, e := s.Devices(ctx, scope, nil); e != nil || len(devices) < 1 {
		t.Fatal("devices", devices, e)
	}
	if _, e = s.CurrentDevice(ctx, scope, nil); e != nil {
		t.Fatal("current device", e)
	}
	if e = s.RegisterDevicePushToken(ctx, scope, "owned-fixture-push-token", nil); e != nil {
		t.Fatal("push registration", e)
	}
	if e = s.ClearDevicePushToken(ctx, scope, true, nil); e != nil {
		t.Fatal("push clearing", e)
	}
	events := make(chan NotificationEvent, 32)
	notify, e := s.StartNotifications(ctx, scope, nil, func(_ context.Context, event NotificationEvent) error { events <- event; return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer func() { notify.Stop(); notify.Wait() }()
	wait := func(ch <-chan NotificationEvent, kind NotificationKind, recovery bool) NotificationEvent {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case event := <-ch:
				if event.Kind == kind && event.Reconnected == recovery {
					return event
				}
			case <-deadline.C:
				t.Fatalf("missing notification %d recovery=%v", kind, recovery)
				return NotificationEvent{}
			}
		}
	}
	// Both pre-dial and subscribed recovery reads must occur before mutation.
	wait(events, NotificationSync, true)
	wait(events, NotificationSync, true)
	folder, e := s.SaveFolder(ctx, scope, "", "notification fixture", nil)
	if e != nil {
		t.Fatal(e)
	}
	wait(events, NotificationSync, false)
	if e = s.DeleteFolder(ctx, scope, folder.ID, nil); e != nil {
		t.Fatal(e)
	}
	pending, meta, e := s.client.BeginAuthRequest(ctx, s.email)
	if e != nil {
		t.Fatal("begin auth request", e)
	}
	defer pending.Close()
	if event := wait(events, NotificationAuthRequest, false); event.RequestID != meta.ID {
		t.Fatal("request id")
	}
	if list, e := s.AuthRequests(ctx, scope, true, nil); e != nil || len(list) != 1 {
		t.Fatal("pending", list, e)
	}
	if list, e := s.AuthRequests(ctx, scope, false, nil); e != nil || len(list) != 1 {
		t.Fatal("list", list, e)
	}
	if _, e = s.GetAuthRequest(ctx, scope, meta.ID, nil); e != nil {
		t.Fatal("get", e)
	}
	if _, e = pending.Poll(ctx); e != nil {
		t.Fatal("poll", e)
	}
	anonymous := make(chan NotificationEvent, 8)
	anon, e := pending.StartNotifications(ctx, scope, func(_ context.Context, event NotificationEvent) error { anonymous <- event; return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer func() { anon.Stop(); anon.Wait() }()
	wait(anonymous, NotificationAuthResponse, true)
	wait(anonymous, NotificationAuthResponse, true)
	if e = s.RespondAuthRequest(ctx, result.Vault, meta.ID, meta.PublicKey, true, true, nil); e != nil {
		t.Fatal("approve", e)
	}
	wait(anonymous, NotificationAuthResponse, false)
	wait(events, NotificationAuthResponse, false)
	key, e := pending.TakeUserKey(ctx)
	if e != nil || !bytes.Equal(key, s.key) {
		t.Fatal("unwrapped key", e)
	}
	clear(key)
	rejected, row, e := s.client.BeginAuthRequest(ctx, s.email)
	if e != nil {
		t.Fatal(e)
	}
	defer rejected.Close()
	if e = s.RespondAuthRequest(ctx, result.Vault, row.ID, "", false, true, nil); e != nil {
		t.Fatal("reject", e)
	}
	if _, e = rejected.Poll(ctx); e == nil {
		t.Fatal("rejected request persisted")
	}
	t.Log("1.37.4 device/list/current/push routes; auth create/list/pending/poll/approve/RSA-key/reject; authenticated and anonymous MessagePack loopback verified")
}
