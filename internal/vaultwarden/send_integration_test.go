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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSendLive1374(t *testing.T) {
	if os.Getenv("MYGO_VW_SEND_TEST") != "1" {
		t.Skip("opt-in owned Docker fixture MYGO_VW_SEND_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "mygo-send-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	output, e := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server:1.37.4").CombinedOutput()
	if e != nil {
		t.Fatalf("owned fixture create: %s %v", output, e)
	}
	id := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("fixture ownership verification", e)
			return
		}
		if out, e = exec.CommandContext(c, "docker", "rm", "-fv", id).CombinedOutput(); e != nil {
			t.Errorf("fixture cleanup %s %v", out, e)
		}
	})
	if out, e := exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); e != nil {
		t.Fatalf("start: %s %v", out, e)
	}
	ready := false
	health := &http.Client{Timeout: time.Second}
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
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
		t.Fatal("fixture readiness")
	}
	s, _ := liveOrganizationMember(t, ctx, base)
	defer s.Close()
	syncVault := func() *VaultData {
		r, e := s.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		return r.Vault
	}
	v := syncVault()
	password := "send-fixture-password"
	d, e := s.NewSend(v, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	d.Fields = sendTestFields()
	d.Fields.Password = &password
	limit := 3
	d.Fields.MaxAccessCount = &limit
	text, e := s.SaveSend(ctx, d, nil, 0, nil)
	if e != nil {
		t.Fatal("create text", e)
	}
	defer text.Close()
	link, e := text.ShareLink()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.client.OpenSend(ctx, link, ""); e != ErrSendPasswordRequired {
		t.Fatal("password required", e)
	}
	if _, e = s.client.OpenSend(ctx, link, "incorrect"); e != ErrSendPasswordInvalid {
		t.Fatal("password invalid", e)
	}
	r, e := s.client.OpenSend(ctx, link, password)
	if e != nil {
		t.Fatal("receive text", e)
	}
	f, e := r.Fields()
	r.Close()
	if e != nil || f.Text != d.Fields.Text {
		t.Fatal("text decryption", e)
	}
	rows, e := s.ListSends(ctx, v.Scope, nil)
	if e != nil || len(rows) != 1 || rows[0].AccessCount() != 1 {
		t.Fatal("list", e)
	}
	edit := rows[0]
	edit.Fields.Text = "edited secret"
	edit.Fields.Disabled = true
	updated, e := s.SaveSend(ctx, edit, nil, 0, nil)
	edit.Close()
	if e != nil {
		t.Fatal("edit", e)
	}
	updated.Close()
	if _, e = s.client.OpenSend(ctx, link, password); e == nil {
		t.Fatal("disabled accessible")
	}
	rows, e = s.ListSends(ctx, v.Scope, nil)
	if e != nil {
		t.Fatal(e)
	}
	edit = rows[0]
	edit.Fields.Disabled = false
	updated, e = s.SaveSend(ctx, edit, nil, 0, nil)
	edit.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RemoveSendPassword(ctx, updated, nil); e != nil {
		t.Fatal("remove password", e)
	}
	updated.Close()
	r, e = s.client.OpenSend(ctx, link, "")
	if e != nil {
		t.Fatal("password removed", e)
	}
	f, _ = r.Fields()
	r.Close()
	if f.Text != "edited secret" {
		t.Fatal("edit text content")
	}
	r, e = s.client.OpenSend(ctx, link, "")
	if e != nil {
		t.Fatal("last access", e)
	}
	r.Close()
	if _, e = s.client.OpenSend(ctx, link, ""); e == nil {
		t.Fatal("access limit bypass")
	}
	v = syncVault()
	file, e := s.NewSend(v, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	file.Fields = sendTestFields()
	file.Fields.Type = 1
	file.Fields.FileName = "private-file.bin"
	file.Fields.Password = &password
	content := bytes.Repeat([]byte("file secret payload"), 6554)
	created, e := s.SaveSend(ctx, file, bytes.NewReader(content), int64(len(content)), nil)
	if e != nil {
		t.Fatal("create file", e)
	}
	defer created.Close()
	fileLink, e := created.ShareLink()
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := s.client.OpenSend(ctx, fileLink, password)
	if e != nil {
		t.Fatal("receive file", e)
	}
	defer receiver.Close()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(dir, "received.bin")
	if e = receiver.SaveFile(ctx, target); e != nil {
		t.Fatal("save file", e)
	}
	actual, e := os.ReadFile(target)
	if e != nil || !bytes.Equal(actual, content) {
		t.Fatal("file content", e)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Fatal("file mode")
	}
	rows, e = s.ListSends(ctx, v.Scope, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 2 {
		t.Fatal("list count")
	}
	for _, row := range rows {
		if e = s.DeleteSend(ctx, row, nil); e != nil {
			t.Fatal("delete", e)
		}
		row.Close()
	}
	if _, e = s.client.OpenSend(ctx, fileLink, password); e == nil {
		t.Fatal("deleted accessible")
	}
	v = syncVault()
	expiring, e := s.NewSend(v, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer expiring.Close()
	expiring.Fields = sendTestFields()
	expiration := time.Now().UTC().Add(500 * time.Millisecond)
	expiring.Fields.ExpirationDate = &expiration
	expired, e := s.SaveSend(ctx, expiring, nil, 0, nil)
	if e != nil {
		t.Fatal("expiring create", e)
	}
	defer expired.Close()
	expiredLink, e := expired.ShareLink()
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(time.Until(expiration) + 20*time.Millisecond):
	}
	if _, e = s.client.OpenSend(ctx, expiredLink, ""); e != ErrNotFound {
		t.Fatal("expired Send accessible", e)
	}
	if e = s.DeleteSend(ctx, expired, nil); e != nil {
		t.Fatal("expired Send delete", e)
	}
	t.Log("owned Vaultwarden 1.37.4: text create/read/edit/disable/password-remove/limit/expiration, file multipart/receiver/decrypt/private publication, owner list/delete passed; container cleanup registered by ID+label")
}
