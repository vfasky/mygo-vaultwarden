// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
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

// Owns a disposable fixed-version loopback server. Never accepts an external URL.
func TestSendRotationLive1374(t *testing.T) {
	if os.Getenv("MYGO_VW_SEND_ROTATION_TEST") != "1" {
		t.Skip("opt-in isolated MYGO_VW_SEND_ROTATION_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	name := "mygo-send-rotation-" + fixtureUUID()
	output, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server:1.37.4").CombinedOutput()
	if err != nil {
		t.Fatalf("owned fixture create: %s %v", output, err)
	}
	id := strings.TrimSpace(string(output))
	t.Logf("owned container %s label mygo.fixture=%s", id, name)
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("fixture ownership verification failed", e)
			return
		}
		if _, e = exec.CommandContext(c, "docker", "rm", "-fv", id).CombinedOutput(); e != nil {
			t.Error("fixture cleanup failed", e)
		} else {
			t.Log("owned container removed")
		}
	})
	if _, err = exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); err != nil {
		t.Fatal("start owned fixture", err)
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
	client, err := NewClient(base, fixtureUUID())
	if err != nil {
		t.Fatal(err)
	}
	email := "rotation-" + fixtureUUID() + "@example.invalid"
	password := []byte("Owned-send-rotation-fixture-3947!")
	defer clear(password)
	verification, err := client.AccountSendRegistrationEmail(ctx, email, "Send rotation fixture")
	if err != nil || verification.EmailSent {
		t.Fatal("registration verification", err)
	}
	if err = client.AccountRegister(ctx, email, password, KDF{Type: 0, Iterations: 100000}, "", verification.Token); err != nil {
		t.Fatal("registration", err)
	}
	verification.Token = ""
	s, err := client.Login(ctx, email, password, nil)
	if err != nil {
		t.Fatal("login", err)
	}
	defer s.Close()
	syncVault := func(s *Session) *VaultData {
		t.Helper()
		r, e := s.Sync(ctx)
		if e != nil {
			t.Fatal("sync", e)
		}
		if e = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); e != nil {
			t.Fatal("accept", e)
		}
		return r.Vault
	}
	vault := syncVault(s)
	links := make([]string, 2)
	defer clear(links)
	sendPasswordFixture := "Owned-send-receiver-password"
	content := bytes.Repeat([]byte("owned file fixture content"), 3000)
	defer clear(content)
	for kind := 0; kind < 2; kind++ {
		draft, e := s.NewSend(vault, kind)
		if e != nil {
			t.Fatal("draft", e)
		}
		draft.Fields = sendTestFields()
		draft.Fields.Type = kind
		draft.Fields.FileName = "fixture.bin"
		draft.Fields.HideEmail = true
		if kind == 0 {
			draft.Fields.Password = &sendPasswordFixture
		}
		var created *SendDraft
		if kind == 0 {
			created, e = s.SaveSend(ctx, draft, nil, 0, nil)
		} else {
			created, e = s.SaveSend(ctx, draft, bytes.NewReader(content), int64(len(content)), nil)
		}
		draft.Close()
		if e != nil {
			t.Fatal("create Send", e)
		}
		links[kind], e = created.ShareLink()
		created.Close()
		if e != nil {
			t.Fatal("share link", e)
		}
		vault = syncVault(s)
	}
	// Test-only composition for an account with actually enumerated empty other
	// resources. This does not attest the final production adapter's coverage.
	adapter := accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
		converted, e := accountEmptyRotation(ctx, in)
		if e != nil {
			return converted, e
		}
		var sync struct {
			Profile          struct{ Organizations, OrganizationsNew []json.RawMessage }
			Ciphers, Folders []json.RawMessage
		}
		if json.Unmarshal(in.Sync, &sync) != nil || sync.Profile.Organizations == nil || sync.Profile.OrganizationsNew == nil || len(sync.Profile.Organizations) != 0 || len(sync.Profile.OrganizationsNew) != 0 || sync.Ciphers == nil || len(sync.Ciphers) != 0 || sync.Folders == nil || len(sync.Folders) != 0 {
			return converted, ErrIdentity
		}
		check := func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
			body, e := read(ctx, "/api/emergency-access/trusted")
			if e != nil {
				return e
			}
			defer clear(body)
			var list struct {
				Data              []json.RawMessage
				ContinuationToken *string
			}
			if json.Unmarshal(body, &list) != nil || list.Data == nil || len(list.Data) != 0 || list.ContinuationToken != nil {
				return ErrIdentity
			}
			return nil
		}
		if e = check(ctx, in.Read); e != nil {
			return converted, e
		}
		converted.Revalidate = check
		converted.Data.Sends, e = ConvertSendRotationResources(ctx, in)
		return converted, e
	})
	oldKey := append([]byte(nil), s.key...)
	defer clear(oldKey)
	oldSync := append([]byte(nil), vault.Sync...)
	defer clear(oldSync)
	plan, err := s.PrepareAccountRotation(ctx, vault, password, adapter, nil)
	if err != nil {
		t.Fatal("prepare", err)
	}
	defer plan.Close()
	var journal []byte
	defer func() { clear(journal) }()
	result, err := s.CommitAccountChange(ctx, plan, string(AccountRotateKey), nil, func(r AccountRecovery) error { var e error; journal, e = json.Marshal(r); return e })
	if err != nil || !result.Confirmed {
		t.Fatal("rotation commit", err)
	}
	var recovery AccountRecovery
	if json.Unmarshal(journal, &recovery) != nil {
		t.Fatal("journal decode")
	}
	defer recovery.Close()
	clear(journal)
	journal = nil
	var request AccountRotationRequest
	if json.Unmarshal(recovery.Request, &request) != nil {
		t.Fatal("request decode")
	}
	freshSession, err := client.Login(ctx, email, password, nil)
	if err != nil {
		t.Fatal("fresh login", err)
	}
	defer freshSession.Close()
	freshVault := syncVault(freshSession)
	if !bytes.Equal(freshSession.key, recovery.NewUserKey) || bytes.Equal(oldKey, freshSession.key) {
		t.Fatal("new key identity")
	}
	report, err := VerifySendRotationResources(ctx, SendRotationVerificationInput{vault.Scope, freshVault.Scope, oldSync, freshVault.Sync, request.Data.Sends, oldKey, recovery.NewUserKey})
	if err != nil || report.State != SendRotationNew || len(report.Resources) != 2 {
		t.Fatal("recovery verification", report.State, err)
	}
	owner, err := freshSession.ListSends(ctx, freshVault.Scope, nil)
	if err != nil || len(owner) != 2 {
		t.Fatal("new owner read", err)
	}
	for _, draft := range owner {
		if draft.Fields.Name != sendTestFields().Name {
			t.Error("owner name decryption")
		}
		if draft.Fields.Type == 0 && draft.Fields.Text != sendTestFields().Text {
			t.Error("owner text decryption")
		}
		if draft.Fields.Type == 1 && draft.Fields.FileName != "fixture.bin" {
			t.Error("owner filename decryption")
		}
		draft.Close()
	}
	if _, err = client.OpenSend(ctx, links[0], ""); err != ErrSendPasswordRequired {
		t.Fatal("rotation cleared password", err)
	}
	text, err := client.OpenSend(ctx, links[0], sendPasswordFixture)
	if err != nil {
		t.Fatal("original protected receiver link", err)
	}
	fields, err := text.Fields()
	text.Close()
	if err != nil || fields.Text != sendTestFields().Text {
		t.Fatal("receiver text", err)
	}
	file, err := client.OpenSend(ctx, links[1], "")
	if err != nil {
		t.Fatal("original file receiver link", err)
	}
	defer file.Close()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve private fixture directory", err)
	}
	target := filepath.Join(dir, "verified-file.bin")
	if err = file.SaveFile(ctx, target); err != nil {
		t.Fatal("binary MAC/decrypt", err)
	}
	actual, err := os.ReadFile(target)
	defer clear(actual)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("binary content mismatch", err)
	}
	// Receiver access advances count/revision; recovery remains verifiable.
	freshVault = syncVault(freshSession)
	report, err = VerifySendRotationResources(ctx, SendRotationVerificationInput{vault.Scope, freshVault.Scope, oldSync, freshVault.Sync, request.Data.Sends, oldKey, recovery.NewUserKey})
	if err != nil || report.State != SendRotationNew {
		t.Fatal("verification after receiver access", report.State, err)
	}
	t.Log("text+file rotated; owner metadata decrypted; original receiver links and password preserved; binary MAC and content verified")
}
