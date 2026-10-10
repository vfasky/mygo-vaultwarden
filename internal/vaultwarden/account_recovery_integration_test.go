// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Fully owned fixture: no supplied server URL, external SMTP, production
// credentials or existing container. Cleanup verifies the full ID and label.
func recoveryLiveFixture(t *testing.T, ctx context.Context) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "mail"), 0700); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", filepath.Join(dir, "smtp"), "../../tools/invitation-smtp")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %s %v", out, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d/recovery-fixture", port)
	name := "mygo-recovery-" + fixtureUUID()
	args := []string{"create", "--name", name, "--label", "mygo.fixture=" + name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "--mount", "type=bind,src=" + dir + ",dst=/fixture", "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN=" + base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "-e", "SMTP_HOST=127.0.0.1", "-e", "SMTP_PORT=1025", "-e", "SMTP_SECURITY=off", "-e", "SMTP_FROM=fixture@example.invalid", "-e", "LOGIN_RATELIMIT_MAX_BURST=100", "-e", "EMERGENCY_REQUEST_TIMEOUT_SCHEDULE=*/2 * * * * *", "--entrypoint", "/bin/sh", "vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055", "-c", "/fixture/smtp & exec /start.sh"}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("owned fixture create: %s %v", out, err)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != name {
			t.Error("cleanup ownership check failed", err)
			return
		}
		if out, err = exec.CommandContext(cleanup, "docker", "rm", "-fv", id).CombinedOutput(); err != nil {
			t.Errorf("cleanup: %s %v", out, err)
		}
	})
	if out, err = exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); err != nil {
		t.Fatalf("fixture start: %s %v", out, err)
	}
	t.Log("owned container", id, "fixed 1.37.4 digest; only loopback SMTP/HTTP")
	client := &http.Client{Timeout: time.Second}
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(base + "/alive")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				return base, dir, id
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
	t.Fatal("owned fixture readiness failed")
	return "", "", ""
}
func emergencyCapturedToken(t *testing.T, dir, email string) (string, string) {
	t.Helper()
	files, err := os.ReadDir(filepath.Join(dir, "mail"))
	if err != nil {
		t.Fatal(err)
	}
	for i := len(files) - 1; i >= 0; i-- {
		raw, err := os.ReadFile(filepath.Join(dir, "mail", files[i].Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Recipients []string
			Data       string
		}
		if json.Unmarshal(raw, &record) != nil {
			t.Fatal("spool")
		}
		found := false
		for _, r := range record.Recipients {
			found = found || r == email
		}
		if !found {
			continue
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(record.Data)))
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range regexp.MustCompile(`https?://[^\s<>"']+`).FindAllString(string(decoded), -1) {
			if !strings.Contains(candidate, "accept-emergency") {
				continue
			}
			parsed, err := url.Parse(strings.ReplaceAll(candidate, "&amp;", "&"))
			if err != nil {
				continue
			}
			fragment, err := url.Parse(parsed.EscapedFragment())
			if err != nil {
				continue
			}
			q := fragment.Query()
			id := q.Get("id")
			if id == "" {
				id = q.Get("emergencyAccessId")
			}
			if id != "" && q.Get("token") != "" {
				return id, q.Get("token")
			}
		}
	}
	t.Fatal("no captured emergency invitation")
	return "", ""
}
func TestLiveRecoveryLifecycle(t *testing.T) {
	if os.Getenv("MYGO_RECOVERY_SMTP_TEST") != "1" {
		t.Skip("opt in to owned 1.37.4 loopback SMTP recovery fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	base, dir, containerID := recoveryLiveFixture(t, ctx)
	grantor, _ := liveOrganizationMember(t, ctx, base)
	defer grantor.Close()
	grantee, public := liveOrganizationMember(t, ctx, base)
	defer grantee.Close()
	wrong, _ := liveOrganizationMember(t, ctx, base)
	defer wrong.Close()
	syncVault := func(s *Session) *VaultData {
		r, err := s.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return r.Vault
	}
	gv, rv := syncVault(grantor), syncVault(grantee)
	// Real enabled/empty probe; no generic HTTP400 acceptance.
	probeStatus, probeBody, probeErr := grantor.client.request(ctx, "GET", emergencyAvailabilityPath, "", "", grantor.access)
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	if _, probeErr = recoveryAvailabilityResponse(probeStatus, probeBody); probeErr != nil {
		t.Fatal("enabled empty probe", probeErr)
	}
	commit := func(s *Session, p *RecoveryPlan) {
		t.Helper()
		defer p.Close()
		r, err := s.CommitRecoveryOperation(ctx, p, p.ConfirmationText(), nil, func(record RecoveryDispatch) error {
			if record.Actor.Account != s.account || record.OperationID == "" {
				t.Fatal("binding")
			}
			return nil
		})
		if err != nil || !r.Confirmed {
			t.Fatal("commit", r.Kind, err)
		}
	}
	prepare := func(s *Session, v *VaultData, r EmergencyRequest) *RecoveryPlan {
		t.Helper()
		p, err := s.PrepareEmergencyOperation(ctx, v, r, nil)
		if err != nil {
			t.Fatal("prepare", r.Action, err)
		}
		return p
	}
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "invite", Email: grantee.email, Type: 0, WaitTimeDays: 7}))
	id, token := emergencyCapturedToken(t, dir, grantee.email)
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "reinvite", ID: id, Trusted: true}))
	expired := expiredFixtureInvitation(t, ctx, containerID, dir, token)
	for _, attempt := range []struct {
		s     *Session
		v     *VaultData
		token string
	}{{wrong, syncVault(wrong), token}, {grantee, rv, expired}} {
		p := prepare(attempt.s, attempt.v, EmergencyRequest{Action: "accept", ID: id, Token: attempt.token})
		r, err := attempt.s.CommitRecoveryOperation(ctx, p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil })
		p.Close()
		if err == nil || !r.Unknown {
			t.Fatal("invalid token/recipient accepted")
		}
	}
	commit(grantee, prepare(grantee, rv, EmergencyRequest{Action: "accept", ID: id, Token: token}))
	der, _ := x509.MarshalPKIXPublicKey(public)
	trusted := base64.StdEncoding.EncodeToString(der)
	if _, err := grantor.PrepareEmergencyOperation(ctx, gv, EmergencyRequest{Action: "confirm", ID: id, Trusted: true, TrustedPublicKey: "bad"}, nil); err == nil {
		t.Fatal("bad trust")
	}
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "confirm", ID: id, Trusted: true, TrustedPublicKey: trusted}))
	trust := RecoveryRotationTrust{Users: map[string]string{grantee.account: trusted}}
	// Deliberately omit one confirmed key: the server rejects before key writes.
	grantor, gv = liveRecoveryRotate(t, ctx, grantor, gv, trust, true, syncVault)
	defer grantor.Close()
	grantor, gv = liveRecoveryRotate(t, ctx, grantor, gv, trust, false, syncVault)
	defer grantor.Close()
	if _, err := grantor.CreatePersonalCipher(ctx, gv.Scope, CipherFields{Type: 1, Name: "Emergency read-only fixture", Login: map[string]any{"username": "fixture-user", "password": "fixture-secret"}}, nil); err != nil {
		t.Fatal("create emergency view item", err)
	}
	gv = syncVault(grantor)
	commit(grantee, prepare(grantee, rv, EmergencyRequest{Action: "initiate", ID: id}))
	if err := grantee.WithEmergencyView(ctx, rv, id, true, nil, func([]CipherFields) error { t.Fatal("waiting view callback"); return nil }); err == nil {
		t.Fatal("waiting bypass")
	}
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "reject", ID: id, Trusted: true}))
	commit(grantee, prepare(grantee, rv, EmergencyRequest{Action: "initiate", ID: id}))
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "approve", ID: id, Trusted: true}))
	if err := grantee.WithEmergencyView(ctx, rv, id, true, nil, func(rows []CipherFields) error {
		if len(rows) != 1 || rows[0].Name != "Emergency read-only fixture" || rows[0].Login["password"] != "fixture-secret" || rows[0].Edit {
			t.Error("wrong or editable emergency view item")
		}
		return nil
	}); err != nil {
		t.Fatal("view", err)
	}
	commit(grantor, prepare(grantor, gv, EmergencyRequest{Action: "update", ID: id, Trusted: true, Type: 1, WaitTimeDays: 0}))
	password := []byte("Recovered-new-passphrase-827!")
	oldKey := bytes.Clone(grantor.key)
	defer clear(oldKey)
	plan, err := grantee.PrepareEmergencyTakeover(ctx, rv, id, password, nil)
	if err != nil {
		t.Fatal("takeover prepare", err)
	}
	commit(grantee, plan)
	fresh, err := grantor.client.Login(ctx, grantor.email, password, nil)
	if err != nil {
		t.Fatal("takeover login", err)
	}
	defer fresh.Close()
	if !bytes.Equal(fresh.key, oldKey) {
		t.Fatal("takeover changed user key")
	}
	t.Log("SMTP invite/reinvite, expired token/wrong identity, trusted confirm, waiting rejection, reject/initiate/approve, view, takeover, retained user key verified; manual approval, not natural waiting")
	if os.Getenv("MYGO_PERSONAL_RELEASE_ONLY") != "1" {
		testLiveAdministratorRecovery(t, ctx, dir, fresh, grantee, syncVault, commit)
	}
	syncVault(fresh)
	testLiveDisabledEmergencyHistory(t, ctx, dir, containerID, fresh)
}

func testLiveAdministratorRecovery(t *testing.T, ctx context.Context, dir string, owner, member *Session, syncVault func(*Session) *VaultData, commit func(*Session, *RecoveryPlan)) {
	t.Helper()
	ov := syncVault(owner)
	org, err := owner.SaveOrganization(ctx, ov, "", OrganizationSettings{Name: "Recovery fixture", BillingEmail: owner.email, CollectionName: "Fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ov = syncVault(owner)
	status, _, err := owner.client.request(ctx, "PUT", "/api/organizations/"+org.ID+"/policies/8", "application/json", `{"policy":{"enabled":true,"data":{"autoEnrollEnabled":false}}}`, owner.access)
	if err != nil || status != 200 {
		t.Fatal("recovery policy", status, err)
	}
	directory, err := owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err = owner.InviteOrganizationMember(ctx, ov, directory, member.email, 2, nil); err != nil {
		t.Fatal(err)
	}
	links := capturedInvitationLinks(t, dir, member.email)
	if len(links) == 0 {
		t.Fatal("org invite")
	}
	mv := syncVault(member)
	if err = member.AcceptOrganizationInvitation(ctx, mv, links[len(links)-1], nil); err != nil {
		t.Fatal(err)
	}
	directory, err = owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	memberID := ""
	for _, m := range directory.Members() {
		if m.UserID == member.account {
			memberID = m.ID
		}
	}
	confirmation, err := owner.PrepareMemberConfirmation(ctx, ov, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, err := owner.memberPublicKeyLocked(ctx, OrganizationMember{UserID: member.account}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ConfirmOrganizationMember(ctx, ov, confirmation, public, nil); err != nil {
		t.Fatal(err)
	}
	mv = syncVault(member)
	orgPublic, err := owner.OrganizationRecoveryPublicKey(ctx, ov, org.ID, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(want bool) {
		t.Helper()
		p, err := member.PrepareRecoveryEnrollment(ctx, mv, org.ID, want, orgPublic, AccountSensitiveInput{Password: []byte("Public-member-fixture-password!")}, nil)
		if err != nil {
			t.Fatal("enroll prepare", err)
		}
		commit(member, p)
		mv = syncVault(member)
	}
	enroll(true)
	enroll(false)
	enroll(true)
	member, mv = liveRecoveryRotate(t, ctx, member, mv, RecoveryRotationTrust{Organizations: map[string]string{org.ID: orgPublic}}, false, syncVault)
	defer member.Close()
	ov = syncVault(owner)
	password := []byte("Administrator-recovered-password-982!")
	key := bytes.Clone(member.key)
	defer clear(key)
	p, err := owner.PrepareAdministratorRecovery(ctx, ov, org.ID, memberID, orgPublic, password, true, true, nil)
	if err != nil {
		t.Fatal("admin prepare", err)
	}
	commit(owner, p)
	fresh, err := member.client.Login(ctx, member.email, password, nil)
	if err != nil {
		t.Fatal("admin login", err)
	}
	defer fresh.Close()
	if !bytes.Equal(fresh.key, key) {
		t.Fatal("admin key changed")
	}
	_ = syncVault(fresh)
	t.Log("member enrollment/withdrawal/re-enrollment; organization RSA unwrap; admin password+MFA reset with real SMTP notification; new login and same user key verified")
}
