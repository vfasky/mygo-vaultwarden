// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
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

// Explicit opt-in creates and destroys only its own container. No external server,
// credentials, mailbox, Docker volumes, app processes, or clipboard are used.
func TestLiveSMTPInvitations(t *testing.T) {
	if os.Getenv("MYGO_VW_SMTP_TEST") != "1" {
		t.Skip("set MYGO_VW_SMTP_TEST=1 for an owned loopback Docker/SMTP fixture")
	}
	for _, autoEnroll := range []bool{false, true} {
		t.Run(fmt.Sprintf("auto-enroll=%v", autoEnroll), func(t *testing.T) { testLiveSMTPInvitations(t, autoEnroll) })
	}
}

func testLiveSMTPInvitations(t *testing.T, autoEnroll bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "mail"), 0700); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", filepath.Join(dir, "smtp"), "../../tools/invitation-smtp")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("SMTP fixture build: %s %v", output, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	// Docker atomically reserves this port or fails; it never reuses another service.
	base := fmt.Sprintf("http://127.0.0.1:%d/vault-fixture", port)
	name := "mygo-smtp-" + fixtureUUID()
	args := []string{"create", "--name", name, "--label", "mygo.fixture=" + name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "--mount", "type=bind,src=" + dir + ",dst=/fixture", "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN=" + base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "-e", "SMTP_HOST=127.0.0.1", "-e", "SMTP_PORT=1025", "-e", "SMTP_SECURITY=off", "-e", "SMTP_FROM=fixture@example.invalid", "-e", "ORG_GROUPS_ENABLED=false", "--entrypoint", "/bin/sh", "vaultwarden/server:1.37.4", "-c", "/fixture/smtp & exec /start.sh"}
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("owned fixture start: %s %v", output, err)
	}
	id := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, err := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != name {
			t.Errorf("refusing unverified cleanup: %v", err)
			return
		}
		if out, err = exec.CommandContext(cleanup, "docker", "rm", "-fv", id).CombinedOutput(); err != nil {
			t.Errorf("owned container cleanup: %s %v", out, err)
		}
	})
	if output, err := exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); err != nil {
		t.Fatalf("owned fixture start: %s %v", output, err)
	}
	health := &http.Client{Timeout: time.Second}
	ready := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		response, err := health.Get(base + "/alive")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
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
		logs, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "35", id).CombinedOutput()
		t.Fatalf("isolated service readiness timed out: %s", logs)
	}
	owner, _ := liveOrganizationMember(t, ctx, base)
	defer owner.Close()
	member, _ := liveOrganizationMember(t, ctx, base)
	defer member.Close()
	wrong, _ := liveOrganizationMember(t, ctx, base)
	defer wrong.Close()
	syncVault := func(s *Session) *VaultData {
		result, err := s.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.BindSnapshotRevision(result.Scope, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return result.Vault
	}
	ov := syncVault(owner)
	org, err := owner.SaveOrganization(ctx, ov, "", OrganizationSettings{Name: "SMTP fixture", BillingEmail: owner.email, CollectionName: "Fixture collection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ov = syncVault(owner)
	if autoEnroll {
		payload := `{"policy":{"enabled":true,"data":{"autoEnrollEnabled":true}}}`
		status, _, err := owner.client.request(ctx, "PUT", "/api/organizations/"+org.ID+"/policies/8", "application/json", payload, owner.access)
		if err != nil || status != 200 {
			t.Fatal("fixture policy", status, err)
		}
	}
	directory, err := owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err = owner.InviteOrganizationMember(ctx, ov, directory, member.email, 2, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	memberID := ""
	for _, row := range directory.Members() {
		if row.Email == member.email {
			if row.Status != 0 {
				t.Fatal("SMTP invitation was automatically accepted")
			}
			memberID = row.ID
		}
	}
	if memberID == "" {
		t.Fatal("invited membership missing")
	}
	links := capturedInvitationLinks(t, dir, member.email)
	if len(links) != 1 {
		t.Fatalf("want one captured invite, got %d", len(links))
	}
	if err = owner.ChangeOrganizationMember(ctx, ov, directory, memberID, "reinvite", nil, nil); err != nil {
		t.Fatal(err)
	}
	links = capturedInvitationLinks(t, dir, member.email)
	if len(links) != 2 {
		t.Fatalf("want invite and reinvite, got %d", len(links))
	}
	mv := syncVault(member)
	link := links[1]
	if err = member.AcceptOrganizationInvitation(ctx, mv, strings.Replace(link, "/vault-fixture/", "/other/", 1), nil); err != ErrIdentity {
		t.Fatal("base path binding", err)
	}
	if err = wrong.AcceptOrganizationInvitation(ctx, syncVault(wrong), link, nil); err != ErrIdentity {
		t.Fatal("email binding", err)
	}
	duplicate := link + "&token=other"
	if err = member.AcceptOrganizationInvitation(ctx, mv, duplicate, nil); err != ErrValidation {
		t.Fatal("duplicate token", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err = member.AcceptOrganizationInvitation(cancelled, mv, link, nil); err != ErrCancelled {
		t.Fatal("cancelled accept", err)
	}
	parsed, _ := url.Parse(link)
	fragment, _ := url.Parse(parsed.EscapedFragment())
	query := fragment.Query()
	token := query.Get("token")
	query.Set("email", wrong.email)
	fragment.RawQuery = query.Encode()
	parsed.Fragment, parsed.RawFragment = fragment.String(), ""
	if err = wrong.AcceptOrganizationInvitation(ctx, syncVault(wrong), base+"/#"+fragment.String(), nil); err == nil || err == ErrIdentity {
		t.Fatal("server JWT account verification", err)
	}
	query.Set("email", member.email)
	query.Set("token", expiredFixtureInvitation(t, ctx, id, dir, token))
	fragment.RawQuery = query.Encode()
	parsed.Fragment, parsed.RawFragment = fragment.String(), ""
	if err = member.AcceptOrganizationInvitation(ctx, mv, base+"/#"+fragment.String(), nil); err == nil || err == ErrIdentity {
		t.Fatal("server expired JWT verification", err)
	}
	query.Set("token", token)
	// A syntactically JWT-shaped, changed signature must reach server verification
	// and cannot accept the pending membership.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("captured token was not JWT")
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	query.Set("token", strings.Join(parts, "."))
	fragment.RawQuery = query.Encode()
	parsed.Fragment = fragment.String()
	if err = member.AcceptOrganizationInvitation(ctx, mv, base+"/#"+fragment.String(), nil); err == nil {
		t.Fatal("forged signature accepted")
	}
	draft, err := member.PrepareInvitationAcceptance(ctx, mv, link, nil)
	if err != nil {
		t.Fatal("real SMTP policy preparation", err)
	}
	defer draft.Close()
	if draft.RecoveryRequired() != autoEnroll {
		t.Fatal("auto-enroll policy")
	}
	trustedRecovery := ""
	if autoEnroll {
		trustedRecovery, err = owner.OrganizationRecoveryPublicKey(ctx, ov, org.ID, false, nil)
		if err != nil || trustedRecovery == "" {
			t.Fatal("creator recovery key", err)
		}
		if err = member.AcceptPreparedInvitation(ctx, mv, draft, false, trustedRecovery, nil); err != ErrPermission {
			t.Fatal("missing recovery consent", err)
		}
	}
	if err = member.AcceptPreparedInvitation(ctx, mv, draft, autoEnroll, trustedRecovery, nil); err != nil {
		t.Fatal("real SMTP JWT acceptance", err)
	}
	if _, err = member.PrepareInvitationAcceptance(ctx, mv, link, nil); err != ErrInvitationAlreadyAccepted {
		t.Fatal("accepted invitation must be reconciled without another write", err)
	}
	mv = syncVault(member)
	organizations, _, err := member.Organizations(mv)
	if err != nil || len(organizations) != 0 {
		t.Fatal("unconfirmed invite released org key", err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	proof, err := owner.PrepareMemberConfirmation(ctx, ov, directory, memberID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Close()
	trusted, err := member.AccountSharingPublicKey(mv)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ConfirmOrganizationMember(ctx, ov, proof, trusted, nil); err != nil {
		t.Fatal(err)
	}
	mv = syncVault(member)
	organizations, _, err = member.Organizations(mv)
	if err != nil || len(organizations) != 1 || organizations[0].ID != org.ID {
		t.Fatal("confirmed SMTP membership did not unlock organization", err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if _, err = owner.PrepareMemberRole(ctx, ov, directory, memberID, nil); err != ErrMemberRoleGroupsDisabled {
		t.Fatal("disabled group relation preservation guard", err)
	}
	if autoEnroll {
		status, raw, err := owner.client.request(ctx, "GET", "/api/organizations/"+org.ID+"/users/"+memberID+"/reset-password-details", "", "", owner.access)
		if err != nil || status != 200 {
			t.Fatal("enrollment details", status, err)
		}
		var details struct{ ResetPasswordKey, EncryptedPrivateKey string }
		if json.Unmarshal(raw, &details) != nil {
			t.Fatal("recovery details")
		}
		owner.mu.Lock()
		data, err := owner.organizationVaultLocked(ov)
		owner.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		defer data.close()
		der, err := vaultcrypto.DecryptString(details.EncryptedPrivateKey, data.keys[org.ID])
		if err != nil {
			t.Fatal(err)
		}
		defer clear(der)
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		private, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("RSA private key")
		}
		defer clearAccountPrivateKey(private)
		wrapped, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(details.ResetPasswordKey, "3."))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, wrapped, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(plain)
		if !bytes.Equal(plain, member.key) {
			t.Fatal("recovery envelope does not contain this member user key")
		}
	}
	t.Log("owned 1.37.4 with SMTP and UseGroups=false: captured invite/reinvite; signed JWT acceptance; same-server/base-path/email/duplicate/cancel/forged-signature boundaries; trusted SPKI confirmation; organization key availability; auto-enroll:", autoEnroll)
}

func capturedInvitationLinks(t *testing.T, dir, email string) []string {
	t.Helper()
	files, err := os.ReadDir(filepath.Join(dir, "mail"))
	if err != nil {
		t.Fatal(err)
	}
	var links []string
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(dir, "mail", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record struct {
			Recipients []string
			Data       string
		}
		if json.Unmarshal(raw, &record) != nil {
			t.Fatal("SMTP spool decode")
		}
		addressed := false
		for _, recipient := range record.Recipients {
			if recipient == email {
				addressed = true
			}
		}
		if !addressed {
			continue
		}
		message, err := mail.ReadMessage(strings.NewReader(record.Data))
		if err != nil {
			t.Fatal(err)
		}
		kind, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(kind, "multipart/") {
			t.Fatal("expected MIME mail")
		}
		reader := multipart.NewReader(message.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain") {
				continue
			}
			var body io.Reader = part
			if part.Header.Get("Content-Transfer-Encoding") == "quoted-printable" {
				body = quotedprintable.NewReader(part)
			}
			text, err := io.ReadAll(io.LimitReader(body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			candidates := regexp.MustCompile(`https?://[^\s<>]+`).FindAllString(string(text), -1)
			for _, candidate := range candidates {
				if strings.Contains(candidate, "#/accept-organization/") {
					links = append(links, candidate)
				}
			}
		}
	}
	return links
}

// Only the just-created, labelled disposable server's signing key is used to
// make a correctly signed expired token. Never reads a user server or credentials.
func expiredFixtureInvitation(t *testing.T, ctx context.Context, containerID, dir, token string) string {
	t.Helper()
	path := filepath.Join(dir, "fixture-jwt.pem")
	if output, err := exec.CommandContext(ctx, "docker", "cp", containerID+":/data/rsa_key.pem", path).CombinedOutput(); err != nil {
		t.Fatalf("owned fixture signing key: %s %v", output, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("fixture PEM")
	}
	defer clear(block.Bytes)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer clearAccountPrivateKey(key)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("JWT fixture")
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if json.Unmarshal(claimsRaw, &claims) != nil {
		t.Fatal("JWT claims")
	}
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	claimsRaw, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := parts[0] + "." + base64.RawURLEncoding.EncodeToString(claimsRaw)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}
