// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLivePolicyExecution(t *testing.T) {
	if os.Getenv("MYGO_VW_POLICY_TEST") != "1" {
		t.Skip("opt-in owned Docker fixture: MYGO_VW_POLICY_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	name := "mygo-policy-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	output, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "-e", "ORG_GROUPS_ENABLED=true", "vaultwarden/server:1.37.4").CombinedOutput()
	if err != nil {
		t.Fatalf("create: %s %v", output, err)
	}
	id := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("unverified fixture cleanup", e)
			return
		}
		if out, e = exec.CommandContext(c, "docker", "rm", "-fv", id).CombinedOutput(); e != nil {
			t.Errorf("cleanup: %s %v", out, e)
		}
	})
	if output, err = exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); err != nil {
		t.Fatalf("start: %s %v", output, err)
	}
	health := &http.Client{Timeout: time.Second}
	ready := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		response, e := health.Get(base + "/alive")
		if e == nil {
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
		t.Fatal("fixture readiness")
	}
	owner, _ := liveOrganizationMember(t, ctx, base)
	defer owner.Close()
	member, pub := liveOrganizationMember(t, ctx, base)
	defer member.Close()
	syncVault := func(s *Session) *VaultData {
		r, e := s.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.BindSnapshotRevision(r.Scope, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		return r.Vault
	}
	ov := syncVault(owner)
	org, err := owner.SaveOrganization(ctx, ov, "", OrganizationSettings{Name: "Policy fixture", BillingEmail: owner.email, CollectionName: "Collection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ov = syncVault(owner)
	directory, err := owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.InviteOrganizationMember(ctx, ov, directory, member.email, 2, nil); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	directory, err = owner.OrganizationMembers(ctx, ov, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	mid := ""
	for _, m := range directory.Members() {
		if m.Email == member.email {
			mid = m.ID
		}
	}
	proof, err := owner.PrepareMemberConfirmation(ctx, ov, directory, mid, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	if err = owner.ConfirmOrganizationMember(ctx, ov, proof, base64.StdEncoding.EncodeToString(der), nil); err != nil {
		t.Fatal(err)
	}
	proof.Close()
	directory.Close()
	mv := syncVault(member)
	note := CipherFields{Type: 2, Name: "Existing personal note"}
	personal, err := member.CreatePersonalCipher(ctx, mv.Scope, note, nil)
	if err != nil {
		t.Fatal("initial create", err)
	}
	fields, err := DecryptCipherDocument(personal, member.key)
	if err != nil {
		t.Fatal(err)
	}
	// Fixture-only policy seeding. This is not the pending native policy editor.
	seedPolicy := func(kind int, value any) {
		body, _ := json.Marshal(map[string]any{"policy": map[string]any{"enabled": true, "data": value}})
		status, _, e := owner.client.request(ctx, "PUT", fmt.Sprintf("/api/organizations/%s/policies/%d", org.ID, kind), "application/json", string(body), owner.access)
		if e != nil || status != 200 {
			t.Fatal("policy seed", status, e)
		}
	}
	seedPolicy(5, nil)
	// No UI sync occurs between changing the server policy and the next write.
	if _, err = member.CreatePersonalCipher(ctx, mv.Scope, note, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("new authority did not reject create", err)
	}
	fields.Name = "Disallowed update"
	if _, err = member.UpdatePersonalCipher(ctx, mv.Scope, personal, fields, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("ownership update", err)
	}
	mv = syncVault(member)
	if _, _, err = member.ReadPersonalCipher(mv, fields.ID); err != nil {
		t.Fatal("ownership existing read", err)
	}
	for _, action := range []CipherAction{CipherTrash, CipherRestore} {
		current, _, e := member.ReadPersonalCipher(mv, fields.ID)
		if e != nil {
			t.Fatal(e)
		}
		if e = member.ChangePersonalCipherStateAuthorized(ctx, mv.Scope, current, action, nil, nil); e != nil {
			t.Fatal("ownership state must remain permitted", action, e)
		}
		mv = syncVault(member)
	}
	if err = member.ChangePersonalCiphers(ctx, mv.Scope, mv, []string{fields.ID}, CipherArchive, nil, nil); err != nil {
		t.Fatal("ownership bulk archive", err)
	}
	if _, err = owner.CreatePersonalCipher(ctx, ov.Scope, note, nil); err != nil {
		t.Fatal("owner exemption", err)
	}
	_, collections, err := owner.Organizations(ov)
	if err != nil || len(collections) == 0 {
		t.Fatal("organization collection", err)
	}
	collectionID := collections[0].ID
	card, err := owner.CreateOrganizationCipher(ctx, ov, org.ID, collectionID, CipherFields{Type: 3, Name: "Existing organization card"}, nil)
	if err != nil {
		t.Fatal("initial organization card", err)
	}
	ov = syncVault(owner)
	var cardMeta struct{ ID string }
	if json.Unmarshal(card.JSON, &cardMeta) != nil {
		t.Fatal("card response")
	}
	card, cardFields, err := owner.ReadOrganizationCipher(ov, cardMeta.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedPolicy(15, []int{3})
	if _, err = owner.CreatePersonalCipher(ctx, ov.Scope, CipherFields{Type: 3, Name: "Restricted card"}, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("owner restricted type bypass", err)
	}
	if _, err = owner.CreatePersonalCipher(ctx, ov.Scope, note, nil); err != nil {
		t.Fatal("unrestricted type rejected", err)
	}
	if _, err = owner.CreateOrganizationCipher(ctx, ov, org.ID, collectionID, CipherFields{Type: 3, Name: "Restricted organization card"}, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("organization create restriction", err)
	}
	if _, err = owner.UpdateOrganizationCipher(ctx, ov, card, cardFields, nil, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("organization update restriction", err)
	}
	if _, err = owner.CreateOrganizationCipher(ctx, ov, org.ID, collectionID, note, nil); err != nil {
		t.Fatal("organization unrestricted type", err)
	}
	seedPolicy(15, []int{3, 2})
	if err = member.ChangePersonalCiphers(ctx, mv.Scope, mv, []string{fields.ID}, CipherTrash, nil, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("restricted bulk state", err)
	}
	seedPolicy(15, []int{3})
	t.Run("protected-state-authorization", func(t *testing.T) {
		testLiveProtectedItem(t, ctx, owner, ov.Scope, []byte("Public-member-fixture-password!"))
	})
	t.Run("bulk-preflight-and-server-partial", func(t *testing.T) {
		testLiveFoldersAndBulk(t, ctx, owner, ov.Scope)
	})
	t.Log("owned 1.37.4: authoritative policy sync; member ownership denial and owner exemption; restricted personal and organization create/update denied without UI resync; unrestricted organization note succeeds; type5 allows state/bulk and type15 blocks bulk; no offline or policy editor claim")
}
