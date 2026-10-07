// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLiveGroupManagement(t *testing.T) {
	if os.Getenv("MYGO_VW_GROUP_TEST") != "1" {
		t.Skip("opt-in owned Docker fixture: MYGO_VW_GROUP_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	name := "mygo-groups-" + fixtureUUID()
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
	org, err := owner.SaveOrganization(ctx, ov, "", OrganizationSettings{Name: "Group fixture", BillingEmail: owner.email, CollectionName: "Collection"}, nil)
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
	ov = syncVault(owner)
	draft, err := owner.GroupDetails(ctx, ov, org.ID, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	draft.Name = "Group true"
	draft.AccessScope = GroupAllCollections
	for i := range draft.Access {
		if !draft.Access[i].Collection && draft.Access[i].ID == mid {
			draft.Access[i].Assigned = true
		}
	}
	consent := draft.Confirm()
	if err = owner.SaveGroup(ctx, ov, draft, consent, nil, nil); err != nil {
		t.Fatal(err)
	}
	consent.Close()
	draft.Close()
	rows, err := owner.OrganizationGroups(ctx, ov, org.ID, nil)
	if err != nil || len(rows) != 1 {
		t.Fatal("list", err)
	}
	gid := rows[0].ID
	isolationCalls := 0
	isolate := func(SessionCheckpoint) error { isolationCalls++; return nil } // API ordering only; durable production bridge is tested separately.
	for _, target := range []GroupScope{GroupSelectedCollections, GroupAllCollections, GroupSelectedCollections} {
		before := syncVault(member)
		_, cols, e := member.Organizations(before)
		if e != nil {
			t.Fatal(e)
		}
		if target == GroupSelectedCollections && len(cols) != 1 {
			t.Fatal("prior full access missing", len(cols))
		}
		if target == GroupAllCollections && len(cols) != 0 {
			t.Fatal("selected empty granted access", len(cols))
		}
		draft, err = owner.GroupDetails(ctx, ov, org.ID, gid, nil)
		if err != nil {
			t.Fatal(err)
		}
		if draft.AccessScope != GroupScopeUnset {
			t.Fatal("GET inferred accessAll")
		}
		draft.Name = "Explicit scope update"
		if err = owner.SaveGroup(ctx, ov, draft, nil, isolate, nil); err != ErrValidation {
			t.Fatal("rename silently changes scope", err)
		}
		draft.AccessScope = target
		consent = draft.Confirm()
		if err = owner.SaveGroup(ctx, ov, draft, consent, isolate, nil); err != nil {
			t.Fatal(err)
		}
		consent.Close()
		draft.Close()
	}
	mv := syncVault(member)
	if _, err = member.GroupDetails(ctx, mv, org.ID, gid, nil); err != ErrPermission {
		t.Fatal("member administration allowed", err)
	}
	draft, err = owner.GroupDetails(ctx, ov, org.ID, gid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.DeleteGroup(ctx, ov, draft, isolate, nil); err != nil {
		t.Fatal(err)
	}
	draft.Close()
	rows, err = owner.OrganizationGroups(ctx, ov, org.ID, nil)
	if err != nil || len(rows) != 0 || isolationCalls != 4 {
		t.Fatal("delete/isolation", err, isolationCalls)
	}
	changeRole := func(role int) {
		ov = syncVault(owner)
		dir, e := owner.OrganizationMembers(ctx, ov, org.ID, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		rd, e := owner.PrepareMemberRole(ctx, ov, dir, mid, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer rd.Close()
		rd.Role = role
		if e = owner.SaveMemberRole(ctx, ov, rd, nil, nil, nil); e != nil {
			t.Fatal(e)
		}
	}
	changeRole(1)
	mv = syncVault(member)
	adminDraft, e := member.GroupDetails(ctx, mv, org.ID, "", nil)
	if e != nil {
		t.Fatal("admin create denied", e)
	}
	adminDraft.Name = "Admin group"
	adminDraft.AccessScope = GroupSelectedCollections
	adminConsent := adminDraft.Confirm()
	if e = member.SaveGroup(ctx, mv, adminDraft, adminConsent, nil, nil); e != nil {
		t.Fatal(e)
	}
	adminConsent.Close()
	adminDraft.Close()
	adminRows, e := member.OrganizationGroups(ctx, mv, org.ID, nil)
	if e != nil || len(adminRows) != 1 {
		t.Fatal("admin list", e)
	}
	adminDraft, e = member.GroupDetails(ctx, mv, org.ID, adminRows[0].ID, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = member.DeleteGroup(ctx, mv, adminDraft, isolate, nil); e != nil {
		t.Fatal("admin delete", e)
	}
	adminDraft.Close()
	changeRole(4)
	mv = syncVault(member)
	if _, e = member.GroupDetails(ctx, mv, org.ID, "", nil); e != ErrPermission {
		t.Fatal("manager group admin allowed", e)
	}
	t.Log("owned 1.37.4: owner/admin CRUD, explicit true→false→true→false, member collection projection, missing-scope rejection, member/manager denial; mock isolation callback only")
}
