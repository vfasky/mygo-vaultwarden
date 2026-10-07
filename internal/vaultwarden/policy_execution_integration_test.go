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
		// Go-only equivalent of a verified publication receipt. This privileged
		// call does not exercise the Swift bridge or platform authentication.
		if e = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); e != nil {
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
	t.Run("uri-default-projection", func(t *testing.T) {
		login := CipherFields{Type: 1, Name: "URI defaults fixture", Login: map[string]any{"username": "fixture", "password": "fixture-only-secret", "uris": []any{
			map[string]any{"uri": "https://login.example.invalid/path", "match": nil},
			map[string]any{"uri": "https://explicit.example.invalid/path", "match": 0},
		}}}
		doc, e := member.CreatePersonalCipher(ctx, mv.Scope, login, nil)
		if e != nil {
			t.Fatal(e)
		}
		var meta struct{ ID string }
		_ = json.Unmarshal(doc.JSON, &meta)
		for match := 0; match <= 5; match++ {
			seedPolicy(16, map[string]any{"uriMatchDetection": match})
			r, e := member.Sync(ctx)
			if e != nil {
				t.Fatal(e)
			}
			found := false
			for _, c := range r.Credentials {
				if c.ID != meta.ID {
					continue
				}
				found = true
				want := 1
				if match == 0 || match == 1 || match == 3 {
					want = 2
				}
				if len(c.URIs) != want || c.URIs[want-1].Match != 0 || c.URIs[want-1].SourceIndex == nil || *c.URIs[want-1].SourceIndex != 1 {
					t.Fatal("explicit/default URI projection", match, c.URIs)
				}
				if want == 2 && c.URIs[0].Match != match {
					t.Fatal("inherited URI projection", match)
				}
			}
			clear(r.Session)
			if r.PasswordUnlock != nil {
				clear(r.PasswordUnlock.Key)
			}
			if !found {
				t.Fatal("login missing")
			}
		}
		seedPolicy(16, map[string]any{"uriMatchDetection": 0})
		mv = syncVault(member)
	})
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
	t.Run("policy-sync-autofill", func(t *testing.T) {
		ov = syncVault(owner)
		login := CipherFields{Type: 1, Name: "Policy projection login", Login: map[string]any{"username": "fixture", "password": "fixture-only-secret"}}
		personalLogin, e := owner.CreatePersonalCipher(ctx, ov.Scope, login, nil)
		if e != nil {
			t.Fatal(e)
		}
		organizationLogin, e := owner.CreateOrganizationCipher(ctx, ov, org.ID, collectionID, login, nil)
		if e != nil {
			t.Fatal(e)
		}
		var personalID, organizationID struct{ ID string }
		_ = json.Unmarshal(personalLogin.JSON, &personalID)
		_ = json.Unmarshal(organizationLogin.JSON, &organizationID)
		check := func(want bool) {
			r, e := owner.Sync(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(r.Session)
			if r.PasswordUnlock != nil {
				defer clear(r.PasswordUnlock.Key)
			}
			seen := map[string]bool{}
			for _, c := range r.Credentials {
				seen[c.ID] = true
			}
			if seen[personalID.ID] != want || seen[organizationID.ID] != want {
				t.Fatal("type15 projection disagrees with policy", want)
			}
			revision := fixtureUUID()
			if e = owner.AcceptAuthenticatedSnapshot(r.Vault, revision); e != nil {
				t.Fatal("authenticated policy snapshot", e)
			}
			if e = owner.ValidateAuthenticatedSnapshot(r.Vault, revision); e != nil {
				t.Fatal(e)
			}
			personalEntries, e := owner.PersonalEntries(r.Vault)
			if e != nil {
				t.Fatal(e)
			}
			organizationEntries, e := owner.OrganizationEntries(r.Vault)
			if e != nil {
				t.Fatal(e)
			}
			visible := map[string]bool{}
			for _, entry := range append(personalEntries, organizationEntries...) {
				visible[entry.ID] = true
			}
			if visible[personalID.ID] != want || visible[organizationID.ID] != want {
				t.Fatal("offline list disagrees with policy")
			}
			_, _, personalErr := owner.ReadPersonalCipher(r.Vault, personalID.ID)
			_, _, organizationErr := owner.ReadOrganizationCipher(r.Vault, organizationID.ID, nil)
			if want && (personalErr != nil || organizationErr != nil) {
				t.Fatal("permitted offline read", personalErr, organizationErr)
			}
			if !want && (!errors.Is(personalErr, ErrPermission) || !errors.Is(organizationErr, ErrPermission)) {
				t.Fatal("restricted offline read", personalErr, organizationErr)
			}
		}
		check(true)
		seedPolicy(15, []int{1, 3})
		check(false)
		seedPolicy(15, []int{3})
		check(true)
	})
	t.Run("policy-management-twelve-types", func(t *testing.T) {
		for _, definition := range OrganizationPolicyDefinitions() {
			ov = syncVault(owner)
			draft, e := owner.OrganizationPolicy(ctx, ov, org.ID, definition.Type, nil)
			if e != nil {
				t.Fatal(definition.Type, e)
			}
			draft.Enabled = false
			record := draft.PendingMutation()
			isolated := *ov
			isolated.Version = 2
			isolated.PendingPolicyMutations = []PendingPolicyMutation{record}
			isolated.QuarantinedOrganizations = []string{org.ID}
			checkpointed := false
			e = owner.SaveOrganizationPolicy(ctx, ov, draft, draft.Confirm(), func(SessionCheckpoint) error { checkpointed = true; return nil }, nil)
			draft.Close()
			if e != nil || !checkpointed {
				t.Fatal("product policy PUT", definition.Type, e)
			}
			// This is the Go-only equivalent of a verified Swift write-ahead receipt.
			if e = owner.AcceptAuthenticatedSnapshot(&isolated, fixtureUUID()); e != nil {
				t.Fatal(e)
			}
			synced, e := owner.Sync(ctx)
			if e != nil {
				t.Fatal(e)
			}
			review, e := owner.ReviewPendingPolicy(synced, record)
			if e != nil || review.Enabled() {
				t.Fatal("review current policy", definition.Type, e)
			}
			preview := *synced.Vault
			preview.Version = 2
			preview.PendingPolicyMutations = []PendingPolicyMutation{record}
			preview.QuarantinedOrganizations = []string{org.ID}
			previewRevision := fixtureUUID()
			if e = owner.AcceptAuthenticatedSnapshot(&preview, previewRevision); e != nil {
				t.Fatal(e)
			}
			if e = owner.BindPolicyRecoveryReview(review, &preview, previewRevision); e != nil {
				t.Fatal(e)
			}
			fresh, e := owner.SyncForPolicyRecovery(ctx, &preview, review, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = owner.ValidatePolicyRecovery(fresh, review); e != nil {
				t.Fatal("recovery", e)
			}
			review.Close()
			if e = owner.AcceptAuthenticatedSnapshot(fresh.Vault, fixtureUUID()); e != nil {
				t.Fatal(e)
			}
			clear(synced.Session)
			clear(fresh.Session)
			if synced.PasswordUnlock != nil {
				clear(synced.PasswordUnlock.Key)
			}
			if fresh.PasswordUnlock != nil {
				clear(fresh.PasswordUnlock.Key)
			}
		}
	})
	t.Log("owned 1.37.4: authoritative policy sync; personal/organization type15 AutoFill projection revokes and recovers; privileged Go snapshot receipt validates; offline personal/organization list and item reads enforce type15 and recover; twelve product policy GET/PUT types and explicit current-state recovery verified with Go-only receipts; no Swift bridge or installed UI claim")
}
