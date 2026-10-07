// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLiveAttachments(t *testing.T) {
	if os.Getenv("MYGO_VW_ATTACHMENT_TEST") != "1" {
		t.Skip("opt-in owned Docker fixture: MYGO_VW_ATTACHMENT_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "mygo-attachment-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	output, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server:1.37.4").CombinedOutput()
	if err != nil {
		t.Fatalf("create: %s %v", output, err)
	}
	id := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", `{{index .Config.Labels "mygo.fixture"}}`, id).CombinedOutput()
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
			response.Body.Close()
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
	syncVault := func() *VaultData {
		result, err := owner.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Privileged Go-only receipt: this does not test Swift durable publication.
		if err := owner.AcceptAuthenticatedSnapshot(result.Vault, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return result.Vault
	}
	vault := syncVault()
	personal, err := owner.CreatePersonalCipher(ctx, vault.Scope, CipherFields{Type: 2, Name: "Attachment fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := documentObject(personal)
	personalID := object["id"].(string)
	vault = syncVault()
	org, err := owner.SaveOrganization(ctx, vault, "", OrganizationSettings{Name: "Attachment organization", BillingEmail: owner.email, CollectionName: "Attachment collection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	vault = syncVault()
	_, collections, err := owner.Organizations(vault)
	if err != nil || len(collections) != 1 {
		t.Fatal("collections", err)
	}
	shared, err := owner.CreateOrganizationCipher(ctx, vault, org.ID, collections[0].ID, CipherFields{Type: 2, Name: "Organization attachment"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, _ = documentObject(shared)
	for _, cipherID := range []string{personalID, object["id"].(string)} {
		for _, size := range []int{0, 8*1024*1024 + 3} {
			t.Run(fmt.Sprintf("%s/%d", map[bool]string{true: "personal", false: "organization"}[cipherID == personalID], size), func(t *testing.T) {
				vault = syncVault()
				input := bytes.Repeat([]byte{173}, size)
				file, err := os.CreateTemp(t.TempDir(), "input-")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(input); err != nil {
					t.Fatal(err)
				}
				result, err := owner.UploadAttachment(ctx, vault, cipherID, "fixture.bin", file, nil, nil)
				if err != nil || !result.Reconciled {
					t.Fatalf("upload %+v %v", result, err)
				}
				vault = syncVault()
				rows, err := owner.Attachments(ctx, vault, cipherID, nil, nil)
				if err != nil || len(rows) != 1 || rows[0].ID != result.AttachmentID || rows[0].FileName != "fixture.bin" {
					t.Fatal("list", rows, err)
				}
				var actual []byte
				proof, err := owner.DownloadAttachment(ctx, vault, cipherID, result.AttachmentID, nil, nil, func(file *os.File, n int64) error {
					if n != int64(size) {
						t.Error("plaintext size", n)
					}
					var err error
					actual, err = io.ReadAll(file)
					return err
				})
				if err != nil || !bytes.Equal(actual, input) {
					t.Fatal("download", err)
				}
				published := false
				if err := owner.PublishAttachment(ctx, proof, nil, func() error { published = true; return nil }); err != nil || !published {
					t.Fatal("publication", err)
				}
				if err := owner.DeleteAttachment(ctx, vault, cipherID, result.AttachmentID, nil, nil); err != nil {
					t.Fatal("delete", err)
				}
				vault = syncVault()
				rows, err = owner.Attachments(ctx, vault, cipherID, nil, nil)
				if err != nil || len(rows) != 0 {
					t.Fatal("delete reconciliation", rows, err)
				}
			})
		}
	}
	t.Run("member-permission-revocation", func(t *testing.T) {
		vault = syncVault()
		sharedID := object["id"].(string)
		file, e := os.CreateTemp(t.TempDir(), "member-input-")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write([]byte("organization secret")); e != nil {
			t.Fatal(e)
		}
		created, e := owner.UploadAttachment(ctx, vault, sharedID, "member.txt", file, nil, nil)
		if e != nil {
			t.Fatal(e)
		}
		member, public := liveOrganizationMember(t, ctx, base)
		defer member.Close()
		vault = syncVault()
		directory, e := owner.OrganizationMembers(ctx, vault, org.ID, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e = owner.InviteOrganizationMember(ctx, vault, directory, member.email, 2, nil); e != nil {
			t.Fatal(e)
		}
		directory.Close()
		directory, e = owner.OrganizationMembers(ctx, vault, org.ID, nil)
		if e != nil {
			t.Fatal(e)
		}
		memberID := ""
		for _, m := range directory.Members() {
			if m.Email == member.email {
				memberID = m.ID
			}
		}
		proof, e := owner.PrepareMemberConfirmation(ctx, vault, directory, memberID, nil)
		if e != nil {
			t.Fatal(e)
		}
		der, _ := x509.MarshalPKIXPublicKey(public)
		if e = owner.ConfirmOrganizationMember(ctx, vault, proof, base64.StdEncoding.EncodeToString(der), nil); e != nil {
			t.Fatal(e)
		}
		proof.Close()
		directory.Close()
		setAccess := func(readOnly, hidden bool) {
			// Fixture seeding changes server collection permissions only; product
			// attachment calls must independently observe the resulting authority.
			body, _ := json.Marshal(map[string]any{"type": 2, "accessAll": false, "groups": []string{}, "collections": []any{map[string]any{"id": collections[0].ID, "readOnly": readOnly, "hidePasswords": hidden, "manage": false}}})
			status, _, e := owner.client.request(ctx, "PUT", "/api/organizations/"+org.ID+"/users/"+memberID, "application/json", string(body), owner.access)
			if e != nil || status != 200 {
				t.Fatal("fixture permissions", status, e)
			}
		}
		memberVault := func() *VaultData {
			r, e := member.Sync(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if e := member.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); e != nil {
				t.Fatal(e)
			}
			return r.Vault
		}
		setAccess(true, false)
		mv := memberVault()
		publication, e := member.DownloadAttachment(ctx, mv, sharedID, created.AttachmentID, nil, nil, func(file *os.File, n int64) error {
			data, e := io.ReadAll(file)
			if string(data) != "organization secret" {
				t.Error("readonly download")
			}
			return e
		})
		if e != nil || publication == nil {
			t.Fatal("readonly read", e)
		}
		if e := member.DeleteAttachment(ctx, mv, sharedID, created.AttachmentID, nil, nil); !errors.Is(e, ErrPermission) {
			t.Fatal("readonly delete", e)
		}
		setAccess(false, true)
		if _, e := member.Attachments(ctx, mv, sharedID, nil, nil); e == nil {
			t.Fatal("stale hidden permission allowed metadata")
		}
		mv = memberVault()
		if _, e := member.DownloadAttachment(ctx, mv, sharedID, created.AttachmentID, nil, nil, func(*os.File, int64) error { t.Error("hidden plaintext exposed"); return nil }); !errors.Is(e, ErrPermission) {
			t.Fatal("hidden download", e)
		}
		setAccess(false, false)
		mv = memberVault()
		vault = syncVault()
		directory, e = owner.OrganizationMembers(ctx, vault, org.ID, nil)
		if e != nil {
			t.Fatal(e)
		}
		if e := owner.ChangeOrganizationMember(ctx, vault, directory, memberID, "revoke", nil, nil); e != nil {
			t.Fatal(e)
		}
		directory.Close()
		if _, e := member.DownloadAttachment(ctx, mv, sharedID, created.AttachmentID, nil, nil, func(*os.File, int64) error { t.Error("revoked plaintext exposed"); return nil }); e == nil {
			t.Fatal("revoked member download")
		}
	})
}
