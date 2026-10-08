// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveRotationCipherResources(t *testing.T) {
	if os.Getenv("MYGO_ROTATION_CIPHER_TEST") != "1" {
		t.Skip("opt-in owned Vaultwarden 1.37.4 fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "mygo-rotation-cipher-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	output, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055").CombinedOutput()
	if err != nil {
		t.Fatalf("create %s: %v", output, err)
	}
	container := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", `{{index .Config.Labels "mygo.fixture"}}`, container).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("ownership check", e)
			return
		}
		if out, e = exec.CommandContext(c, "docker", "rm", "-fv", container).CombinedOutput(); e != nil {
			t.Errorf("cleanup %s: %v", out, e)
		}
	})
	if output, err = exec.CommandContext(ctx, "docker", "start", container).CombinedOutput(); err != nil {
		t.Fatalf("start %s: %v", output, err)
	}
	client := &http.Client{Timeout: time.Second}
	ready := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		response, e := client.Get(base + "/alive")
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
	output, err = exec.CommandContext(ctx, "docker", "inspect", "--format", `{{.Image}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}`, container).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	identity := strings.Fields(string(output))
	if len(identity) != 3 || identity[1] != "1.37.4" || identity[2] != "7c188967e7a467b19b2757bc3326f9cf3ccae327" {
		t.Fatal("image identity")
	}
	t.Log("owned fixture", container, strings.TrimSpace(string(output)))
	owner, _ := liveOrganizationMember(t, ctx, base)
	defer owner.Close()
	email := owner.email
	api := owner.client
	var rotationPosts atomic.Int32
	transport := api.http.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	api.http.Transport = accountRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" && r.URL.Path == "/api/accounts/key-management/rotate-user-account-keys" {
			rotationPosts.Add(1)
		}
		return transport.RoundTrip(r)
	})
	oldKey := bytes.Clone(owner.key)
	defer clear(oldKey)
	syncVault := func() *VaultData {
		result, e := owner.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = owner.AcceptAuthenticatedSnapshot(result.Vault, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		return result.Vault
	}
	vault := syncVault()
	// Real legacy owner-key cipher with every FIDO secret and history/custom data.
	doc, err := NewPersonalCipher(CipherFields{Type: 1, Name: "rotation legacy", Login: map[string]any{"username": "user", "password": "password", "uris": []any{map[string]any{"uri": "https://example.invalid/path", "match": json.Number("3")}}}}, owner.key, owner.account)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := documentObject(doc)
	itemKey, _ := cipherItemKey(object, owner.key)
	if err = transformCipher(object, itemKey, false); err != nil {
		t.Fatal(err)
	}
	clear(itemKey)
	fido, _ := migrationFIDOFixture(t, owner.key)
	object["login"].(map[string]any)["fido2Credentials"] = []any{fido}
	object["fields"] = []any{map[string]any{"name": "custom", "value": "value", "type": json.Number("1")}}
	object["passwordHistory"] = []any{map[string]any{"password": "old-password", "lastUsedDate": "2026-01-01T00:00:00Z"}}
	delete(object, "key")
	if err = transformCompleteCipher(object, owner.key, true); err != nil {
		t.Fatal(err)
	}
	doc.JSON = mustRotationCipherJSON(object)
	owner.mu.Lock()
	operation, finish, err := owner.beginOperationLocked(ctx)
	if err == nil {
		doc, err = owner.createCipherDocumentLocked(operation, doc, nil)
		finish()
	}
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fields, err := DecryptCipherDocument(doc, owner.key)
	if err != nil {
		t.Fatal(err)
	}
	id := fields.ID
	plain := bytes.Repeat([]byte("legacy-binary\x00\xff"), 4096)
	liveLegacyAttachment(t, ctx, owner, id, owner.key, owner.key, "rotation.bin", plain)
	vault = syncVault()
	probe := AccountRotationInput{Scope: vault.Scope, Sync: vault.Sync, OldUserKey: owner.key, NewUserKey: bytes.Repeat([]byte{82}, 64)}
	readiness, err := AnalyzeAccountRotationCipherResources(ctx, probe)
	if err != nil || readiness.Ready || len(readiness.Preparations) != 1 {
		t.Fatal("readiness", err)
	}
	if _, err = ConvertAccountRotationCipherResources(ctx, probe); err == nil {
		t.Fatal("unprepared rotation accepted")
	}
	originalID := readiness.Preparations[0].AttachmentID
	blocked, prepareErr := owner.PrepareAccountRotation(ctx, vault, []byte("Public-member-fixture-password!"), accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
		_, err := ConvertAccountRotationCipherResources(ctx, in)
		return AccountRotationConversion{}, err
	}), nil)
	var preparation *RotationCipherPreparationError
	if blocked != nil || !errors.As(prepareErr, &preparation) || rotationPosts.Load() != 0 {
		t.Fatal("unprepared account path must issue zero rotation POST", prepareErr)
	}
	upgraded, err := owner.UpgradeLegacyCipherAttachment(ctx, vault, id, originalID, true, nil, nil)
	if err != nil || !upgraded.Reconciled {
		t.Fatal("upgrade", err)
	}
	vault = syncVault()
	checked, err := owner.VerifyAndDeleteLegacyCipherAttachment(ctx, vault, id, originalID, upgraded.ReplacementID, true, nil, nil)
	if err != nil || !checked.OriginalDeleted {
		t.Fatal("verify delete", err)
	}
	vault = syncVault()
	// Include a modern item and a folder; keep a legacy cipher in trash to verify
	// the rotation update retains deleted_at instead of restoring it.
	if _, err = owner.CreatePersonalCipher(ctx, vault.Scope, CipherFields{Type: 2, Name: "modern item"}, nil); err != nil {
		t.Fatal(err)
	}
	folderName, _ := EncryptString([]byte("rotation folder"), owner.key)
	folderBody, _ := json.Marshal(map[string]string{"name": folderName})
	status, _, err := owner.client.request(ctx, "POST", "/api/folders", "application/json", string(folderBody), owner.access)
	if err != nil || status != 200 {
		t.Fatal("folder", status, err)
	}
	vault = syncVault()
	source, _, err := owner.ReadPersonalCipherAuthorized(vault, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ChangePersonalCipherStateAuthorized(ctx, vault.Scope, source, CipherTrash, nil, nil); err != nil {
		t.Fatal("trash", err)
	}
	vault = syncVault()
	originalSync := bytes.Clone(vault.Sync)
	defer clear(originalSync)
	adapter := accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
		converted, _ := accountEmptyRotation(ctx, in)
		var raw struct {
			Profile struct{ Organizations, OrganizationsNew []json.RawMessage }
			Sends   []json.RawMessage
		}
		if json.Unmarshal(in.Sync, &raw) != nil || raw.Profile.Organizations == nil || raw.Profile.OrganizationsNew == nil || len(raw.Profile.Organizations) != 0 || len(raw.Profile.OrganizationsNew) != 0 || raw.Sends == nil || len(raw.Sends) != 0 {
			return converted, ErrIdentity
		}
		check := func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
			body, e := read(ctx, "/api/emergency-access/trusted")
			if e != nil {
				return e
			}
			var contacts struct {
				Data              []json.RawMessage
				ContinuationToken *string
			}
			if json.Unmarshal(body, &contacts) != nil || contacts.Data == nil || len(contacts.Data) != 0 || contacts.ContinuationToken != nil {
				return ErrIdentity
			}
			return nil
		}
		if e := check(ctx, in.Read); e != nil {
			return converted, e
		}
		converted.Revalidate = check
		resources, e := ConvertAccountRotationCipherResources(ctx, in)
		if e != nil {
			return converted, e
		}
		converted.Data.Ciphers = resources.Ciphers
		converted.Data.Folders = resources.Folders
		return converted, nil
	})
	// Cross the JWT timestamp boundary deliberately; freshness must accept only
	// changed download URLs, without relying on two syncs happening in one second.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(1100 * time.Millisecond):
	}
	plan, err := owner.PrepareAccountRotation(ctx, vault, []byte("Public-member-fixture-password!"), adapter, nil)
	if err != nil {
		t.Fatal("prepare rotation", err)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(1100 * time.Millisecond):
	}
	var recoveryJSON []byte
	result, err := owner.CommitAccountChange(ctx, plan, string(AccountRotateKey), nil, func(r AccountRecovery) error { recoveryJSON = mustAccountJSON(t, r); return nil })
	plan.Close()
	if err != nil || !result.Confirmed {
		t.Fatal("rotation", err)
	}
	var recovery AccountRecovery
	if json.Unmarshal(recoveryJSON, &recovery) != nil {
		t.Fatal("recovery decode")
	}
	clear(recoveryJSON)
	defer recovery.Close()
	var request AccountRotationRequest
	if json.Unmarshal(recovery.Request, &request) != nil {
		t.Fatal("request decode")
	}
	fresh, err := api.Login(ctx, email, []byte("Public-member-fixture-password!"), nil)
	if err != nil {
		t.Fatal("fresh login", err)
	}
	defer fresh.Close()
	owner = fresh
	vault = syncVault()
	verified, err := VerifyAccountRotationCipherResources(ctx, RotationCipherVerificationInput{Scope: vault.Scope, CurrentScope: vault.Scope, OriginalSync: originalSync, CurrentSync: vault.Sync, Target: RotationCipherResources{Ciphers: request.Data.Ciphers, Folders: request.Data.Folders}, OldUserKey: oldKey, NewUserKey: recovery.NewUserKey})
	if err != nil || verified.State != RotationCipherNew {
		t.Fatalf("fresh verify %s: %v; %+v", verified.State, err, verified.Resources)
	}
	document, fields, err := owner.ReadPersonalCipherAuthorized(vault, id, nil)
	if err != nil || fields.DeletedDate == nil {
		t.Fatal("trash retained", err)
	}
	object, _ = documentObject(document)
	if err = transformCompleteCipher(object, owner.key, false); err != nil {
		t.Fatal("new key FIDO decrypt", err)
	}
	credential := object["login"].(map[string]any)["fido2Credentials"].([]any)[0].(map[string]any)
	if credential["counter"] != "42" || credential["keyValue"] != "base64url-pkcs8" {
		t.Fatal("FIDO changed")
	}
	attachment := object["attachments"].([]any)[0].(map[string]any)
	binaryKey, err := DecryptString(attachment["key"].(string), owner.key)
	if err != nil || bytes.Equal(binaryKey, oldKey) || len(binaryKey) != 64 {
		t.Fatal("owner key masquerading as independent key", err)
	}
	clear(binaryKey)
	var downloaded []byte
	publication, err := owner.DownloadAttachmentForBackup(ctx, vault, id, upgraded.ReplacementID, nil, nil, func(file *os.File, _ int64) error { var e error; downloaded, e = io.ReadAll(file); return e })
	if err != nil || publication == nil || !bytes.Equal(downloaded, plain) {
		t.Fatal("new key binary MAC/content", err)
	}
	clear(downloaded)
	if rotationPosts.Load() != 1 {
		t.Fatal("rotation POST count", rotationPosts.Load())
	}
	t.Log("real 1.37.4: legacy owner-key file -> keyed replacement -> both-file verification/delete -> fresh sync -> cipher/folder rotation -> fresh login, complete resource verification, FIDO and trash binary MAC/content verified; no old user key used as attachment key")
}
