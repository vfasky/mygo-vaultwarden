// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLiveVaultFinishing(t *testing.T) {
	if os.Getenv("MYGO_VW_FINISHING_TEST") != "1" {
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
	name := "mygo-finishing-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	output, err := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055").CombinedOutput()
	if err != nil {
		t.Fatalf("create: %s %v", output, err)
	}
	container := strings.TrimSpace(string(output))
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(c, "docker", "inspect", "--format", `{{index .Config.Labels "mygo.fixture"}}`, container).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("fixture ownership check", e)
			return
		}
		if out, e = exec.CommandContext(c, "docker", "rm", "-fv", container).CombinedOutput(); e != nil {
			t.Errorf("cleanup: %s %v", out, e)
		}
	})
	if output, err = exec.CommandContext(ctx, "docker", "start", container).CombinedOutput(); err != nil {
		t.Fatalf("start: %s %v", output, err)
	}
	httpClient := &http.Client{Timeout: time.Second}
	ready := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		response, e := httpClient.Get(base + "/alive")
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
	if output, err = exec.CommandContext(ctx, "docker", "inspect", "--format", `{{.Image}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}`, container).CombinedOutput(); err == nil {
		t.Log("owned image", strings.TrimSpace(string(output)))
		identity := strings.Fields(string(output))
		if len(identity) != 3 || identity[1] != "1.37.4" || identity[2] != "7c188967e7a467b19b2757bc3326f9cf3ccae327" {
			t.Fatal("fixture image identity mismatch")
		}
	} else {
		t.Fatal("fixture image inspection", err)
	}
	owner, _ := liveOrganizationMember(t, ctx, base)
	defer owner.Close()
	syncVault := func() *VaultData {
		result, err := owner.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = owner.AcceptAuthenticatedSnapshot(result.Vault, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		return result.Vault
	}
	vault := syncVault()
	// Seed a real legacy no-item-key cipher, including complete FIDO2 wire fields.
	doc, err := NewPersonalCipher(CipherFields{Type: 1, Name: "legacy FIDO attachment", Login: map[string]any{"username": "fixture", "password": "fixture-password", "uris": []any{map[string]any{"uri": "https://example.invalid/path", "match": json.Number("3")}}}}, owner.key, owner.account)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := documentObject(doc)
	key, _ := cipherItemKey(object, owner.key)
	if err = transformCipher(object, key, false); err != nil {
		t.Fatal(err)
	}
	clear(key)
	plainFIDO, _ := migrationFIDOFixture(t, owner.key)
	expectedFIDO := map[string]any{}
	for key, value := range plainFIDO {
		expectedFIDO[key] = value
	}
	login := object["login"].(map[string]any)
	login["fido2Credentials"] = []any{plainFIDO}
	login["uri"] = login["uris"].([]any)[0].(map[string]any)["uri"]
	object["fields"] = []any{map[string]any{"name": "custom", "value": "value", "type": json.Number("1")}}
	object["passwordHistory"] = []any{map[string]any{"password": "old-password", "lastUsedDate": "2026-01-01T00:00:00Z"}}
	delete(object, "key")
	if err = transformCompleteCipher(object, owner.key, true); err != nil {
		t.Fatal(err)
	}
	doc.JSON, _ = json.Marshal(object)
	owner.mu.Lock()
	operation, finish, err := owner.beginOperationLocked(ctx)
	if err == nil {
		doc, err = owner.createCipherDocumentLocked(operation, doc, nil)
		finish()
	}
	owner.mu.Unlock()
	if err != nil {
		t.Fatal("legacy create", err)
	}
	fields, err := DecryptCipherDocument(doc, owner.key)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := fields.ID
	// Construct old owner-key binary data through the fixed legacy route.
	plain := bytes.Repeat([]byte("legacy-binary\x00\xff"), 4096)
	liveLegacyAttachment(t, ctx, owner, sourceID, owner.key, owner.key, "same-name.bin", plain)
	vault = syncVault()
	rows, err := owner.CipherAttachmentMigrationInfo(vault, sourceID, nil)
	if err != nil {
		documents, _ := vault.Documents(vault.Scope)
		for _, document := range documents {
			object, _ := documentObject(document)
			if object["id"] != sourceID {
				continue
			}
			for label, value := range map[string]any{"cipher": object, "login": object["login"], "permissions": object["permissions"]} {
				if fields, ok := value.(map[string]any); ok {
					names := []string{}
					for name := range fields {
						names = append(names, name)
					}
					t.Log("schema", label, names)
				}
			}
			if rows, ok := object["attachments"].([]any); ok {
				for _, raw := range rows {
					names := []string{}
					for name := range raw.(map[string]any) {
						names = append(names, name)
					}
					t.Log("attachment schema", names)
				}
			}
		}
	}
	if err != nil || len(rows) != 1 || !rows[0].Legacy {
		t.Fatal("legacy metadata", err)
	}
	upgraded, err := owner.UpgradeLegacyCipherAttachment(ctx, vault, sourceID, rows[0].ID, true, nil, nil)
	if err != nil || !upgraded.Reconciled {
		t.Fatal("upgrade", upgraded, err)
	}
	vault = syncVault()
	checked, err := owner.VerifyAndDeleteLegacyCipherAttachment(ctx, vault, sourceID, rows[0].ID, upgraded.ReplacementID, true, nil, nil)
	if err != nil || !checked.OriginalDeleted {
		t.Fatal("verify upgrade", checked, err)
	}
	vault = syncVault()
	// Personal complete backup, parser and staged copy including actual binaries.
	var archive bytes.Buffer
	publication, err := owner.WriteResourceBackup(ctx, vault, []string{sourceID}, "", nil, true, &archive, nil)
	if err != nil {
		t.Fatal("personal resource backup", err)
	}
	if err = owner.PublishResourceBackup(ctx, publication, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	parse := func(data []byte) *ResourceImportPlan {
		file, e := os.CreateTemp("", "mygo-live-resource-*")
		if e != nil {
			t.Fatal(e)
		}
		defer os.Remove(file.Name())
		if _, e = file.Write(data); e != nil {
			t.Fatal(e)
		}
		file.Seek(0, io.SeekStart)
		plan, e := ParseResourceImport(ctx, file)
		if e != nil {
			t.Fatal(e)
		}
		return plan
	}
	plan := parse(archive.Bytes())
	defer plan.Clear()
	copied, err := owner.CopyPersonalResourceMetadata(ctx, vault, plan, nil, nil)
	if err != nil {
		t.Fatal("resource copy metadata", err)
	}
	copiedFields, err := DecryptCipherDocument(copied, owner.key)
	if err != nil {
		t.Fatal(err)
	}
	vault = syncVault()
	uploaded, err := owner.UploadResource(ctx, vault, copiedFields.ID, plan, 0, true, nil, nil)
	if err != nil {
		t.Fatal("restore copy binary", err)
	}
	vault = syncVault()
	if err = owner.VerifyRestoredResource(ctx, vault, copiedFields.ID, uploaded.AttachmentID, plan, 0, nil, nil); err != nil {
		t.Fatal("verify copy", err)
	}
	copyDocument, _, err := owner.ReadPersonalCipherAuthorized(vault, copiedFields.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ChangePersonalCipherStateAuthorized(ctx, vault.Scope, copyDocument, CipherTrash, nil, nil); err != nil {
		t.Fatal(err)
	}
	vault = syncVault()
	var personalTrashArchive bytes.Buffer
	publication, err = owner.WriteResourceBackup(ctx, vault, []string{copiedFields.ID}, "", nil, true, &personalTrashArchive, nil)
	if err != nil {
		t.Fatal("personal trash export", err)
	}
	if err = owner.PublishResourceBackup(ctx, publication, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	personalTrashPlan := parse(personalTrashArchive.Bytes())
	defer personalTrashPlan.Clear()
	if len(personalTrashPlan.DeferredTrashIDs()) != 1 {
		t.Fatal("personal trash state lost")
	}
	if err = owner.VerifyRestoredResource(ctx, vault, copiedFields.ID, uploaded.AttachmentID, personalTrashPlan, 0, nil, nil); err != nil {
		t.Fatal("personal trash binary", err)
	}
	_, stillTrashed, err := owner.ReadPersonalCipherAuthorized(vault, copiedFields.ID, nil)
	if err != nil || stillTrashed.DeletedDate == nil {
		t.Fatal("personal backup restored source", err)
	}
	if os.Getenv("MYGO_PERSONAL_RELEASE_ONLY") == "1" {
		t.Log("Vaultwarden 1.37.4 personal complete resource backup, parser, staged copy and binary verification passed; organization product flows deferred")
		return
	}
	// Create an organization and migrate the original legacy cipher. Recovery
	// bytes survive independently of the live Session's generated item key.
	organization, err := owner.SaveOrganization(ctx, vault, "", OrganizationSettings{Name: "Finishing organization", BillingEmail: owner.email, CollectionName: "Finishing collection"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	vault = syncVault()
	_, collections, err := owner.Organizations(vault)
	if err != nil || len(collections) == 0 {
		t.Fatal(err)
	}
	source, sourceFields, err := owner.ReadPersonalCipherAuthorized(vault, sourceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	var recovery []byte
	shared, err := owner.SharePersonalCipherWithRecovery(ctx, vault, organization.ID, collections[0].ID, source, sourceFields, nil, nil, func(data []byte) error { recovery = bytes.Clone(data); return nil })
	if err != nil {
		t.Fatal("legacy share attachments2", err)
	}
	defer clear(recovery)
	vault = syncVault()
	inspection, err := owner.InspectCipherShareRecovery(ctx, vault, recovery, nil, nil)
	if err == nil && inspection.CipherState != "新组织" {
		payload, e := decodeCipherShareRecovery(recovery, vault.Scope, owner.key)
		if e == nil {
			expected, _ := documentObject(CipherDocument{JSON: payload.Target})
			docs, _ := vault.Documents(vault.Scope)
			for _, doc := range docs {
				actual, _ := documentObject(doc)
				if actual["id"] == sourceID {
					left, right := shareRecoveryComparable(expected), shareRecoveryComparable(actual)
					for key, value := range left {
						if !reflect.DeepEqual(value, right[key]) {
							t.Log("recovery differing field", key)
						}
					}
					for key := range right {
						if _, ok := left[key]; !ok {
							t.Log("recovery additional field", key)
						}
					}
				}
			}
			clear(payload.Original)
			clear(payload.Target)
		}
	}
	if err != nil || inspection.CipherState != "新组织" || inspection.CanRepair {
		t.Fatal("real share classification", inspection, err)
	}
	orgData, err := owner.organizationVaultLocked(vault)
	if err != nil {
		t.Fatal(err)
	}
	sharedObject, _ := documentObject(shared)
	orgKey := bytes.Clone(orgData.keys[organization.ID])
	defer clear(orgKey)
	sharedKey, err := cipherItemKey(sharedObject, orgData.keys[organization.ID])
	orgData.close()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sharedKey)
	if err = transformCompleteCipher(sharedObject, sharedKey, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sharedObject["login"].(map[string]any)["fido2Credentials"].([]any)[0], expectedFIDO) {
		t.Fatal("real FIDO fields lost")
	}
	// A legacy binary can still use the organization owner key even though its
	// cipher now has an independent item key. Duplicate names must not be IDs.
	liveLegacyAttachment(t, ctx, owner, sourceID, orgKey, sharedKey, "same-name.bin", []byte("different organization legacy contents"))
	vault = syncVault()
	// Organization resource copies use the selected source, without invoking a
	// whole-organization export or copying unrelated records.
	var orgCopyArchive bytes.Buffer
	publication, err = owner.WriteOrganizationCipherResourceCopy(ctx, vault, sourceID, nil, &orgCopyArchive, nil)
	if err != nil {
		t.Fatal("org copy preflight", err)
	}
	if err = owner.PublishResourceBackup(ctx, publication, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	orgCopyPlan := parse(orgCopyArchive.Bytes())
	defer orgCopyPlan.Clear()
	orgCopy, err := owner.CopyOrganizationResourceMetadata(ctx, vault, sourceID, organization.ID, collections[0].ID, orgCopyPlan, nil, nil)
	if err != nil {
		t.Fatal("org copy metadata", err)
	}
	var orgCopyIdentity struct{ ID string }
	json.Unmarshal(orgCopy.JSON, &orgCopyIdentity)
	vault = syncVault()
	if len(orgCopyPlan.Resources()) != 2 {
		t.Fatal("organization legacy resource omitted")
	}
	for index := range orgCopyPlan.Resources() {
		orgCopyUpload, err := owner.UploadResource(ctx, vault, orgCopyIdentity.ID, orgCopyPlan, index, true, nil, nil)
		if err != nil {
			t.Fatal("org copy binary", err)
		}
		vault = syncVault()
		if err = owner.VerifyRestoredResource(ctx, vault, orgCopyIdentity.ID, orgCopyUpload.AttachmentID, orgCopyPlan, index, nil, nil); err != nil {
			t.Fatal("org copy verify", err)
		}
	}
	orgCopy, orgCopyFields, err := owner.ReadOrganizationCipher(vault, orgCopyIdentity.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	orgCopyFields.Name = "distinct organization copy"
	if _, err = owner.UpdateOrganizationCipher(ctx, vault, orgCopy, orgCopyFields, nil, nil); err != nil {
		t.Fatal(err)
	}
	vault = syncVault()
	// Real organization trash reads must not issue restore or change the source.
	if _, err = owner.ChangeOrganizationCiphers(ctx, vault, organization.ID, []string{sourceID}, CipherTrash, nil, nil); err != nil {
		t.Fatal("org trash", err)
	}
	vault = syncVault()
	archive.Reset()
	publication, err = owner.WriteResourceBackup(ctx, vault, nil, organization.ID, nil, true, &archive, nil)
	if err != nil {
		t.Fatal("organization trash resource export", err)
	}
	if err = owner.PublishResourceBackup(ctx, publication, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	organizationPlan := parse(archive.Bytes())
	defer organizationPlan.Clear()
	if len(organizationPlan.Resources()) != 4 || len(organizationPlan.ItemStates()) != 2 {
		t.Fatal("organization resources not retained")
	}
	originalIndex := -1
	for i, resource := range organizationPlan.Resources() {
		if resource.CipherID == sourceID && resource.AttachmentID == upgraded.ReplacementID {
			originalIndex = i
		}
	}
	if originalIndex < 0 {
		t.Fatal("original missing from archive")
	}
	if err = owner.VerifyRestoredResource(ctx, vault, sourceID, upgraded.ReplacementID, organizationPlan, originalIndex, nil, nil); err != nil {
		t.Fatal("org trash download", err)
	}
	if err = owner.DeleteAttachment(ctx, vault, sourceID, upgraded.ReplacementID, nil, nil); err == nil {
		t.Fatal("trash write unexpectedly allowed")
	}
	vault = syncVault()
	_, end, err := owner.ReadOrganizationCipher(vault, sourceID, nil)
	if err != nil || end.DeletedDate == nil {
		t.Fatal("export restored source", err)
	}
	metadataPlan, err := organizationPlan.OrganizationRestoreMetadata()
	if err != nil {
		t.Fatal(err)
	}
	defer metadataPlan.Clear()
	mappings := map[string]string{}
	for _, collection := range metadataPlan.Collections() {
		mappings[collection.ID] = collections[0].ID
	}
	imported, err := owner.ImportOrganizationBackup(ctx, vault, organization.ID, metadataPlan, mappings, true, nil)
	if err != nil {
		t.Fatal("organization resource metadata import", err)
	}
	if imported.ImportReconciliation == nil {
		t.Fatal("missing import observations")
	}
	targets := map[string]string{}
	for _, item := range imported.ImportReconciliation.Items {
		if item.Verified {
			targets[item.SourceID] = item.ServerID
		}
	}
	if len(targets) != 2 {
		t.Fatal("organization import remained unverified")
	}
	vault = syncVault()
	for index, resource := range organizationPlan.Resources() {
		target := targets[resource.CipherID]
		upload, err := owner.UploadResource(ctx, vault, target, organizationPlan, index, true, nil, nil)
		if err != nil {
			t.Fatal("organization resource restore", err)
		}
		vault = syncVault()
		if err = owner.VerifyRestoredResource(ctx, vault, target, upload.AttachmentID, organizationPlan, index, nil, nil); err != nil {
			t.Fatal("organization resource restore verification", err)
		}
	}
	for _, state := range organizationPlan.ItemStates() {
		if state.Deleted {
			if _, err = owner.ChangeOrganizationCiphers(ctx, vault, organization.ID, []string{targets[state.SourceID]}, CipherTrash, nil, nil); err != nil {
				t.Fatal("restore imported trash state", err)
			}
			vault = syncVault()
			_, fields, err := owner.ReadOrganizationCipher(vault, targets[state.SourceID], nil)
			if err != nil || fields.DeletedDate == nil {
				t.Fatal("imported trash state not verified", err)
			}
		}
	}
	if os.Getenv("MYGO_BW_CLI") != "" {
		cliSession, _ := liveOrganizationMember(t, ctx, base)
		defer cliSession.Close()
		initial, err := cliSession.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = cliSession.AcceptAuthenticatedSnapshot(initial.Vault, fixtureUUID()); err != nil {
			t.Fatal(err)
		}
		testLiveBackups(t, ctx, cliSession, initial.Scope, cliSession.email, []byte("Public-member-fixture-password!"))
	}
	t.Log("Vaultwarden 1.37.4: legacy v1 binary -> keyed verified replacement -> attachments2 share; FIDO/custom/history/URI preserved; personal and organization resource copy (including organization-key legacy binaries with duplicate names), organization staged import/full binary verification, and personal/organization trash export passed. Synthetic stored passkey only; no hardware/OS passkey assertion.")
}

// Fixture construction only: fixed 1.37.4 requires the legacy multipart key
// field. Empty means the client's old owner-key binary branch, with the filename
// still encrypted by the cipher's current key. Production uses Session streams.
func liveLegacyAttachment(t *testing.T, ctx context.Context, s *Session, id string, binaryKey, filenameKey []byte, name string, plain []byte) {
	t.Helper()
	binary, err := vaultcrypto.EncryptAttachment(ctx, bytes.NewReader(plain), int64(len(plain)), binaryKey)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	filename, err := vaultcrypto.EncryptString([]byte(name), filenameKey)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("data", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(part, binary.File); err != nil {
		t.Fatal(err)
	}
	if err = writer.WriteField("key", ""); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	status, _, err := s.authenticatedLocked(ctx, http.MethodPost, "/api/ciphers/"+id+"/attachment", writer.FormDataContentType(), body.String(), nil)
	s.mu.Unlock()
	if err != nil || status != http.StatusOK {
		t.Fatal("legacy fixture upload", status, err)
	}
}
