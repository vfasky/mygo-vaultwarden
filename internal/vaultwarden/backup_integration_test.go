// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testLiveBackups(t *testing.T, ctx context.Context, s *Session, scope Scope, email string, password []byte) {
	t.Helper()
	before, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The Go fixture must explicitly install each newly authenticated snapshot;
	// Sync alone cannot stand in for the production durable publication receipt.
	if err = s.AcceptAuthenticatedSnapshot(before.Vault, fixtureUUID()); err != nil {
		t.Fatal(err)
	}
	beforeDocs, _ := before.Vault.Documents(scope)
	keep := map[string]bool{}
	for _, doc := range beforeDocs {
		obj, _ := documentObject(doc)
		keep[obj["id"].(string)] = true
	}
	beforeFolders, err := s.PersonalFolders(before.Vault)
	if err != nil {
		t.Fatal(err)
	}
	keepFolders := map[string]bool{}
	for _, f := range beforeFolders {
		keepFolders[f.ID] = true
	}
	defer func() {
		after, err := s.Sync(ctx)
		if err != nil {
			t.Errorf("backup fixture cleanup sync: %v", err)
			return
		}
		if err = s.AcceptAuthenticatedSnapshot(after.Vault, fixtureUUID()); err != nil {
			t.Error("backup fixture cleanup receipt", err)
			return
		}
		docs, _ := after.Vault.Documents(scope)
		for _, doc := range docs {
			obj, _ := documentObject(doc)
			id := obj["id"].(string)
			if !keep[id] {
				if err := s.ChangeCipherState(ctx, scope, id, CipherDeletePermanently, nil); err != nil {
					t.Error("fixture item cleanup", err)
				}
			}
		}
		folders, err := s.PersonalFolders(after.Vault)
		if err != nil {
			t.Error(err)
			return
		}
		for _, folder := range folders {
			if !keepFolders[folder.ID] {
				if err := s.DeleteFolder(ctx, scope, folder.ID, nil); err != nil {
					t.Error("fixture folder cleanup", err)
				}
			}
		}
	}()
	source, vault, ids := backupFixture(t, MyGoBackup, 1, 2, 3, 4, 5, 6, 7, 8)
	defer source.Close()
	data, err := source.ExportPersonalBackup(ctx, vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParseImport(data, MyGoBackup)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	result, err := s.ImportPersonalBackup(ctx, scope, plan, nil)
	if err != nil {
		t.Fatalf("live eight-type import: %v", err)
	}
	imported := []string{}
	for _, entry := range result.Entries {
		if entry.Kind == ImportKindItem {
			imported = append(imported, entry.ID)
		}
	}
	if len(imported) != 8 {
		t.Fatal("live import count")
	}
	synced, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptAuthenticatedSnapshot(synced.Vault, fixtureUUID()); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := s.ExportPersonalBackup(ctx, synced.Vault, imported, MyGoBackup)
	if err != nil {
		t.Fatalf("live backup export: %v", err)
	}
	roundPlan, err := ParseImport(roundtrip, MyGoBackup)
	clear(roundtrip)
	if err != nil {
		t.Fatal(err)
	}
	defer roundPlan.Clear()
	if roundPlan.Items != 8 || roundPlan.Deleted != 8 || roundPlan.Archived != 8 {
		t.Fatal("live archive/trash lost")
	}
	for _, id := range imported {
		_, fields, err := s.ReadPersonalCipher(synced.Vault, id)
		if err != nil || len(fields.PasswordHistory) != 1 {
			t.Fatal("live history/read failed", err)
		}
	}
	// The server's returned legacy URI alias and new timestamps are included in
	// the MyGo backup; official conversion must never claim to preserve these.
	for _, id := range imported {
		if err := s.ChangeCipherState(ctx, scope, id, CipherDeletePermanently, nil); err != nil {
			t.Fatal(err)
		}
	}
	cli := os.Getenv("MYGO_BW_CLI")
	if cli == "" {
		t.Log("official CLI interoperability not requested")
		return
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "cli-state")
	target, _ := url.Parse(scope.Server)
	relay := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	defer relay.Close()
	certificate := filepath.Join(dir, "fixture-ca.pem")
	if err = os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: relay.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		command := exec.CommandContext(ctx, cli, args...)
		command.Env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+state, "MYGO_FIXTURE_PASSWORD="+string(password), "BW_NOINTERACTION=true", "NODE_EXTRA_CA_CERTS="+certificate)
		output, err := command.Output()
		if err != nil {
			clear(output)
			if failure, ok := err.(*exec.ExitError); ok {
				message := strings.ReplaceAll(string(failure.Stderr), string(password), "[fixture password]")
				message = strings.ReplaceAll(message, email, "[fixture email]")
				t.Fatalf("official CLI %s failed: %s", args[0], message)
			}
			t.Fatalf("official CLI %s failed: %T", args[0], err)
		}
		return output
	}
	clear(run("config", "server", relay.URL))
	token := run("login", email, "--passwordenv", "MYGO_FIXTURE_PASSWORD", "--raw")
	defer clear(token)
	// Pass the fixture session only in the environment, never command arguments.
	runAuth := func(args ...string) []byte {
		command := exec.CommandContext(ctx, cli, args...)
		command.Env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+state, "BW_SESSION="+strings.TrimSpace(string(token)), "BW_NOINTERACTION=true", "NODE_EXTRA_CA_CERTS="+certificate)
		output, err := command.Output()
		if err != nil {
			clear(output)
			if failure, ok := err.(*exec.ExitError); ok {
				message := strings.ReplaceAll(string(failure.Stderr), strings.TrimSpace(string(token)), "[fixture session]")
				message = strings.ReplaceAll(message, email, "[fixture email]")
				t.Fatalf("official CLI %s failed: %s", args[0], message)
			}
			t.Fatalf("official CLI %s failed: %T", args[0], err)
		}
		return output
	}
	officialSource, officialVault, officialIDs := backupFixture(t, BitwardenJSON, 1, 2, 3, 4, 5, 6, 7)
	defer officialSource.Close()
	exported, err := officialSource.ExportPersonalBackup(ctx, officialVault, officialIDs, BitwardenJSON)
	if err != nil {
		t.Fatal(err)
	}
	file, err := decodeBackup(exported, BitwardenJSON)
	clear(exported)
	if err != nil {
		t.Fatal(err)
	}
	// Distinct public fixture names make independent matching unambiguous.
	for _, item := range file.Items {
		item["name"] = fmt.Sprintf("Official interoperability type %v", item["type"])
		if mustBackupType(item) == 1 {
			login := item["login"].(map[string]any)
			login["uris"] = append(login["uris"].([]any), map[string]any{"uri": "https://second.example.invalid/path", "match": json.Number("3")})
			item["fields"] = append(item["fields"].([]any), map[string]any{"name": "hidden fixture", "value": "hidden value", "type": json.Number("1")}, map[string]any{"name": "boolean fixture", "value": "true", "type": json.Number("2")}, map[string]any{"name": "linked fixture", "value": nil, "type": json.Number("3"), "linkedId": json.Number("101")})
		}
	}
	exported, _ = json.Marshal(file)
	path := filepath.Join(dir, "bitwarden.json")
	if err = os.WriteFile(path, exported, 0600); err != nil {
		t.Fatal(err)
	}
	clear(exported)
	clear(runAuth("import", "bitwardenjson", path))
	clear(runAuth("sync"))
	listed := runAuth("list", "items")
	var officialItems []map[string]any
	if json.Unmarshal(listed, &officialItems) != nil {
		t.Fatal("official list not JSON")
	}
	clear(listed)
	archived := runAuth("list", "items", "--archived")
	var archivedItems []map[string]any
	if json.Unmarshal(archived, &archivedItems) != nil {
		t.Fatal("official archive list not JSON")
	}
	clear(archived)
	officialItems = append(officialItems, archivedItems...)
	for _, expected := range file.Items {
		found := false
		for _, item := range officialItems {
			if item["name"] != expected["name"] {
				continue
			}
			found = true
			// CLI JSON numbers use float64; compare serialized field structures instead.
			for _, field := range []string{"name", "notes", "type", "favorite", "fields", "passwordHistory", cipherSections[mustBackupType(expected)]} {
				want, _ := json.Marshal(expected[field])
				got, _ := json.Marshal(item[field])
				if field == "fields" {
					wantFields := expected[field].([]any)
					gotFields := item[field].([]any)
					if len(wantFields) != len(gotFields) {
						t.Fatal("official custom field count")
					}
					for i := range wantFields {
						a, b := wantFields[i].(map[string]any), gotFields[i].(map[string]any)
						for _, key := range []string{"name", "type", "value", "linkedId"} {
							av, _ := json.Marshal(a[key])
							bv, _ := json.Marshal(b[key])
							if string(av) != string(bv) {
								t.Fatalf("official field %d key=%s wanted-nil=%t got-nil=%t wanted-empty=%t got-empty=%t", i, key, a[key] == nil, b[key] == nil, a[key] == "", b[key] == "")
							}
						}
					}
					continue
				}
				if field == "passwordHistory" {
					wantHistory := expected[field].([]any)
					gotHistory, ok := item[field].([]any)
					if !ok || len(wantHistory) != len(gotHistory) {
						t.Fatal("official password history count")
					}
					for i := range wantHistory {
						a, b := wantHistory[i].(map[string]any), gotHistory[i].(map[string]any)
						at, _ := time.Parse(time.RFC3339Nano, a["lastUsedDate"].(string))
						bt, _ := time.Parse(time.RFC3339Nano, b["lastUsedDate"].(string))
						if a["password"] != b["password"] || !at.Equal(bt) {
							t.Fatal("official password history changed")
						}
					}
					continue
				}
				if field == "login" {
					login := item[field].(map[string]any)
					for _, k := range []string{"username", "password", "totp"} {
						if login[k] != expected[field].(map[string]any)[k] {
							t.Fatalf("official decrypted login %s mismatch", k)
						}
					}
					wantURIs := expected[field].(map[string]any)["uris"].([]any)
					gotURIs := login["uris"].([]any)
					if len(wantURIs) != len(gotURIs) {
						t.Fatal("official URI count")
					}
					for i := range wantURIs {
						if wantURIs[i].(map[string]any)["uri"] != gotURIs[i].(map[string]any)["uri"] {
							t.Fatal("official URI mismatch")
						}
					}
					continue
				}
				if string(want) != string(got) {
					t.Fatalf("official decrypted type %v field %s mismatch", expected["type"], field)
				}
			}
		}
		if !found {
			t.Fatalf("official CLI missing type %v", expected["type"])
		}
	}
	output := filepath.Join(dir, "official-export.json")
	clear(runAuth("export", "--format", "json", "--output", output))
	returned, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(returned)
	officialPlan, err := ParseImport(returned, BitwardenJSON)
	if err != nil {
		t.Fatalf("official export not accepted: %v", err)
	}
	defer officialPlan.Clear()
	if officialPlan.Items < 7 {
		t.Fatal("official export lost imported items")
	}
	if _, err = s.ImportPersonalBackup(ctx, scope, officialPlan, nil); err != nil {
		t.Fatalf("official export reimport failed: %v", err)
	}
	clear(runAuth("logout"))
	t.Log("official CLI 2026.5.0 imported/decrypted all seven compatible types and exported a file accepted and reimported by MyGo")
}
func mustBackupType(item map[string]any) int {
	n, _ := item["type"].(json.Number).Int64()
	return int(n)
}
