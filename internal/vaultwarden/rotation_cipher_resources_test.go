// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"testing"
)

func rotationCipherFixture(t *testing.T, kind int, modern bool) AccountRotationInput {
	t.Helper()
	doc, key := copyFixture(t, kind)
	object, _ := rotationCipherObject(doc.JSON)
	object["fields"].([]any)[0].(map[string]any)["linkedId"] = json.Number("9007199254740993")
	if kind == 1 {
		_, fido := migrationFIDOFixture(t, key)
		object["login"].(map[string]any)["fido2Credentials"] = []any{fido}
	}
	if modern {
		item := bytes.Repeat([]byte{91}, 64)
		if err := transformCompleteCipher(object, key, false); err != nil {
			t.Fatal(err)
		}
		if err := transformCompleteCipher(object, item, true); err != nil {
			t.Fatal(err)
		}
		object["key"], _ = vaultcrypto.EncryptString(item, key)
		keyForFile := item
		fileKey, _ := vaultcrypto.EncryptString(bytes.Repeat([]byte{29}, 64), keyForFile)
		fileName, _ := vaultcrypto.EncryptString([]byte("payload.bin"), keyForFile)
		object["attachments"] = []any{map[string]any{"object": "attachment", "id": "file-1", "key": fileKey, "fileName": fileName, "size": "9007199254740993", "sizeName": "large", "url": "https://example.invalid/signed"}}
	} else {
		fileKey, _ := vaultcrypto.EncryptString(bytes.Repeat([]byte{29}, 64), key)
		fileName, _ := vaultcrypto.EncryptString([]byte("payload.bin"), key)
		object["attachments"] = []any{map[string]any{"object": "attachment", "id": "file-1", "key": fileKey, "fileName": fileName, "size": "9007199254740993", "sizeName": "large", "url": "https://example.invalid/signed"}}
	}
	name, _ := vaultcrypto.EncryptString([]byte("folder name"), key)
	sync, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": "account-a"}, "ciphers": []any{object}, "folders": []any{map[string]any{"id": "folder-1", "name": name, "object": "folder"}}})
	return AccountRotationInput{Scope: Scope{Server: "https://example.invalid", Account: "account-a"}, Sync: sync, OldUserKey: key, NewUserKey: bytes.Repeat([]byte{82}, 64), Read: func(context.Context, string) (json.RawMessage, error) {
		t.Fatal("unexpected transport")
		return nil, ErrProtocol
	}}
}
func rotationCipherProjected(t *testing.T, in AccountRotationInput, out RotationCipherResources) json.RawMessage {
	t.Helper()
	sync, _ := rotationCipherObject(in.Sync)
	rows := sync["ciphers"].([]any)
	for i, raw := range out.Ciphers {
		object, e := rotationCipherExpected(rows[i].(map[string]any), raw, in.Scope.Account)
		if e != nil {
			t.Fatal(e)
		}
		object["revisionDate"] = "2026-06-01T00:00:00Z"
		rows[i] = object
	}
	for i, folder := range out.Folders {
		sync["folders"].([]any)[i].(map[string]any)["name"] = folder.Name
	}
	return mustRotationCipherJSON(sync)
}
func TestRotationCipherResourcesEightTypes(t *testing.T) {
	for kind := 1; kind <= 8; kind++ {
		for _, modern := range []bool{false, true} {
			t.Run(cipherSections[kind]+map[bool]string{false: "-legacy", true: "-modern"}[modern], func(t *testing.T) {
				in := rotationCipherFixture(t, kind, modern)
				original := bytes.Clone(in.Sync)
				out, err := ConvertAccountRotationCipherResources(context.Background(), in)
				if err != nil {
					t.Fatal(err)
				}
				dto, _ := rotationCipherObject(out.Ciphers[0])
				if dto["fields"].([]any)[0].(map[string]any)["linkedId"] != json.Number("9007199254740993") {
					t.Fatal("integer precision lost")
				}
				if _, ok := dto["attachments"]; ok {
					t.Fatal("response emitted as request")
				}
				if dto["encryptedFor"] != "account-a" || dto["lastKnownRevisionDate"] == nil || dto["deletedDate"] != nil {
					t.Fatal("wrong DTO")
				}
				if !bytes.Equal(in.Sync, original) {
					t.Fatal("mutated borrowed input")
				}
				current := rotationCipherProjected(t, in, out)
				verification := RotationCipherVerificationInput{Scope: in.Scope, CurrentScope: in.Scope, OriginalSync: in.Sync, CurrentSync: current, Target: out, OldUserKey: in.OldUserKey, NewUserKey: in.NewUserKey}
				result, err := VerifyAccountRotationCipherResources(context.Background(), verification)
				if err != nil || result.State != RotationCipherNew {
					t.Fatalf("new %s %v", result.State, err)
				}
				verification.CurrentSync = in.Sync
				result, err = VerifyAccountRotationCipherResources(context.Background(), verification)
				if err != nil || result.State != RotationCipherOld {
					t.Fatalf("old %s %v", result.State, err)
				}
				// Check attachment wrapper still holds original independent key, never owner.
				sync, _ := rotationCipherObject(current)
				o := sync["ciphers"].([]any)[0].(map[string]any)
				if o["deletedDate"] == nil {
					t.Fatal("trash lost")
				}
				key, e := cipherItemKey(o, in.NewUserKey)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(key)
				attachment := o["attachments"].([]any)[0].(map[string]any)
				fileKey, e := vaultcrypto.DecryptString(attachment["key"].(string), key)
				if e != nil || !bytes.Equal(fileKey, bytes.Repeat([]byte{29}, 64)) || bytes.Equal(fileKey, in.OldUserKey) {
					t.Fatal("attachment key changed or owner leaked", e)
				}
				clear(fileKey)
			})
		}
	}
}
func TestRotationCipherResourcesPreparationAndFailures(t *testing.T) {
	for _, scenario := range []string{"keyless", "modern-keyless", "owner-as-file-key", "owner-as-item-key", "unknown", "unknown-null", "unknown-fido", "bad-name", "bad-fido", "bad-wrapper", "bad-file-wrapper", "duplicate", "scope", "folder-unknown", "cancel", "org"} {
		t.Run(scenario, func(t *testing.T) {
			in := rotationCipherFixture(t, 1, scenario == "modern-keyless" || scenario == "bad-wrapper")
			sync, _ := rotationCipherObject(in.Sync)
			object := sync["ciphers"].([]any)[0].(map[string]any)
			rows := object["attachments"].([]any)
			attachment := rows[0].(map[string]any)
			ctx := context.Background()
			switch scenario {
			case "keyless", "modern-keyless":
				attachment["key"] = nil
			case "owner-as-item-key":
				object["key"], _ = vaultcrypto.EncryptString(in.OldUserKey, in.OldUserKey)
			case "owner-as-file-key":
				attachment["key"], _ = vaultcrypto.EncryptString(in.OldUserKey, in.OldUserKey)
			case "unknown":
				object["future"] = json.Number("9007199254740993")
			case "unknown-null":
				object["future"] = nil
			case "unknown-fido":
				object["login"].(map[string]any)["fido2Credentials"].([]any)[0].(map[string]any)["future"] = nil
			case "bad-name":
				object["name"] = "2.invalid"
			case "bad-fido":
				object["login"].(map[string]any)["fido2Credentials"].([]any)[0].(map[string]any)["counter"] = "2.invalid"
			case "bad-wrapper":
				object["key"] = "2.invalid"
			case "bad-file-wrapper":
				attachment["key"] = "2.invalid"
			case "duplicate":
				sync["ciphers"] = []any{object, object}
			case "scope":
				in.Scope.Account = "other"
			case "folder-unknown":
				sync["folders"].([]any)[0].(map[string]any)["future"] = nil
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "org":
				object["organizationId"] = "organization-a"
			}
			in.Sync = mustRotationCipherJSON(sync)
			out, err := ConvertAccountRotationCipherResources(ctx, in)
			if scenario == "org" {
				if err != nil || len(out.Ciphers) != 0 {
					t.Fatal("org not isolated", err)
				}
				return
			}
			if err == nil || out.Ciphers != nil {
				t.Fatal("did not fail closed")
			}
			if scenario == "keyless" || scenario == "modern-keyless" {
				var preparation *RotationCipherPreparationError
				if !errors.As(err, &preparation) || len(preparation.Readiness.Preparations) != 1 || preparation.Readiness.Preparations[0].AttachmentID != "file-1" || !preparation.Readiness.Preparations[0].Deleted {
					t.Fatal("missing actionable preparation", err)
				}
				// A fresh snapshot after explicit upgrade/delete is immediately usable.
				attachment["key"], _ = vaultcrypto.EncryptString(bytes.Repeat([]byte{29}, 64), in.OldUserKey)
				if scenario == "modern-keyless" {
					k, _ := cipherItemKey(object, in.OldUserKey)
					attachment["key"], _ = vaultcrypto.EncryptString(bytes.Repeat([]byte{29}, 64), k)
					clear(k)
				}
				in.Sync = mustRotationCipherJSON(sync)
				if _, err = ConvertAccountRotationCipherResources(ctx, in); err != nil {
					t.Fatal("prepared path rejected", err)
				}
			}
		})
	}
}
func TestRotationCipherResourcesVerification(t *testing.T) {
	for _, scenario := range []string{"mixed-field", "mixed-file", "external", "unknown-null", "missing", "extra", "duplicate", "scope", "target-bad-mac", "target-changed-content", "target-missing-wrapper", "target-unknown", "folder-mixed", "folder-missing", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			in := rotationCipherFixture(t, 1, false)
			out, err := ConvertAccountRotationCipherResources(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			current := rotationCipherProjected(t, in, out)
			sync, _ := rotationCipherObject(current)
			oldSync, _ := rotationCipherObject(in.Sync)
			object := sync["ciphers"].([]any)[0].(map[string]any)
			old := oldSync["ciphers"].([]any)[0].(map[string]any)
			verify := RotationCipherVerificationInput{Scope: in.Scope, CurrentScope: in.Scope, OriginalSync: in.Sync, Target: out, OldUserKey: in.OldUserKey, NewUserKey: in.NewUserKey}
			want := RotationCipherExternal
			wantError := false
			ctx := context.Background()
			switch scenario {
			case "mixed-field":
				object["name"] = old["name"]
				want = RotationCipherMixed
			case "mixed-file":
				object["attachments"].([]any)[0].(map[string]any)["key"] = old["attachments"].([]any)[0].(map[string]any)["key"]
				want = RotationCipherMixed
			case "external":
				object["name"], _ = vaultcrypto.EncryptString([]byte("other edit"), in.NewUserKey)
			case "unknown-null":
				object["future"] = nil
			case "missing":
				sync["ciphers"] = []any{}
				want = RotationCipherMissing
			case "extra":
				extra, _ := rotationCipherObject(mustRotationCipherJSON(object))
				extra["id"] = "extra"
				sync["ciphers"] = []any{object, extra}
			case "duplicate":
				sync["ciphers"] = []any{object, object}
				wantError = true
			case "scope":
				verify.CurrentScope.Account = "other"
				wantError = true
			case "target-bad-mac", "target-changed-content", "target-missing-wrapper", "target-unknown":
				dto, _ := rotationCipherObject(out.Ciphers[0])
				wantError = true
				switch scenario {
				case "target-bad-mac":
					dto["name"] = "2.invalid"
				case "target-changed-content":
					dto["name"], _ = vaultcrypto.EncryptString([]byte("changed"), in.NewUserKey)
				case "target-missing-wrapper":
					dto["attachments2"] = map[string]any{}
				case "target-unknown":
					dto["future"] = nil
				}
				verify.Target.Ciphers[0] = mustRotationCipherJSON(dto)
			case "folder-mixed":
				sync["folders"] = oldSync["folders"]
				want = RotationCipherMixed
			case "folder-missing":
				sync["folders"] = []any{}
				want = RotationCipherMissing
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantError = true
			}
			verify.CurrentSync = mustRotationCipherJSON(sync)
			before := bytes.Clone(verify.CurrentSync)
			result, err := VerifyAccountRotationCipherResources(ctx, verify)
			if wantError {
				if err == nil {
					t.Fatal("bad verification accepted")
				}
				return
			}
			if err != nil || result.State != want {
				t.Fatalf("got %s want %s: %v", result.State, want, err)
			}
			if !bytes.Equal(before, verify.CurrentSync) {
				t.Fatal("mutated observation")
			}
		})
	}
}
