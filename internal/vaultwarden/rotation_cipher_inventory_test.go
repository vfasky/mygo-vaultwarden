// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRotationCipherResourcesFreshness(t *testing.T) {
	in := rotationCipherFixture(t, 1, false)
	original, _ := rotationCipherObject(in.Sync)
	before := mustRotationCipherJSON(original["ciphers"].([]any)[0].(map[string]any))
	array := func(object map[string]any) json.RawMessage { raw, _ := json.Marshal([]any{object}); return raw }
	for _, scenario := range []string{"url", "key", "size", "unknown-null", "revision", "id", "duplicate", "invalid-array", "bad-attachment", "bad-url", "missing-url", "missing-id", "duplicate-attachment", "bad-type"} {
		t.Run(scenario, func(t *testing.T) {
			old, _ := rotationCipherObject(before)
			current, _ := rotationCipherObject(before)
			attachment := current["attachments"].([]any)[0].(map[string]any)
			switch scenario {
			case "url":
				attachment["url"] = "https://example.invalid/fresh-token"
			case "key":
				attachment["key"] = "different"
			case "size":
				attachment["size"] = "9007199254740994"
			case "unknown-null":
				attachment["future"] = nil
			case "revision":
				current["revisionDate"] = "2026-07-01T00:00:00Z"
			case "id":
				attachment["id"] = "other"
			case "bad-attachment":
				current["attachments"] = []any{nil}
			case "missing-url":
				delete(attachment, "url")
			case "missing-id":
				delete(attachment, "id")
			case "duplicate-attachment":
				current["attachments"] = []any{attachment, attachment}
			case "bad-type":
				current["type"] = "1"
			case "bad-url":
				attachment["url"] = nil
			}
			right := array(current)
			if scenario == "duplicate" {
				right, _ = json.Marshal([]any{current, current})
			}
			if scenario == "invalid-array" {
				right = json.RawMessage(`null`)
			}
			if got := AccountRotationCipherInventoryEqual(array(old), right); got != (scenario == "url") {
				t.Fatalf("equal=%v", got)
			}
		})
	}
}
func TestRotationCipherResourcesNoFilesAndAlias(t *testing.T) {
	in := rotationCipherFixture(t, 1, false)
	sync, _ := rotationCipherObject(in.Sync)
	object := sync["ciphers"].([]any)[0].(map[string]any)
	object["attachments"] = nil
	login := object["login"].(map[string]any)
	delete(login, "uris")
	in.Sync = mustRotationCipherJSON(sync)
	out, err := ConvertAccountRotationCipherResources(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := rotationCipherObject(out.Ciphers[0])
	if len(target["attachments2"].(map[string]any)) != 0 {
		t.Fatal("files invented")
	}
	if _, ok := target["login"].(map[string]any)["uris"].([]any); !ok {
		t.Fatal("alias not migrated")
	}
	verified, err := VerifyAccountRotationCipherResources(context.Background(), RotationCipherVerificationInput{Scope: in.Scope, CurrentScope: in.Scope, OriginalSync: in.Sync, CurrentSync: rotationCipherProjected(t, in, out), Target: out, OldUserKey: in.OldUserKey, NewUserKey: in.NewUserKey})
	if err != nil || verified.State != RotationCipherNew {
		t.Fatal("alias verification", verified.State, err)
	}
	sync["ciphers"] = []any{}
	sync["folders"] = []any{}
	in.Sync = mustRotationCipherJSON(sync)
	out, err = ConvertAccountRotationCipherResources(context.Background(), in)
	if err != nil || out.Ciphers == nil || out.Folders == nil {
		t.Fatal("empty arrays", err)
	}
}
