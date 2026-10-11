// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestBackupMalformedItemsFailWithoutPanic(t *testing.T) {
	s, vault, ids := backupFixture(t, MyGoBackup, 1)
	defer s.Close()
	data, err := s.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	mutations := map[string]func(map[string]any){
		"missing-name":    func(m map[string]any) { delete(m, "name") },
		"missing-type":    func(m map[string]any) { delete(m, "type") },
		"wrong-type":      func(m map[string]any) { m["type"] = []any{} },
		"fractional-type": func(m map[string]any) { m["type"] = json.Number("1.5") },
		"missing-id":      func(m map[string]any) { delete(m, "id") },
		"wrong-name":      func(m map[string]any) { m["name"] = map[string]any{} },
		"null-uri":        func(m map[string]any) { m["login"].(map[string]any)["uris"] = []any{nil} },
		"scalar-uri":      func(m map[string]any) { m["login"].(map[string]any)["uris"] = []any{false} },
		"object-uris":     func(m map[string]any) { m["login"].(map[string]any)["uris"] = map[string]any{} },
		"bad-history":     func(m map[string]any) { m["passwordHistory"] = []any{map[string]any{"lastUsedDate": false}} },
		"unknown-field":   func(m map[string]any) { m["future"] = "must not drop" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			file, err := decodeBackup(data, MyGoBackup)
			if err != nil {
				t.Fatal(err)
			}
			mutate(file.Items[0])
			raw, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			if _, err = ParseImport(raw, MyGoBackup); err == nil {
				t.Fatal("malformed personal backup accepted")
			}
			// The public import entry must reject before policy/transport access.
			result, err := s.ImportPersonalBackup(context.Background(), vault.Scope, &ImportPlan{data: raw, Format: MyGoBackup}, nil)
			if err == nil || len(result.Entries) != 0 {
				t.Fatalf("import proceeded: %+v, %v", result, err)
			}
			item := file.Items[0]
			item["organizationId"], item["collectionIds"] = "org-1", []any{}
			org, err := json.Marshal(organizationBackup{Format: organizationBackupFormat, Version: 1, OrganizationID: "org-1", Collections: []OrganizationBackupCollection{}, Items: []map[string]any{item}})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(org)
			if _, err = ParseOrganizationImport(org); err == nil {
				t.Fatal("malformed organization backup accepted")
			}
			if _, err := backupItemIdentity(item); err != nil {
				plan := &OrganizationImportPlan{file: organizationBackup{Items: []map[string]any{item}}}
				if plan.PreviewItems() != nil {
					t.Fatal("invalid preview accepted")
				}
			}
		})
	}
}

func TestBackupConversionPreservesErrorIdentity(t *testing.T) {
	err := backupError(1, "detail")
	var conversion *BackupConversionError
	if !errors.Is(err, ErrUnsupportedEdit) || !errors.As(err, &conversion) || conversion.Index != 1 {
		t.Fatalf("unstable conversion identity: %v", err)
	}
	if !errors.Is(backupUnsupportedError{reason: "回收站项目请使用 MyGo 备份"}, ErrUnsupportedEdit) {
		t.Fatal("missing unsupported identity")
	}
	raw := []byte(`{"format":"mygo-vaultwarden-personal-backup","version":1,"encrypted":false,"folders":[],"items":[{"id":"item","type":1}]}`)
	_, err = ParseImport(raw, MyGoBackup)
	if !errors.Is(err, ErrProtocol) || !errors.As(err, &conversion) {
		t.Fatalf("lost underlying parse error: %v", err)
	}
}

func TestResourceBackupMalformedMetadataFailsBeforeRestore(t *testing.T) {
	for _, value := range []any{nil, false, map[string]any{}, []any{}} {
		archive := resourceArchiveFixture(t, func(manifest *resourceManifest) {
			file, err := decodeBackup(manifest.Metadata, MyGoBackup)
			if err != nil {
				t.Fatal(err)
			}
			file.Items[0]["id"] = value
			manifest.Metadata, err = json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
		}, nil, false)
		plan, err := parseResourceBytes(t, archive)
		if plan != nil {
			plan.Clear()
			t.Fatal("invalid archive produced a restore plan")
		}
		if err == nil {
			t.Fatalf("accepted malformed source ID: %#v", value)
		}
	}
}

func TestOrganizationImportReconciliationMalformedPlanFailsClosed(t *testing.T) {
	s := &Session{}
	for _, plan := range []*OrganizationImportPlan{nil, {}, {file: organizationBackup{Items: []map[string]any{{"id": false}}}}} {
		var expected []json.RawMessage
		if plan != nil && len(plan.file.Items) != 0 {
			expected = []json.RawMessage{json.RawMessage(`{}`)}
		}
		result := s.reconcileOrganizationImportLocked(context.Background(), "org", nil, expected, plan, nil, nil)
		if result.ReadCompleted {
			t.Fatal("invalid plan reached remote reconciliation")
		}
		for _, item := range result.Items {
			if item.Verified {
				t.Fatal("invalid item verified")
			}
		}
	}
}

func TestBackupObjectRowsRejectsWrongTypes(t *testing.T) {
	for _, value := range []any{true, "rows", map[string]any{}, []any{nil}, []any{1}, []any{map[string]any(nil)}} {
		if _, err := backupObjectRows(value); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted %T: %v", value, err)
		}
	}
}

func TestRotationCipherMalformedAttachmentsFailWithoutPanic(t *testing.T) {
	for _, value := range []any{true, map[string]any{}, []any{nil}, []any{"bad"}, []any{map[string]any{"id": false}}} {
		old := map[string]any{"id": "cipher-1", "revisionDate": "2026-01-01T00:00:00Z", "attachments": value}
		dto := map[string]any{"id": "cipher-1", "encryptedFor": "account-a", "lastKnownRevisionDate": old["revisionDate"], "attachments2": map[string]any{"attachment-1": map[string]any{"key": "wrapped", "fileName": "name"}}}
		raw, err := json.Marshal(dto)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rotationCipherExpected(old, raw, "account-a"); err == nil {
			t.Fatalf("accepted expected attachments: %#v", value)
		}
		encoded, _ := json.Marshal(old)
		if _, err := rotationCipherRows([]json.RawMessage{encoded}); err == nil {
			t.Fatalf("accepted inventory: %#v", value)
		}
		if _, err := rotationCipherPlain(old, make([]byte, 64)); err == nil {
			t.Fatalf("accepted plaintext: %#v", value)
		}
		if _, err := backupObjectRows(value); err != nil {
			if _, err := rotationCipherComparable(old, true); !errors.Is(err, ErrProtocol) {
				t.Fatalf("comparable accepted malformed rows: %v", err)
			}
		}
	}
	// Comparing two untrusted interface values must not panic on maps/slices.
	old := map[string]any{"id": map[string]any{}, "revisionDate": []any{}}
	if _, err := rotationCipherExpected(old, []byte(`{"id":{},"lastKnownRevisionDate":[],"encryptedFor":"account-a"}`), "account-a"); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
}
