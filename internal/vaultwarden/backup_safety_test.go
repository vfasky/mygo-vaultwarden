// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestImportCloseAndScopeStopFurtherWrites(t *testing.T) {
	source, vault, ids := backupFixture(t, MyGoBackup, 1, 2)
	defer source.Close()
	data, err := source.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParseImport(data, MyGoBackup)
	clear(data)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Clear()
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
		w.WriteHeader(500)
	}))
	defer server.Close()
	defer close(release)
	s, _ := resumableFixture(t, server.URL)
	s.key = source.key
	scope := Scope{Server: server.URL, Account: "account-a"}
	if _, err := s.ImportPersonalBackup(context.Background(), Scope{Server: scope.Server, Account: "other"}, plan, nil); !errors.Is(err, ErrIdentity) {
		t.Fatal("scope bypass", err)
	}
	if calls.Load() != 0 {
		t.Fatal("scope wrote")
	}
	done := make(chan error, 1)
	go func() { _, err := s.ImportPersonalBackup(context.Background(), scope, plan, nil); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	s.Close()
	select {
	case err := <-done:
		var unknown *MutationUncertainError
		if !errors.As(err, &unknown) {
			t.Fatal("in-flight create cancellation not unknown", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close failed to cancel")
	}
	if calls.Load() != 1 {
		t.Fatal("import continued after cancel")
	}
}
func TestBackupHistoryAndStrictValidation(t *testing.T) {
	s, vault, ids := backupFixture(t, MyGoBackup, 1)
	defer s.Close()
	data, err := s.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	for _, scenario := range []string{"long-history", "invalid-date", "field-type", "uri-strategy", "invalid-utf8"} {
		t.Run(scenario, func(t *testing.T) {
			file, _ := decodeBackup(data, MyGoBackup)
			item := file.Items[0]
			switch scenario {
			case "long-history":
				entry := item["passwordHistory"].([]any)[0]
				item["passwordHistory"] = []any{entry, entry, entry, entry, entry, entry}
			case "invalid-date":
				item["passwordHistory"].([]any)[0].(map[string]any)["lastUsedDate"] = "yesterday"
			case "field-type":
				item["fields"].([]any)[0].(map[string]any)["type"] = json.Number("9")
			case "uri-strategy":
				item["login"].(map[string]any)["uris"].([]any)[0].(map[string]any)["match"] = json.Number("50")
			}
			raw, _ := json.Marshal(file)
			if scenario == "invalid-utf8" {
				raw = append(raw[:len(raw)-1], 0xff, '}')
			}
			plan, err := ParseImport(raw, MyGoBackup)
			if scenario == "long-history" {
				if err != nil {
					t.Fatal("history truncated/rejected", err)
				}
				plan.Clear()
			} else if err == nil {
				plan.Clear()
				t.Fatal("invalid input accepted")
			}
		})
	}
}
