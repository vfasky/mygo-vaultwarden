// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type personalBackupFake struct {
	events   []string
	grant    bool
	finalErr error
	cancel   context.CancelFunc
}

func (f *personalBackupFake) checkScope(Scope) error {
	f.events = append(f.events, "scope")
	return nil
}
func (f *personalBackupFake) policies(*VaultData) (*operationPolicies, error) {
	f.events = append(f.events, "policies")
	return &operationPolicies{}, nil
}
func (f *personalBackupFake) validGrant(*ItemAuthorization, CipherDocument) bool {
	f.events = append(f.events, "grant")
	return f.grant
}
func (f *personalBackupFake) decryptItem(_ CipherDocument, object map[string]any) (CipherFields, error) {
	f.events = append(f.events, "decrypt")
	object["name"] = "Plain note"
	if f.cancel != nil {
		f.cancel()
	}
	return CipherFields{}, nil
}
func (f *personalBackupFake) decryptFolder(string) ([]byte, error) {
	f.events = append(f.events, "folder")
	return []byte("Folder"), nil
}
func (f *personalBackupFake) checkExport(*VaultData, []string, map[string]*ItemAuthorization) error {
	f.events = append(f.events, "final-authority")
	return f.finalErr
}

func TestPersonalBackupServiceWithoutSession(t *testing.T) {
	scope := Scope{Server: "https://backup.example.invalid", Account: "account-1"}
	raw := json.RawMessage(`{"profile":{"id":"account-1"},"folders":[],"ciphers":[{"id":"item-1","type":2,"name":"encrypted-name","favorite":false,"reprompt":1,"organizationId":null,"edit":true,"viewPassword":true,"secureNote":{"type":0}}]}`)
	vault := &VaultData{Version: 1, Scope: scope, Sync: raw}
	for _, mode := range []string{"success", "deny-grant", "revoke-final", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := &personalBackupFake{grant: mode != "deny-grant"}
			if mode == "revoke-final" {
				fake.finalErr = ErrExpired
			}
			if mode == "cancel" {
				fake.cancel = cancel
			}
			service := personalBackupService{access: fake}
			data, err := service.export(ctx, vault, []string{"item-1"}, MyGoBackup, nil, false)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				file, err := decodeBackup(data, MyGoBackup)
				if err != nil || len(file.Items) != 1 || file.Items[0]["name"] != "Plain note" {
					t.Fatalf("bad export: %s %v", data, err)
				}
				if !reflect.DeepEqual(fake.events, []string{"scope", "policies", "grant", "decrypt", "final-authority"}) {
					t.Fatal(fake.events)
				}
				return
			}
			expected := ErrPermission
			if mode == "revoke-final" {
				expected = ErrExpired
			}
			if mode == "cancel" {
				expected = ErrCancelled
			}
			if !errors.Is(err, expected) || data != nil {
				t.Fatalf("%s: data=%d err=%v", mode, len(data), err)
			}
			if mode == "deny-grant" && !reflect.DeepEqual(fake.events, []string{"scope", "policies", "grant"}) {
				t.Fatal("decrypted without grant", fake.events)
			}
		})
	}
}
