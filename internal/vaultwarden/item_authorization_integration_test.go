// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"testing"
)

func testLiveProtectedItem(t *testing.T, ctx context.Context, s *Session, scope Scope, password []byte) {
	t.Helper()
	created, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 1, Name: "reprompt fixture", Reprompt: 1, Login: map[string]any{"password": "protected fixture", "totp": "WQIQ25BRKZYCJVYP"}}, nil)
	if err != nil {
		t.Fatal("protected create", err)
	}
	fields, err := DecryptCipherDocument(created, s.key)
	if err != nil {
		t.Fatal(err)
	}
	deleteProtected := func(id string) error {
		snapshot, e := s.Sync(ctx)
		if e != nil {
			return e
		}
		revision := fixtureUUID()
		if e = s.AcceptAuthenticatedSnapshot(snapshot.Vault, revision); e != nil {
			return e
		}
		grant, e := s.AuthorizePersonalItem(ctx, snapshot.Vault, revision, id, password)
		if e != nil {
			return e
		}
		document, _, e := s.ReadPersonalCipherAuthorized(snapshot.Vault, id, grant)
		if e != nil {
			return e
		}
		return s.ChangePersonalCipherStateAuthorized(ctx, scope, document, CipherDeletePermanently, grant, nil)
	}
	defer func() {
		if err := deleteProtected(fields.ID); err != nil {
			t.Error("protected fixture cleanup", err)
		}
	}()
	result, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range result.Credentials {
		if c.ID == fields.ID {
			t.Fatal("reprompt item entered AutoFill")
		}
	}
	if err := s.AcceptAuthenticatedSnapshot(result.Vault, "live-protocol-fixture-revision"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadPersonalCipherAuthorized(result.Vault, fields.ID, nil); err != ErrPermission {
		t.Fatal("live protected read bypass", err)
	}
	grant, err := s.AuthorizePersonalItem(ctx, result.Vault, "live-protocol-fixture-revision", fields.ID, password)
	if err != nil {
		t.Fatal("live password verification", err)
	}
	document, opened, err := s.ReadPersonalCipherAuthorized(result.Vault, fields.ID, grant)
	if err != nil || opened.Reprompt != 1 {
		t.Fatal("live grant read", err)
	}
	opened.Name = "protected edited"
	updated, err := s.UpdatePersonalCipherAuthorized(ctx, scope, document, opened, grant, nil)
	if err != nil {
		t.Fatal("live protected write", err)
	}
	check, err := DecryptCipherDocument(updated, s.key)
	if err != nil || check.Reprompt != 1 || check.Name != "protected edited" {
		t.Fatal("reprompt write damaged fields", err)
	}
	// Copy the authorized original snapshot: it must retain reprompt under a new
	// item key. It does not overwrite the source, which was just updated above.
	copied, err := s.CopyPersonalCipherAuthorized(ctx, scope, document, opened, grant, nil)
	if err != nil {
		t.Fatal("live protected copy", err)
	}
	copyFields, err := DecryptCipherDocument(copied, s.key)
	if err != nil || copyFields.Reprompt != 1 {
		t.Fatal("live copy removed reprompt", err)
	}
	if err := deleteProtected(copyFields.ID); err != nil {
		t.Fatal(err)
	}
}
