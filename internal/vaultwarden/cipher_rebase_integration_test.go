// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Called only by the opt-in isolated loopback fixture; never by default tests.
func testLiveCipherComparison(t *testing.T, ctx context.Context, s *Session, scope Scope) {
	t.Helper()
	base, err := s.CreatePersonalCipher(ctx, scope, CipherFields{Type: 1, Name: "comparison fixture", Login: map[string]any{"password": "initial fixture password"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := DecryptCipherDocument(base, s.key)
	if err != nil {
		t.Fatal(err)
	}
	local.Name = "local draft name"
	remote, err := DecryptCipherDocument(base, s.key)
	if err != nil {
		t.Fatal(err)
	}
	note := "remote note retained"
	remote.Notes = &note
	// Vaultwarden truncates the delta to whole seconds and checks > 1. Wait
	// beyond two seconds to exercise its actual check rather than strict CAS.
	timer := time.NewTimer(2200 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, err := s.UpdatePersonalCipher(ctx, scope, base, remote, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdatePersonalCipher(ctx, scope, base, local, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("expected server old revision rejection", err)
	}
	result, err := s.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptAuthenticatedSnapshot(result.Vault, "live-comparison-revision"); err != nil {
		t.Fatal(err)
	}
	plan, changes, err := s.ComparePersonalCipher(result.Vault, "live-comparison-revision", base, local, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatal("unexpected live field comparison", changes)
	}
	latest, draft, err := s.ApplyPersonalCipherComparison(result.Vault, "live-comparison-revision", plan, []string{"name"})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.UpdatePersonalCipher(ctx, scope, latest, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := DecryptCipherDocument(saved, s.key)
	if err != nil || fields.Name != local.Name || fields.Notes == nil || *fields.Notes != note {
		t.Fatal("live merge lost fields", err)
	}
	if err := s.ChangeCipherState(ctx, scope, fields.ID, CipherDeletePermanently, nil); err != nil {
		t.Fatal(err)
	}
}
