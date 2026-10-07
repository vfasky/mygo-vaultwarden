// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Uses only an explicitly configured, isolated loopback fixture. Each test owns
// its generated example.invalid account. No preexisting account is accessed.
func TestLiveAccountLifecycle(t *testing.T) {
	server := os.Getenv("MYGO_ACCOUNT_TEST_URL")
	if server == "" {
		t.Skip("set MYGO_ACCOUNT_TEST_URL to this card's isolated 1.37.4 loopback fixture")
	}
	if !strings.HasPrefix(server, "http://127.0.0.1:") {
		t.Fatal("refusing nonloopback fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client, err := NewClient(server, fixtureUUID())
	if err != nil {
		t.Fatal(err)
	}
	email := "account-" + fixtureUUID() + "@example.invalid"
	password := []byte("Live-account-Primary-Passphrase-762!")
	defer clear(password)
	kdf := KDF{Type: 0, Iterations: 100000}
	verification, err := client.AccountSendRegistrationEmail(ctx, email, "Account fixture")
	if err != nil {
		t.Fatal("registration verification", err)
	}
	if verification.EmailSent {
		t.Fatal("fixture must have SMTP disabled for this test")
	}
	if err = client.AccountRegister(ctx, email, password, kdf, "", verification.Token); err != nil {
		t.Fatal("register", err)
	}
	verification.Token = ""
	var session *Session
	var vault *VaultData
	var originalKey []byte
	checkpoint := func(SessionCheckpoint) error { return nil } // Go-only storage test double, not a platform receipt.
	login := func() {
		t.Helper()
		if session != nil {
			session.Close()
		}
		session, err = client.Login(ctx, email, password, nil)
		if err != nil {
			t.Fatal("login", err)
		}
		sync, err := session.SyncWithCheckpoint(ctx, checkpoint)
		if err != nil {
			t.Fatal("sync", err)
		}
		vault = sync.Vault
		if err = session.AcceptAuthenticatedSnapshot(vault, fixtureUUID()); err != nil {
			t.Fatal("accept Go-only receipt", err)
		}
		if originalKey == nil {
			originalKey = append([]byte(nil), session.key...)
		} else if !bytes.Equal(originalKey, session.key) {
			t.Fatal("credential change rotated user key unexpectedly")
		}
	}
	login()
	defer func() {
		if session != nil {
			session.Close()
		}
		clear(originalKey)
	}()
	profile, err := session.AccountUpdateProfile(ctx, "Changed display name", checkpoint)
	if err != nil || profile.Name != "Changed display name" {
		t.Fatal("profile", err)
	}
	color := "#13a4B7"
	profile, err = session.AccountUpdateAvatar(ctx, &color, checkpoint)
	if err != nil || profile.AvatarColor == nil || *profile.AvatarColor != color {
		t.Fatal("avatar", err)
	}
	api, err := session.AccountAPIKey(ctx, AccountSensitiveInput{Password: password}, false, true, checkpoint)
	if err != nil || api.APIKey == "" {
		t.Fatal("api key", err)
	}
	rotated, err := session.AccountAPIKey(ctx, AccountSensitiveInput{Password: password}, true, true, checkpoint)
	if err != nil || rotated.APIKey == api.APIKey {
		t.Fatal("rotate API key", err)
	}
	api.APIKey = ""
	rotated.APIKey = ""
	if _, err = session.AccountAPIKey(ctx, AccountSensitiveInput{OTP: "000000"}, false, true, checkpoint); err == nil {
		t.Fatal("wrong OTP accepted")
	}
	fields := CipherFields{Type: 1, Name: "Account rewrap fixture"}
	if _, err = session.CreatePersonalCipher(ctx, vault.Scope, fields, checkpoint); err != nil {
		t.Fatal("create cipher", err)
	}
	login()
	changes := []AccountChangeKind{AccountChangePassword, AccountChangeKDF, AccountChangeEmail}
	for _, kind := range changes {
		next := []byte("Live-account-Replacement-Passphrase-948!")
		nextEmail := "changed-" + fixtureUUID() + "@example.invalid"
		if kind == AccountChangeEmail {
			if err = session.AccountRequestEmailChange(ctx, password, nextEmail, checkpoint); err != nil {
				t.Fatal("email token", err)
			}
		}
		plan, err := session.PrepareAccountCredentials(ctx, vault, kind, password, next, nextEmail, KDF{Type: 1, Iterations: 2, Memory: 16, Parallelism: 1}, "", "", checkpoint)
		if err != nil {
			t.Fatal("prepare", kind, err)
		}
		var recovery []byte
		result, err := session.CommitAccountChange(ctx, plan, string(kind), checkpoint, func(r AccountRecovery) error { recovery = mustAccountJSON(t, r); return nil })
		plan.Close()
		clear(recovery)
		if err != nil || !result.Confirmed {
			t.Fatal("commit", kind, err)
		}
		if kind == AccountChangePassword {
			clear(password)
			password = append([]byte(nil), next...)
		}
		clear(next)
		if kind == AccountChangeEmail {
			email = nextEmail
		}
		login()
		entries, err := session.PersonalEntries(vault)
		if err != nil || len(entries) != 1 || entries[0].Title != "Account rewrap fixture" {
			t.Fatal("decrypt after credential change", kind, err)
		}
	}
	// This test adapter is restricted to our self-created account: it proves
	// there are no memberships or emergency recipients, and handles item keys.
	adapter := accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
		converted, _ := accountEmptyRotation(ctx, in)
		var raw struct {
			Profile        struct{ Organizations, OrganizationsNew []json.RawMessage }
			Ciphers, Sends []json.RawMessage
			Folders        []AccountRotationFolder
		}
		if json.Unmarshal(in.Sync, &raw) != nil || raw.Profile.Organizations == nil || raw.Profile.OrganizationsNew == nil || len(raw.Profile.Organizations) != 0 || len(raw.Profile.OrganizationsNew) != 0 {
			return converted, ErrIdentity
		}
		trusted, err := in.Read(ctx, "/api/emergency-access/trusted")
		if err != nil {
			return converted, err
		}
		var contacts struct {
			Data              []json.RawMessage
			ContinuationToken *string
		}
		if json.Unmarshal(trusted, &contacts) != nil || contacts.Data == nil || len(contacts.Data) != 0 || contacts.ContinuationToken != nil {
			return converted, ErrIdentity
		}
		converted.Revalidate = func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
			body, err := read(ctx, "/api/emergency-access/trusted")
			if err != nil {
				return err
			}
			var current struct {
				Data              []json.RawMessage
				ContinuationToken *string
			}
			if json.Unmarshal(body, &current) != nil || current.Data == nil || len(current.Data) != 0 || current.ContinuationToken != nil {
				return ErrConflict
			}
			return nil
		}
		for _, row := range raw.Ciphers {
			rewrapped, err := AccountRewrapRotationCipher(row, in.OldUserKey, in.NewUserKey, in.Scope.Account)
			if err != nil {
				return converted, err
			}
			converted.Data.Ciphers = append(converted.Data.Ciphers, rewrapped)
		}
		for _, row := range raw.Sends {
			rewrapped, err := AccountRewrapRotationObject(row, in.OldUserKey, in.NewUserKey, 16)
			if err != nil {
				return converted, err
			}
			converted.Data.Sends = append(converted.Data.Sends, rewrapped)
		}
		for _, row := range raw.Folders {
			rewrapped, err := AccountRewrapRotationFolder(row, in.OldUserKey, in.NewUserKey)
			if err != nil {
				return converted, err
			}
			converted.Data.Folders = append(converted.Data.Folders, rewrapped)
		}
		return converted, nil
	})
	rotation, err := session.PrepareAccountRotation(ctx, vault, password, adapter, checkpoint)
	if err != nil {
		t.Fatal("prepare rotation", err)
	}
	var rotationRecovery []byte
	rotatedResult, err := session.CommitAccountChange(ctx, rotation, string(AccountRotateKey), checkpoint, func(r AccountRecovery) error { rotationRecovery = mustAccountJSON(t, r); return nil })
	rotation.Close()
	if err != nil || !rotatedResult.Confirmed {
		clear(rotationRecovery)
		t.Fatal("rotation", err)
	}
	var restored AccountRecovery
	_ = json.Unmarshal(rotationRecovery, &restored)
	clear(rotationRecovery)
	clear(originalKey)
	originalKey = append([]byte(nil), restored.NewUserKey...)
	restored.Close()
	login()
	rotatedEntries, err := session.PersonalEntries(vault)
	if err != nil || len(rotatedEntries) != 1 || rotatedEntries[0].Title != "Account rewrap fixture" {
		t.Fatal("decrypt rotated cipher", err)
	}
	for _, kind := range []AccountChangeKind{AccountSecurityStamp, AccountPurge, AccountDelete} {
		plan, err := session.PrepareAccountDestructive(ctx, vault, kind, AccountSensitiveInput{Password: password}, checkpoint)
		if err != nil {
			t.Fatal("prepare destructive", err)
		}
		var recovery []byte
		result, err := session.CommitAccountChange(ctx, plan, string(kind), checkpoint, func(r AccountRecovery) error { recovery = mustAccountJSON(t, r); return nil })
		plan.Close()
		clear(recovery)
		if err != nil || !result.Confirmed {
			t.Fatal("destructive", kind, err)
		}
		if kind != AccountDelete {
			login()
			if kind == AccountPurge {
				var raw struct{ Ciphers []json.RawMessage }
				_ = json.Unmarshal(vault.Sync, &raw)
				if len(raw.Ciphers) != 0 {
					t.Fatal("purge left ciphers")
				}
			}
		}
	}
	if s, err := client.Login(ctx, email, password, nil); err == nil {
		s.Close()
		t.Fatal("deleted account could login")
	}
}
