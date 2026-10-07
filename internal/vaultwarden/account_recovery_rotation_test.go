// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Only for the deliberately empty personal vault used by this owned fixture.
// Production integration must compose the real schema/Send adapters.
type recoveryFixtureRotationAdapter struct {
	trust         RecoveryRotationTrust
	omitEmergency bool
}

func (a recoveryFixtureRotationAdapter) Convert(ctx context.Context, input AccountRotationInput) (AccountRotationConversion, error) {
	var doc struct{ Ciphers, Folders, Sends []json.RawMessage }
	if json.Unmarshal(input.Sync, &doc) != nil || len(doc.Ciphers) != 0 || len(doc.Folders) != 0 || len(doc.Sends) != 0 {
		return AccountRotationConversion{}, ErrValidation
	}
	c, err := RewrapRecoveryRotation(ctx, input, a.trust)
	if err != nil {
		return c, err
	}
	c.Data = AccountRotationData{Ciphers: []json.RawMessage{}, Folders: []AccountRotationFolder{}, Sends: []json.RawMessage{}}
	if a.omitEmergency {
		c.Emergency = []AccountRotationEmergency{}
		c.Coverage.EmergencyIDs = nil
	}
	return c, nil
}
func liveRecoveryRotate(t *testing.T, ctx context.Context, s *Session, v *VaultData, trust RecoveryRotationTrust, omit bool, syncVault func(*Session) *VaultData) (*Session, *VaultData) {
	t.Helper()
	password := []byte("Public-member-fixture-password!")
	old := bytes.Clone(s.key)
	defer clear(old)
	plan, err := s.PrepareAccountRotation(ctx, v, password, recoveryFixtureRotationAdapter{trust, omit}, nil)
	if err != nil {
		t.Fatal("rotation prepare", err)
	}
	defer plan.Close()
	result, err := s.CommitAccountChange(ctx, plan, plan.ConfirmationText(), nil, func(AccountRecovery) error { return nil })
	if omit {
		if err == nil || !result.Unknown || !result.Dispatched {
			t.Fatal("missing key not rejected", err)
		}
	} else if err != nil || !result.Confirmed {
		t.Fatal("nonempty recovery rotation", err)
	}
	fresh, err := s.client.Login(ctx, s.email, password, nil)
	if err != nil {
		t.Fatal("rotation login", err)
	}
	if omit && !bytes.Equal(fresh.key, old) {
		t.Fatal("missing key changed account")
	}
	if !omit && bytes.Equal(fresh.key, old) {
		t.Fatal("rotation did not change account key")
	}
	t.Log("nonempty rotation check", "missing-emergency-rejected", omit, "emergency-trust", len(trust.Users), "recovery-trust", len(trust.Organizations))
	return fresh, syncVault(fresh)
}
func TestRecoveryRotationNonemptyIdentityAndKeyRevalidation(t *testing.T) {
	key := bytes.Repeat([]byte{45}, 64)
	pair, err := makeOrganizationKeyPair(key)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := json.Marshal(map[string]string{"privateKey": pair.EncryptedPrivateKey})
	private, err := accountPrivateKey(profile, key)
	if err != nil {
		t.Fatal(err)
	}
	defer clearAccountPrivateKey(private)
	input := AccountRotationInput{Scope: Scope{Server: "http://localhost", Account: "account-a"}, Revision: "r", Epoch: 1, NewUserKey: bytes.Repeat([]byte{11}, 64), Sync: json.RawMessage(`{"profile":{"id":"account-a","organizations":[{"id":"org-a","organizationUserId":"member-a","userId":"account-a","status":2,"enabled":true,"resetPasswordEnrolled":true}]}}`)}
	public := pair.PublicKey
	state := 2
	input.Read = func(ctx context.Context, path string) (json.RawMessage, error) {
		switch path {
		case emergencyAvailabilityPath:
			return json.RawMessage(`{"emergencyAccessEnabled":true}`), nil
		case "/api/emergency-access/trusted":
			b, _ := json.Marshal(emergencyTestList(state, 1, true))
			return b, nil
		case "/api/users/account-b/public-key":
			b, _ := json.Marshal(map[string]string{"userId": "account-b", "publicKey": public})
			return b, nil
		case "/api/organizations/org-a/public-key":
			b, _ := json.Marshal(map[string]string{"publicKey": public})
			return b, nil
		}
		return nil, ErrPermission
	}
	trust := RecoveryRotationTrust{Users: map[string]string{"account-b": public}, Organizations: map[string]string{"org-a": public}}
	if _, err = RewrapRecoveryRotation(context.Background(), input, RecoveryRotationTrust{}); err == nil {
		t.Fatal("untrusted recovery key")
	}
	c, err := RewrapRecoveryRotation(context.Background(), input, trust)
	if err != nil || len(c.Emergency) != 1 || len(c.Recovery) != 1 {
		t.Fatal(err)
	}
	for _, wrapped := range []string{c.Emergency[0].KeyEncrypted, c.Recovery[0].ResetPasswordKey} {
		plain, e := unwrapOrganizationKey(wrapped, private)
		if e != nil || !bytes.Equal(plain, input.NewUserKey) {
			t.Fatal("wrong wrapped key", e)
		}
		clear(plain)
	}
	// Mutation of caller trust map cannot change the captured trusted metadata.
	trust.Users["account-b"] = "attacker"
	if err = c.Revalidate(context.Background(), input.Read); err != nil {
		t.Fatal(err)
	}
	state = 3
	if err = c.Revalidate(context.Background(), input.Read); err == nil {
		t.Fatal("changed state accepted")
	}
	state = 2
	public = "invalid"
	if err = c.Revalidate(context.Background(), input.Read); err == nil {
		t.Fatal("changed public key accepted")
	}
}
