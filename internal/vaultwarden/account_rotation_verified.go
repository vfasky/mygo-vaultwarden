// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
	"sort"
)

const rotationGit1374 = "7c188967e7a467b19b2757bc3326f9cf3ccae327"

var ErrRotationCompatibility = errors.New(i18n.T("无法确认支持完整恢复核验的 Vaultwarden 1.37.4 实现，未提交用户密钥轮换"))

// This is a compatibility declaration over the configured trusted server/TLS
// origin, not attestation of its binary. /api/config.version is deliberately
// ignored: it advertises Bitwarden compatibility, not the Vaultwarden release.
func (c *Client) rotationCompatibility(ctx context.Context) (string, string, error) {
	status, raw, err := c.request(ctx, "GET", "/api/version", "", "", "")
	if err != nil {
		return "", "", err
	}
	var version string
	if status != 200 || strictJSON(raw) != nil || json.Unmarshal(raw, &version) != nil || version != "1.37.4" {
		return "", "", ErrRotationCompatibility
	}
	status, raw, err = c.request(ctx, "GET", "/api/config", "", "", "")
	if err != nil {
		return "", "", err
	}
	var config struct {
		GitHash string `json:"gitHash"`
		Server  struct{ Name, URL string }
	}
	if status != 200 || strictJSON(raw) != nil || json.Unmarshal(raw, &config) != nil || config.Server.Name != "Vaultwarden" || config.Server.URL != "https://github.com/dani-garcia/vaultwarden" || (config.GitHash != rotationGit1374 && config.GitHash != "7c188967") {
		return "", "", ErrRotationCompatibility
	}
	return version, config.GitHash, nil
}

type RotationTrustRecipient struct{ ID, Name, Email string }
type RotationTrustRequirements struct{ Users, Organizations []RotationTrustRecipient }

func (s *Session) AccountRotationTrustRequirements(ctx context.Context, vault *VaultData, persist func(SessionCheckpoint) error) (RotationTrustRequirements, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return RotationTrustRequirements{}, err
	}
	defer done()
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return RotationTrustRequirements{}, err
	}
	if _, _, err = s.client.rotationCompatibility(ctx); err != nil {
		return RotationTrustRequirements{}, err
	}
	contacts, err := s.emergencyContactsLocked(ctx, true, persist, s.recoveryGuardLocked(s.authorizationEpoch, s.authorizationRevision))
	if err != nil {
		return RotationTrustRequirements{}, err
	}
	result := RotationTrustRequirements{Users: []RotationTrustRecipient{}, Organizations: []RotationTrustRecipient{}}
	for _, c := range contacts {
		if c.Status >= 2 {
			result.Users = append(result.Users, RotationTrustRecipient{ID: c.GranteeID, Name: c.Name, Email: c.Email})
		}
	}
	var sync struct {
		Profile struct {
			Organizations []struct {
				Organization
				ResetPasswordEnrolled *bool
			}
		}
	}
	if json.Unmarshal(vault.Sync, &sync) != nil || sync.Profile.Organizations == nil {
		return result, ErrProtocol
	}
	for _, org := range sync.Profile.Organizations {
		if org.ResetPasswordEnrolled == nil {
			return result, ErrProtocol
		}
		if *org.ResetPasswordEnrolled {
			result.Organizations = append(result.Organizations, RotationTrustRecipient{ID: org.ID, Name: org.Name})
		}
	}
	return result, nil
}

type completeRotationAdapter struct {
	trust    RecoveryRotationTrust
	evidence *AccountRotationEvidence
}

func (a completeRotationAdapter) Convert(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
	out, err := RewrapRecoveryRotation(ctx, in, a.trust)
	if err != nil {
		return out, err
	}
	ciphers, err := ConvertAccountRotationCipherResources(ctx, in)
	if err != nil {
		return out, err
	}
	sends, err := ConvertSendRotationResources(ctx, in)
	if err != nil {
		return out, err
	}
	out.Data = AccountRotationData{Ciphers: ciphers.Ciphers, Folders: ciphers.Folders, Sends: sends}
	raw, err := in.Read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		return out, err
	}
	contacts, err := decodeEmergencyContacts(raw, true, in.Scope.Account)
	if err != nil {
		return out, err
	}
	sort.Slice(contacts, func(i, j int) bool { return contacts[i].ID < contacts[j].ID })
	a.evidence.Contacts = contacts
	var sync struct {
		Profile struct {
			Organizations []struct {
				Organization
				ResetPasswordEnrolled *bool
			}
		}
	}
	if json.Unmarshal(in.Sync, &sync) != nil || sync.Profile.Organizations == nil {
		return out, ErrProtocol
	}
	a.evidence.Members = []RotationRecoveryMemberEvidence{}
	for _, org := range sync.Profile.Organizations {
		if org.ResetPasswordEnrolled == nil {
			return out, ErrProtocol
		}
		if *org.ResetPasswordEnrolled {
			a.evidence.Members = append(a.evidence.Members, RotationRecoveryMemberEvidence{OrganizationID: org.ID, MemberID: org.OrganizationUserID, UserID: org.UserID, PublicKey: a.trust.Organizations[org.ID]})
		}
	}
	// Bind the additional evidence enumeration to the same preflight that the
	// account layer executes immediately before its one sensitive mutation.
	original := out.Revalidate
	actor := in.Scope.Account
	out.Revalidate = func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
		if err := original(ctx, read); err != nil {
			return err
		}
		raw, err := read(ctx, "/api/emergency-access/trusted")
		if err != nil {
			return err
		}
		fresh, err := decodeEmergencyContacts(raw, true, actor)
		if err != nil {
			return err
		}
		sort.Slice(fresh, func(i, j int) bool { return fresh[i].ID < fresh[j].ID })
		if !reflect.DeepEqual(fresh, contacts) {
			return ErrConflict
		}
		return nil
	}
	return out, nil
}

// PrepareVerifiedAccountRotation is the production composition. It stores the
// precise metadata used by the non-empty converters before the recovery Begin
// callback can allow POST. No credential material is supplied by a UI verdict.
func (s *Session) PrepareVerifiedAccountRotation(ctx context.Context, vault *VaultData, password []byte, trust RecoveryRotationTrust, persist func(SessionCheckpoint) error) (*AccountChangePlan, error) {
	version, commit, err := s.client.rotationCompatibility(ctx)
	if err != nil {
		return nil, err
	}
	copied := RecoveryRotationTrust{Users: map[string]string{}, Organizations: map[string]string{}}
	for id, key := range trust.Users {
		copied.Users[id] = key
	}
	for id, key := range trust.Organizations {
		copied.Organizations[id] = key
	}
	evidence := &AccountRotationEvidence{Version: 1, ServerVersion: version, GitHash: commit, Trust: copied}
	plan, err := s.PrepareAccountRotation(ctx, vault, password, completeRotationAdapter{copied, evidence}, persist)
	if err != nil {
		return nil, err
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	digest := sha256.Sum256(plan.recovery.Request)
	evidence.RequestDigest = hex.EncodeToString(digest[:])
	plan.recovery.RotationEvidence = evidence
	original := plan.preflight
	plan.preflight = func(ctx context.Context) error {
		currentVersion, currentCommit, err := s.client.rotationCompatibility(ctx)
		if err != nil {
			return err
		}
		if currentVersion != version || currentCommit != commit {
			return ErrRotationCompatibility
		}
		return original(ctx)
	}
	return plan, nil
}
