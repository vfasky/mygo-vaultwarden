// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
	"sort"
)

const emergencyAvailabilityPath = "/api/emergency-access/00000000-0000-0000-0000-000000000000"

var ErrEmergencyUnavailable = i18n.Error("server.rotation.err_emergency_inventory_unavailable")

// The reserved GET is a capability probe, never an access request. 1.37.4
// checks enabled BEFORE record lookup; only the exact known missing-record
// response proves enabled. A 200 collision, arbitrary 400, proxy or translated
// error is deliberately unclassified. No raw error text escapes this function.
func recoveryAvailabilityResponse(status int, body []byte) (json.RawMessage, error) {
	var response struct {
		Message    string `json:"message"`
		ErrorModel *struct {
			Message string `json:"message"`
		} `json:"errorModel"`
	}
	if status != 400 || strictJSON(body) != nil || json.Unmarshal(body, &response) != nil {
		return nil, ErrEmergencyUnavailable
	}
	if response.Message != "Emergency access not valid." || response.ErrorModel == nil || response.ErrorModel.Message != response.Message {
		return nil, ErrEmergencyUnavailable
	}
	return json.RawMessage(`{"emergencyAccessEnabled":true}`), nil
}

// RecoveryRotationTrust is supplied only by trusted integration from prior
// independent recipient/organization key verification. Server keys alone are
// not trust anchors. This helper returns ONLY the emergency/recovery portion;
// the final adapter must compose cipher/folder/Send conversion separately.
type RecoveryRotationTrust struct{ Users, Organizations map[string]string }
type recoveryRotationMember struct{ OrganizationID, MemberID, UserID, PublicKey string }

func RewrapRecoveryRotation(ctx context.Context, input AccountRotationInput, trust RecoveryRotationTrust) (AccountRotationConversion, error) {
	out := AccountRotationConversion{Emergency: []AccountRotationEmergency{}, Recovery: []AccountRotationRecovery{}}
	if input.Read == nil || len(input.NewUserKey) != 64 || input.Scope.Account == "" || input.Revision == "" || input.Epoch == 0 {
		return out, ErrValidation
	}
	checkAvailable := func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
		body, e := read(ctx, emergencyAvailabilityPath)
		if e != nil {
			return e
		}
		if string(body) != `{"emergencyAccessEnabled":true}` {
			return ErrEmergencyUnavailable
		}
		return nil
	}
	if err := checkAvailable(ctx, input.Read); err != nil {
		return out, err
	}
	body, err := input.Read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		return out, err
	}
	contacts, err := decodeEmergencyContacts(body, true, input.Scope.Account)
	if err != nil {
		return out, err
	}
	sort.Slice(contacts, func(i, j int) bool { return contacts[i].ID < contacts[j].ID })
	userKeys := map[string]string{}
	for _, c := range contacts {
		if c.Status < 2 {
			continue
		}
		public, e := rotationRecoveryPublic(ctx, input.Read, "/api/users/"+c.GranteeID+"/public-key", c.GranteeID)
		if e != nil {
			return out, e
		}
		if public == "" || public != trust.Users[c.GranteeID] {
			return out, ErrIdentity
		}
		userKeys[c.GranteeID] = public
		wrapped, e := recoveryWrapUserKey(public, input.NewUserKey)
		if e != nil {
			return out, e
		}
		out.Emergency = append(out.Emergency, AccountRotationEmergency{ID: c.ID, KeyEncrypted: wrapped})
		out.Coverage.EmergencyIDs = append(out.Coverage.EmergencyIDs, c.ID)
	}
	var sync struct {
		Profile struct {
			ID            string
			Organizations []struct {
				Organization
				ResetPasswordEnrolled *bool
			}
		}
	}
	if strictJSON(input.Sync) != nil || json.Unmarshal(input.Sync, &sync) != nil || sync.Profile.ID != input.Scope.Account || sync.Profile.Organizations == nil {
		return out, ErrIdentity
	}
	members := []recoveryRotationMember{}
	seen := map[string]bool{}
	for _, org := range sync.Profile.Organizations {
		if !validObjectID(org.ID) || seen[org.ID] || org.UserID != input.Scope.Account || !validObjectID(org.OrganizationUserID) || org.ResetPasswordEnrolled == nil {
			return out, ErrIdentity
		}
		seen[org.ID] = true
		if !*org.ResetPasswordEnrolled {
			continue
		}
		if org.Status != 2 || !org.Enabled {
			return out, ErrPermission
		}
		public, e := rotationRecoveryPublic(ctx, input.Read, "/api/organizations/"+org.ID+"/public-key", "")
		if e != nil {
			return out, e
		}
		if public == "" || public != trust.Organizations[org.ID] {
			return out, ErrIdentity
		}
		wrapped, e := recoveryWrapUserKey(public, input.NewUserKey)
		if e != nil {
			return out, e
		}
		out.Recovery = append(out.Recovery, AccountRotationRecovery{OrganizationID: org.ID, ResetPasswordKey: wrapped})
		out.Coverage.RecoveryOrganizationIDs = append(out.Coverage.RecoveryOrganizationIDs, org.ID)
		members = append(members, recoveryRotationMember{org.ID, org.OrganizationUserID, org.UserID, public})
	}
	out.Coverage.Scope = input.Scope
	out.Coverage.Revision = input.Revision
	out.Coverage.Epoch = input.Epoch
	out.Coverage.SnapshotHash = input.SnapshotHash
	out.Coverage.EmergencyComplete = true
	out.Coverage.RecoveryComplete = true
	// Capture only metadata, no borrowed input keys/sync or trust maps.
	actor := input.Scope.Account
	out.Revalidate = func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
		if e := checkAvailable(ctx, read); e != nil {
			return e
		}
		body, e := read(ctx, "/api/emergency-access/trusted")
		if e != nil {
			return e
		}
		current, e := decodeEmergencyContacts(body, true, actor)
		if e != nil {
			return e
		}
		sort.Slice(current, func(i, j int) bool { return current[i].ID < current[j].ID })
		if !reflect.DeepEqual(current, contacts) {
			return ErrConflict
		}
		for id, want := range userKeys {
			got, e := rotationRecoveryPublic(ctx, read, "/api/users/"+id+"/public-key", id)
			if e != nil {
				return e
			}
			if got != want {
				return ErrConflict
			}
		}
		for _, member := range members {
			got, e := rotationRecoveryPublic(ctx, read, "/api/organizations/"+member.OrganizationID+"/public-key", "")
			if e != nil {
				return e
			}
			if got != member.PublicKey {
				return ErrConflict
			}
		}
		// Account rotation additionally compares fresh profile to the prepared sync,
		// including membership IDs and resetPasswordEnrolled, before invoking this.
		return nil
	}
	return out, nil
}
func rotationRecoveryPublic(ctx context.Context, read func(context.Context, string) (json.RawMessage, error), path, user string) (string, error) {
	body, err := read(ctx, path)
	if err != nil {
		return "", err
	}
	var response struct{ UserID, PublicKey string }
	if strictJSON(body) != nil || json.Unmarshal(body, &response) != nil || (user != "" && response.UserID != user) {
		return "", ErrIdentity
	}
	if _, err = decodeRecoveryPublicKey(response.PublicKey); err != nil {
		return "", err
	}
	return response.PublicKey, nil
}
