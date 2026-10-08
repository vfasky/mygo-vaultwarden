// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

// AccountRotationEvidence is authenticated alongside the original recovery
// record. Public keys are independently trusted inputs captured by the actual
// prepare adapter, not a claim supplied by a recovery confirmation checkbox.
// The request digest binds this evidence to the one prepared server mutation.
type AccountRotationEvidence struct {
	Version       int                              `json:"version"`
	ServerVersion string                           `json:"serverVersion"`
	GitHash       string                           `json:"gitHash"`
	RequestDigest string                           `json:"requestDigest"`
	Contacts      []EmergencyContact               `json:"contacts"`
	Members       []RotationRecoveryMemberEvidence `json:"members"`
	Trust         RecoveryRotationTrust            `json:"trust"`
}
type RotationRecoveryMemberEvidence struct {
	OrganizationID string `json:"organizationId"`
	MemberID       string `json:"memberId"`
	UserID         string `json:"userId"`
	PublicKey      string `json:"publicKey"`
}
