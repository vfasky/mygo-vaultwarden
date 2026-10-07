// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "encoding/json"

// AccountRewrapRotationCipher converts a full sync cipher with an independent
// item key into the server's CipherData request. CipherData requires encryptedFor
// even though it is absent from /sync. All opaque fields and integer tokens are
// preserved, since their item key is unchanged. Legacy keyless ciphers need the
// schema-specific adapter. Organization ciphers must never enter this DTO.
func AccountRewrapRotationCipher(raw json.RawMessage, oldKey, newKey []byte, account string) (json.RawMessage, error) {
	if !validObjectID(account) {
		return nil, ErrIdentity
	}
	var identity struct {
		ID               string  `json:"id"`
		OrganizationID   *string `json:"organizationId"`
		EncryptedByKeyID *string `json:"encryptedByKeyId"`
		Revision         string  `json:"revisionDate"`
	}
	if json.Unmarshal(raw, &identity) != nil || !validObjectID(identity.ID) || identity.OrganizationID != nil {
		return nil, ErrIdentity
	}
	if identity.EncryptedByKeyID != nil && *identity.EncryptedByKeyID != "" {
		return nil, ErrProtocol
	}
	converted, err := AccountRewrapRotationObject(raw, oldKey, newKey, 64)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(converted, &fields)
	fields["encryptedFor"], _ = json.Marshal(account)
	if identity.Revision != "" {
		fields["lastKnownRevisionDate"], _ = json.Marshal(identity.Revision)
	}
	return json.Marshal(fields)
}
