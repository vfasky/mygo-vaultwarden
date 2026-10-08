// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"reflect"
)

// AccountRotationCipherInventoryEqual compares full authoritative cipher arrays,
// excluding only attachment download URLs. Vaultwarden 1.37.4 attachment.rs
// get_url/to_json generates expiring JWT or presigned URLs for each response.
// IDs, order, wrappers, names, sizes, revisions, unknown fields and nulls all
// remain exact. Invalid/duplicate inventory fails closed. This is suitable for
// the account prepare/preflight freshness gate, not resource recovery acceptance.
func AccountRotationCipherInventoryEqual(a, b json.RawMessage) bool {
	decode := func(raw json.RawMessage) ([]map[string]any, error) {
		if strictJSON(raw) != nil {
			return nil, ErrProtocol
		}
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 100000 {
			return nil, ErrProtocol
		}
		result := make([]map[string]any, 0, len(rows))
		seen := map[string]bool{}
		for _, row := range rows {
			object, err := rotationCipherObject(row)
			if err != nil {
				return nil, err
			}
			id, ok := object["id"].(string)
			if !ok || !validObjectID(id) || seen[id] {
				return nil, ErrProtocol
			}
			seen[id] = true
			kind, ok := object["type"].(json.Number)
			if !ok {
				return nil, ErrProtocol
			}
			n, err := kind.Int64()
			if err != nil || cipherSections[int(n)] == "" {
				return nil, ErrProtocol
			}
			if org := object["organizationId"]; org != nil {
				id, ok := org.(string)
				if !ok || !validObjectID(id) {
					return nil, ErrIdentity
				}
			}
			if _, err = shareRecoveryAttachments(object); err != nil {
				return nil, err
			}
			attachments, _ := object["attachments"].([]any)
			for _, raw := range attachments {
				attachment := raw.(map[string]any)
				if name, ok := attachment["fileName"].(string); !ok || name == "" {
					return nil, ErrProtocol
				}
				if _, ok := attachment["size"].(string); !ok {
					return nil, ErrProtocol
				}
				if key := attachment["key"]; key != nil {
					if _, ok := key.(string); !ok {
						return nil, ErrProtocol
					}
				}
				if url, exists := attachment["url"]; exists {
					if _, ok := url.(string); !ok {
						return nil, ErrProtocol
					}
					attachment["url"] = "" // Preserve presence: missing URL is still a difference.
				}
			}
			result = append(result, object)
		}
		return result, nil
	}
	left, err := decode(a)
	if err != nil {
		return false
	}
	right, err := decode(b)
	return err == nil && reflect.DeepEqual(left, right)
}
