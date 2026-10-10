// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "encoding/json"

// backupIdentity validates the fields consumed by preview and restore. Keep the
// original object for lossless round trips; this view never discards extensions.
type backupIdentity struct {
	ID, Name string
	Type     int
}

func backupItemIdentity(item map[string]any) (backupIdentity, error) {
	id, idOK := item["id"].(string)
	name, nameOK := item["name"].(string)
	number, typeOK := item["type"].(json.Number)
	if !idOK || !validObjectID(id) || !nameOK || !typeOK {
		return backupIdentity{}, ErrProtocol
	}
	kind, err := number.Int64()
	if err != nil || kind < 1 || kind > 8 {
		return backupIdentity{}, ErrUnsupportedEdit
	}
	return backupIdentity{ID: id, Name: name, Type: int(kind)}, nil
}

// backupObjectRows accepts the optional null/absent list but rejects malformed
// containers and elements, even when a caller has already run schema validation.
func backupObjectRows(value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	rows, ok := value.([]any)
	if !ok {
		return nil, ErrProtocol
	}
	result := make([]map[string]any, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok || row == nil {
			return nil, ErrProtocol
		}
		result = append(result, row)
	}
	return result, nil
}
