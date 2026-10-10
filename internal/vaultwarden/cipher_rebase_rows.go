// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
)

// CipherRowChoice explicitly maps a local row to a remote row. Remote=-1 appends
// a separate row. Omitted rows retain the remote version; indices are positions
// in the pinned comparison, never an inferred persistent row identity.
type CipherRowChoice struct {
	Path          string
	Local, Remote int
}

func cipherArrayRows(path string, value any) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if path == "fields" {
		rows, ok := value.([]map[string]any)
		if !ok {
			return nil, ErrProtocol
		}
		return rows, nil
	}
	if path != "login.uris" {
		return nil, ErrValidation
	}
	values, ok := value.([]any)
	if !ok {
		return nil, ErrProtocol
	}
	rows := make([]map[string]any, len(values))
	for i, value := range values {
		var ok bool
		rows[i], ok = value.(map[string]any)
		if !ok {
			return nil, ErrProtocol
		}
	}
	return rows, nil
}

func cipherArrayLabels(path string, value any) []string {
	rows, err := cipherArrayRows(path, value)
	if err != nil {
		return nil
	}
	labels := make([]string, len(rows))
	for i, row := range rows {
		// Do not expose URI query strings, hidden values or custom names here. The
		// row position corresponds to the user's already visible source form.
		label := i18n.T("网址与匹配规则")
		if path == "fields" {
			label = i18n.Tf("自定义字段（类型 %v）", row["type"])
		}
		labels[i] = i18n.Tf("第 %d 行 · %s", i+1, label)
	}
	return labels
}

func applyCipherRowChoices(plan *CipherRebase, fields *CipherFields, choices []CipherRowChoice) error {
	if len(choices) > 10000 {
		return ErrValidation
	}
	localSeen, remoteSeen := map[string]bool{}, map[string]bool{}
	arrays := map[string][]map[string]any{}
	originalLengths := map[string]int{}
	for _, choice := range choices {
		allowed := false
		for _, change := range plan.changes {
			if change.Path == choice.Path && change.Local && change.Remote && !change.CanApply {
				allowed = true
			}
		}
		if !allowed {
			return ErrUnsupportedEdit
		}
		local, err := cipherArrayRows(choice.Path, plan.values[choice.Path])
		if err != nil {
			return err
		}
		if choice.Local < 0 || choice.Local >= len(local) || choice.Remote < -1 {
			return ErrValidation
		}
		localID := fmt.Sprintf("%s/%d", choice.Path, choice.Local)
		if localSeen[localID] {
			return ErrValidation
		}
		localSeen[localID] = true
		remote, exists := arrays[choice.Path]
		if !exists {
			value := any(fields.Fields)
			if choice.Path == "login.uris" {
				value = fields.Login["uris"]
			}
			remote, err = cipherArrayRows(choice.Path, value)
			if err != nil {
				return err
			}
			remote = append([]map[string]any(nil), remote...)
			originalLengths[choice.Path] = len(remote)
		}
		target := map[string]any{}
		if choice.Remote >= 0 {
			if choice.Remote >= originalLengths[choice.Path] {
				return ErrValidation
			}
			remoteID := fmt.Sprintf("%s/%d", choice.Path, choice.Remote)
			if remoteSeen[remoteID] {
				return ErrValidation
			}
			remoteSeen[remoteID] = true
			for key, value := range remote[choice.Remote] {
				target[key] = value
			}
		}
		names := []string{"name", "value", "type", "linkedId"}
		if choice.Path == "login.uris" {
			names = []string{"uri", "match", "uriChecksum"}
		}
		known := map[string]bool{}
		for _, name := range names {
			known[name] = true
		}
		for name, value := range local[choice.Local] {
			if !known[name] && choice.Remote >= 0 {
				// Never replace an unknown extension or silently lose a local extension.
				remoteValue, exists := target[name]
				if !exists || !reflect.DeepEqual(remoteValue, value) {
					return ErrUnsupportedEdit
				}
			} else {
				target[name] = value
			}
		}
		for _, name := range names {
			if _, exists := local[choice.Local][name]; !exists {
				delete(target, name)
			}
		}
		if choice.Remote < 0 {
			remote = append(remote, target)
		} else {
			remote[choice.Remote] = target
		}
		if len(remote) > 10000 || (choice.Path == "login.uris" && len(remote) > 128) {
			return ErrValidation
		}
		arrays[choice.Path] = remote
	}
	for path, rows := range arrays {
		if path == "fields" {
			fields.Fields = rows
		} else {
			values := make([]any, len(rows))
			for i, row := range rows {
				values[i] = row
			}
			fields.Login["uris"] = values
		}
	}
	return nil
}
