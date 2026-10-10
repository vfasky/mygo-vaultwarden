// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/sha256"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"time"
)

type CipherRowPreview struct {
	Index                 int
	Name, Value, Metadata string
	HasUnknown            bool
}

// WithCipherComparisonRows authorizes an explicit short-lived view of both
// versions so a user can choose real row correspondence, not guess by index.
func (s *Session) WithCipherComparisonRows(vault *VaultData, revision string, plan *CipherRebase, path string, use func([]CipherRowPreview, []CipherRowPreview, []byte, time.Time) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if plan == nil || plan.session != s || revision != plan.revision || revision != s.authorizationRevision || (s.passwordUnlock == nil && !s.runtimeOnly) || use == nil {
		return ErrExpired
	}
	latest, err := s.personalDocumentLocked(vault, plan.merged.ID)
	if err != nil {
		return err
	}
	if sha256.Sum256(latest.JSON) != sha256.Sum256(plan.latest.JSON) {
		return ErrConflict
	}
	if plan.merged.Reprompt != 0 && !s.validItemAuthorizationLocked(plan.grant, latest) {
		return ErrPermission
	}
	allowed := false
	for _, change := range plan.changes {
		if change.Path == path && change.Local && change.Remote && !change.CanApply {
			allowed = true
		}
	}
	if !allowed {
		return ErrValidation
	}
	local, err := cipherArrayRows(path, plan.values[path])
	if err != nil {
		return err
	}
	remote, err := cipherArrayRows(path, cipherEditableValues(plan.merged)[path])
	if err != nil {
		return err
	}
	preview := func(rows []map[string]any) ([]CipherRowPreview, error) {
		values := make([]CipherRowPreview, 0, len(rows))
		total := 0
		for i, row := range rows {
			value := CipherRowPreview{Index: i}
			known := map[string]bool{"name": true, "value": true, "type": true, "linkedId": true}
			if path == "login.uris" {
				value.Name = i18n.T("vault.field.uri")
				value.Value, _ = row["uri"].(string)
				value.Metadata = i18n.Tf("server.rebase.match_rule", row["match"])
				known = map[string]bool{"uri": true, "match": true, "uriChecksum": true}
			} else {
				value.Name, _ = row["name"].(string)
				value.Value, _ = row["value"].(string)
				value.Metadata = i18n.Tf("server.rebase.field_metadata", row["type"], row["linkedId"])
			}
			for key := range row {
				if !known[key] {
					value.HasUnknown = true
				}
			}
			total += len(value.Name) + len(value.Value) + len(value.Metadata)
			if len(value.Name) > 4096 || len(value.Value) > 65536 || total > MaxBackupSize {
				return nil, ErrValidation
			}
			values = append(values, value)
		}
		return values, nil
	}
	l, err := preview(local)
	if err != nil {
		return err
	}
	defer clear(l)
	r, err := preview(remote)
	if err != nil {
		return err
	}
	defer clear(r)
	deadline := time.Now().Add(30 * time.Second)
	if plan.grant != nil && plan.grant.expires.Before(deadline) {
		deadline = plan.grant.expires
	}
	key, err := s.secretProtectionKeyLocked()
	if err != nil {
		return err
	}
	deadline = s.secretDeadlineLocked(deadline)
	defer clear(key)
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || s.closed {
		return ErrExpired
	}
	return use(l, r, key, deadline)
}
