// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"time"
)

// A long multi-file archive must not keep an early file's publication capability
// alive. After consuming those capabilities while the archive is still private,
// fetch one new authenticated sync and recheck every selected source together.
// This preserves bounded publication age without imposing a 30-second total
// download limit or retaining a full cipher document per attachment.
func (s *Session) prepareResourcePublication(ctx context.Context, proof *ResourceBackupPublication, grants map[string]*ItemAuthorization, persist func(SessionCheckpoint) error, online bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if proof == nil || proof.session != s || proof.revision == "" || proof.revision != s.authorizationRevision || proof.epoch != s.authorizationEpoch {
		return ErrExpired
	}
	snapshotPolicies, err := s.snapshotPoliciesLocked(proof.vault)
	if err != nil {
		return err
	}
	if online {
		policies, err := s.operationPoliciesLocked(ctx, persist)
		if err != nil {
			return err
		}
		fresh := map[string]CipherDocument{}
		for _, raw := range policies.ciphers {
			var meta struct{ ID string }
			if json.Unmarshal(raw, &meta) != nil || fresh[meta.ID].JSON != nil {
				return ErrProtocol
			}
			fresh[meta.ID] = CipherDocument{JSON: raw}
		}
		documents, err := proof.vault.Documents(proof.vault.Scope)
		if err != nil {
			return err
		}
		needed := map[string]bool{}
		for _, id := range proof.ids {
			needed[id] = true
		}
		var organizations *organizationVault
		defer func() {
			if organizations != nil {
				organizations.close()
			}
		}()
		for _, document := range documents {
			var meta struct {
				ID             string
				Type, Reprompt int
				OrganizationID *string
				ViewPassword   *bool
			}
			if json.Unmarshal(document.JSON, &meta) != nil {
				return ErrProtocol
			}
			if !needed[meta.ID] {
				continue
			}
			delete(needed, meta.ID)
			if meta.ViewPassword == nil || !*meta.ViewPassword || meta.Reprompt < 0 || meta.Reprompt > 1 || policies.restricts(meta.OrganizationID, meta.Type) {
				return ErrPermission
			}
			if !attachmentSameDocument(document, fresh[meta.ID], false, false) {
				return ErrConflict
			}
			if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[meta.ID], document) {
				return ErrPermission
			}
			if meta.OrganizationID != nil {
				if organizations == nil {
					organizations, err = s.organizationVaultLocked(proof.vault)
					if err != nil {
						return err
					}
				}
				if _, _, err = organizationDocumentWithPolicies(meta.ID, organizations, snapshotPolicies); err != nil {
					return err
				}
				member, ok := policies.memberships[*meta.OrganizationID]
				if !ok || member.Status == nil || *member.Status != 2 || member.Enabled == nil || !*member.Enabled || member.Type == nil {
					return ErrPermission
				}
				matched := false
				for _, local := range organizations.organizations {
					if local.ID == *meta.OrganizationID && local.OrganizationUserID == member.MemberID && local.UserID == member.UserID && local.Type == *member.Type {
						matched = true
					}
				}
				if !matched {
					return ErrExpired
				}
			}
		}
		if len(needed) != 0 {
			return ErrNotFound
		}
		if err = s.checkOperationPoliciesLocked(ctx, policies); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if proof.revision != s.authorizationRevision || proof.epoch != s.authorizationEpoch || !s.itemSessionActiveLocked() {
		return ErrExpired
	}
	proof.expires = time.Now().Add(30 * time.Second)
	return nil
}
