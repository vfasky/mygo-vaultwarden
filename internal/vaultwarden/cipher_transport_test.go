// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "context"

// Test-only transport helpers support method assertions and disposal of fixtures
// owned by live integration tests. They are absent from the production package:
// the UI must use document-bound authorization, never an ID-only state mutation.
func (s *Session) ChangeCipherState(ctx context.Context, scope Scope, id string, action CipherAction, persist func(SessionCheckpoint) error) error {
	return s.changeCipherState(ctx, scope, id, action, persist, nil)
}
func (s *Session) SetCipherPersonalMetadata(ctx context.Context, scope Scope, id string, folderID *string, favorite bool, persist func(SessionCheckpoint) error) error {
	return s.setCipherPersonalMetadataUnchecked(ctx, scope, id, folderID, favorite, persist)
}
