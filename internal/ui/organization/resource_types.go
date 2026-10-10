// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Resource states are in-memory workflow identifiers; translate only for display.
const (
	ResourceNotStarted    = "not_started"
	ResourcePendingVerify = "pending_verify"
	ResourceVerified      = "verified"
	ResourcePendingSync   = "pending_sync"
)

func ResourceStateText(state string) string {
	switch state {
	case ResourceNotStarted:
		return i18n.T("state.resource.status_not_started")
	case ResourcePendingVerify:
		return i18n.T("state.resource.status_pending_verify")
	case ResourceVerified:
		return i18n.T("state.resource.status_verified")
	case ResourcePendingSync:
		return i18n.T("state.resource.status_pending_sync")
	default:
		return state
	}
}

type ResourceRow struct {
	Resource                    vaultwarden.BackupResource
	Target, AttachmentID, State string
	Problem                     string
}

// A callback refusing BEFORE entering the resource mutation is distinguishable
// from an entered API with an unknown server result. It never licenses retries
// of a possibly dispatched request.
type ResourcePreparationError struct{ Cause error }

func (e *ResourcePreparationError) Error() string {
	return i18n.Tf("org.resource.err_not_submitted", e.Cause.Error())
}

func (e *ResourcePreparationError) Unwrap() error { return e.Cause }
