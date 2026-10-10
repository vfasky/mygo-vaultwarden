// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

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
	return i18n.Tf("尚未提交：%s", e.Cause.Error())
}

func (e *ResourcePreparationError) Unwrap() error { return e.Cause }
