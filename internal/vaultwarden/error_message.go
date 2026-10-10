// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"errors"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

// ErrorMessage is the presentation boundary for Vaultwarden errors. Preserve
// uncertain-write warnings before examining any wrapped transport sentinel.
// Other packages must map their own trusted domain errors before this fallback.
func ErrorMessage(err error) string {
	var uncertain *MutationUncertainError
	if errors.As(err, &uncertain) && uncertain != nil {
		return uncertain.Error()
	}
	var upload *SendUploadError
	if errors.As(err, &upload) && upload != nil {
		return upload.Error()
	}
	return vaulterr.ErrorMessage(err)
}
