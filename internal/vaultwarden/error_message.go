// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"errors"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
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
	var conversion *BackupConversionError
	if errors.As(err, &conversion) && conversion != nil {
		return conversion.Error()
	}
	var unsupported backupUnsupportedError
	if errors.As(err, &unsupported) {
		return unsupported.Error()
	}
	var preparation *RotationCipherPreparationError
	if errors.As(err, &preparation) && preparation != nil {
		return i18n.T("server.rotation.err_attachment_preparation")
	}
	if errors.Is(err, ErrDeviceUnknown) {
		return i18n.T("account.device_login.err_unknown_device")
	}
	if errors.Is(err, ErrDeviceRejected) {
		return i18n.T("account.device_login.err_approval_rejected")
	}
	// Only explicitly trusted local error types opt into displaying their text.
	// Never pass arbitrary transport errors or wrapped server responses through.
	var message interface{ UserMessage() string }
	if errors.As(err, &message) {
		return message.UserMessage()
	}
	return vaulterr.ErrorMessage(err)
}
