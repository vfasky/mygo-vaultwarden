// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"errors"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"strings"
	"testing"
)

func TestDomainErrorPresentationRetainsGuidanceAndIdentity(t *testing.T) {
	defer i18n.Set(i18n.Current())
	sentinels := []struct {
		err error
		key string
	}{
		{ErrSendPasswordRequired, "server.send.err_password_required"},
		{ErrSendPasswordInvalid, "server.send.err_password_invalid"},
		{ErrRecoveryUnverified, "server.recovery.err_unverified"},
		{ErrDeviceUnknown, "account.device_login.err_unknown_device"},
		{ErrDeviceRejected, "account.device_login.err_approval_rejected"},
		// Allocate once, before language changes: the merged helper must retain
		// identity while translating through the trusted display boundary.
		{i18n.Error("common.save"), "common.save"},
	}
	for _, lang := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(lang)
		for _, tc := range sentinels {
			wrapped := fmt.Errorf("secret response payload: %w", tc.err)
			if !errors.Is(wrapped, tc.err) || ErrorMessage(wrapped) != i18n.T(tc.key) {
				t.Fatalf("lost identity or current translation for %s", tc.key)
			}
		}
		cause := localError("server.backup.err_attachment_filename", ErrUnsupportedEdit, "attachment-id")
		if !errors.Is(cause, ErrUnsupportedEdit) || !strings.Contains(ErrorMessage(cause), "attachment-id") || strings.Contains(ErrorMessage(cause), "vaultwarden:") {
			t.Fatal("lost actionable attachment guidance")
		}
		conversion := &BackupConversionError{Index: 2, Reason: ErrorMessage(cause), Cause: cause}
		if got := ErrorMessage(fmt.Errorf("secret: %w", conversion)); got != conversion.Error() || !strings.Contains(got, "3") {
			t.Fatal("lost conversion index or reason")
		}
		preparation := &RotationCipherPreparationError{}
		if ErrorMessage(preparation) != i18n.T("server.rotation.err_attachment_preparation") || !errors.Is(preparation, ErrUnsupportedEdit) {
			t.Fatal("lost rotation preparation guidance")
		}
		if got := ErrorMessage(fmt.Errorf("secret URL/token: %w", errors.New("secret body"))); got != i18n.T("error.unknown") {
			t.Fatal("unknown error exposed untrusted data")
		}
	}
}
