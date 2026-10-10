// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

func TestBackendEnglishTextAndStableRecoveryState(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)

	definitions := OrganizationPolicyDefinitions()
	if definitions[1].Name != "Master password requirements" || definitions[1].Fields[0].Label != "Minimum strength score (0–4)" {
		t.Fatalf("policy text is not English: %+v", definitions[1])
	}
	review := &PolicyRecoveryReview{}
	if got := review.Summary()[1]; got != "Current member role: No valid membership" {
		t.Fatalf("policy recovery summary: %q", got)
	}
	if got := backupError(2, "detail").Error(); got != "Item 3 cannot be converted without data loss: detail" {
		t.Fatalf("backup error: %q", got)
	}
	inspection, err := inspectShareRecovery(cipherShareRecoveryPayload{}, CipherDocument{})
	if err != nil || inspection.CipherState != ShareRecoveryMissing {
		t.Fatalf("English must preserve recovery state: %+v, %v", inspection, err)
	}
	if got := ShareRecoveryStateText(inspection.CipherState); got != "Missing" {
		t.Fatalf("recovery display text: %q", got)
	}
}
