// SPDX-License-Identifier: GPL-3.0-only
package zxcvbn

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDistributionIntegrity(t *testing.T) {
	digest := sha256.Sum256([]byte(Script))
	if hex.EncodeToString(digest[:]) != "f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a" {
		t.Fatal("official distribution modified")
	}
}
