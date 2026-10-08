// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRecoveryExpectationSchemaAndValueCopies(t *testing.T) {
	expectation, err := recoveryExpectation("administrator-recovery", bytes.Repeat([]byte{7}, 64), "exact-final-wrapper", true, true)
	if err != nil {
		t.Fatal(err)
	}
	original := RecoveryDispatch{Kind: "administrator-recovery", RequireTargetLogin: true, Verification: expectation}
	plan := &RecoveryPlan{record: original}
	external := plan.Summary()
	external.Verification = RecoveryVerificationExpectation{}
	if plan.Summary().Verification != expectation {
		t.Fatal("Summary aliases internal expectation")
	}
	if expectation.ExpectedMasterWrapperSHA256 != recoveryWitness([]byte("exact-final-wrapper")) {
		t.Fatal("wrapper witness not bound to actual bytes")
	}
	raw, _ := json.Marshal(original)
	if _, err := DecodeRecoveryDispatch(raw); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "null", "unknown", "version", "bits", "wrapper"} {
		t.Run(mode, func(t *testing.T) {
			var object map[string]any
			json.Unmarshal(raw, &object)
			fields := object["Verification"].(map[string]any)
			switch mode {
			case "missing":
				delete(fields, "ResetMFA")
			case "null":
				fields["ResetMFA"] = nil
			case "unknown":
				fields["UnrecognizedIntent"] = true
			case "version":
				fields["Version"] = 2
			case "bits":
				fields["RemoveNonOwnerMemberships"] = true
			case "wrapper":
				fields["ResetPassword"] = false
			}
			changed, _ := json.Marshal(object)
			if _, err := DecodeRecoveryDispatch(changed); err == nil {
				t.Fatal("invalid expectation accepted")
			}
		})
	}
	original.Verification = RecoveryVerificationExpectation{}
	legacy, _ := json.Marshal(original)
	decoded, err := DecodeRecoveryDispatch(legacy)
	if err != nil || decoded.Verification != (RecoveryVerificationExpectation{}) {
		t.Fatal("legacy inspection changed")
	}
	if decoded.Verification.Validate(decoded.Kind) == nil {
		t.Fatal("legacy record invented an expectation")
	}
}
