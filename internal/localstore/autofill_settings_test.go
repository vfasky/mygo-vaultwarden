// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"encoding/json"
	"testing"
)

func TestAutofillSettingsWire(t *testing.T) {
	if !OperationAutofillSettings.Valid() || OperationAutofillSettings.AllowsTransfer() {
		t.Fatal("AutoFill preferences must use the control path")
	}
	for _, test := range []struct {
		name  string
		value *bool
		want  string
	}{
		{name: "read", want: ""},
		{name: "disable", value: boolValue(false), want: "false"},
		{name: "enable", value: boolValue(true), want: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(Request{Operation: OperationAutofillSettings, AutofillCopyTOTP: test.value})
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if string(fields["autofillCopyTOTP"]) != test.want {
				t.Fatalf("unexpected preference field: %s", data)
			}
		})
	}
	for _, value := range []bool{false, true} {
		data, err := json.Marshal(Reply{OK: true, AutofillCopyTOTP: value})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["autofillCopyTOTP"]; !ok {
			t.Fatal("reply omitted preference")
		}
		var reply Reply
		if err := json.Unmarshal(data, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.AutofillCopyTOTP != value {
			t.Fatal("preference did not round trip")
		}
	}
}

func boolValue(value bool) *bool { return &value }
