// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"testing"
)

func TestOrgOfficialOrganizationJSONStrictPreview(t *testing.T) {
	raw := []byte(`{"encrypted":false,"collections":[{"id":"11111111-1111-4111-8111-111111111111","name":"Engineering","externalId":"directory"}],"items":[{"id":"22222222-2222-4222-8222-222222222222","organizationId":null,"collectionIds":["11111111-1111-4111-8111-111111111111"],"type":1,"name":"Portal","notes":"Note","favorite":false,"reprompt":1,"fields":[{"name":"custom","value":"keep","type":0}],"login":{"username":"alice","password":"secret","totp":"totp","uris":[{"uri":"https://example.invalid","match":0}]},"passwordHistory":[{"password":"previous","lastUsedDate":"2026-01-01T00:00:00.000Z"}]}]}`)
	p, err := ParseBitwardenOrganizationJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	if p.PreviewItems()[0].Name != "Portal" || p.Collections()[0].Name != "Engineering" || p.file.Items[0]["reprompt"] != json.Number("1") {
		t.Fatal("lost preview or fields")
	}
	if _, err := ParseOrganizationImport(raw); err == nil {
		t.Fatal("official file accepted as MyGo")
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["encrypted"] = true },
		func(m map[string]any) { m["future"] = true },
		func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["future"] = true },
		func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["collectionIds"] = []string{"unknown"} },
		func(m map[string]any) {
			m["items"].([]any)[0].(map[string]any)["login"].(map[string]any)["fido2Credentials"] = []any{map[string]any{"credentialId": "secret"}}
		},
		func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["organizationId"] = "bad" },
	} {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		change(m)
		encoded, _ := json.Marshal(m)
		if _, err := ParseBitwardenOrganizationJSON(encoded); err == nil {
			t.Fatal("unsupported accepted")
		}
	}
}

func TestOrgDirectoryReconciliationPartialAndOverwrite(t *testing.T) {
	ptr := func(s string) *string { return &s }
	before := &OrganizationDirectorySnapshot{Members: []OrganizationDirectoryMemberObservation{{ID: "old-member", ExternalID: ptr("old"), Status: 2}}}
	after := &OrganizationDirectorySnapshot{Members: []OrganizationDirectoryMemberObservation{{ID: "one", Email: "one@example.invalid", ExternalID: ptr("one"), Status: 2}, {ID: "two", Email: "two@example.invalid", ExternalID: ptr("two"), Status: -1}, {ID: "old-member", ExternalID: ptr("old"), Status: -1}}, Groups: []OrganizationDirectoryGroupObservation{{ID: "g", Name: "Team", ExternalID: ptr("group"), MemberIDs: []string{"one"}}}}
	input := OrganizationDirectoryImport{Members: []OrganizationDirectoryMember{{Email: "one@example.invalid", ExternalID: "one"}, {Email: "two@example.invalid", ExternalID: "two"}}, Groups: []OrganizationDirectoryGroup{{Name: "Team", ExternalID: "group", MemberExternalIDs: []string{"one", "two"}}}, OverwriteExisting: true}
	r := reconcileOrganizationDirectory(input, before, after)
	if len(r.Rows) != 4 || !r.Rows[0].Verified || r.Rows[1].Verified || r.Rows[2].Verified || !r.Rows[3].Verified {
		t.Fatal(r.Rows)
	}
	missing := reconcileOrganizationDirectory(input, before, nil)
	for _, row := range missing.Rows {
		if row.Verified {
			t.Fatal("missing read green")
		}
	}
	after.Members = append(after.Members, after.Members[0])
	r = reconcileOrganizationDirectory(input, before, after)
	if r.Rows[0].Verified || r.Rows[2].Verified {
		t.Fatal("duplicate identity green")
	}
}
