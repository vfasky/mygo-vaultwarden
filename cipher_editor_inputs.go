// SPDX-License-Identifier: GPL-3.0-only
package main

// applyInputs merges only controls that actually changed. In particular null
// optional values and unknown extensions must survive a no-op editor save.
func (e *cipherEditor) applyInputs() {
	for _, f := range e.inputs {
		section := sectionFields(&e.fields)
		previous, _ := section[f.key].(string)
		if previous != f.value {
			section[f.key] = f.value
		}
	}
	if e.fields.Type == 1 && (e.fields.Login["uris"] != nil || len(e.uris) > 0) {
		uris := make([]any, 0, len(e.uris))
		for _, u := range e.uris {
			source := cloneEditorMap(u.source)
			previous, _ := source["uri"].(string)
			if previous != u.value || source["uri"] == nil {
				source["uri"] = u.value
			}
			uris = append(uris, source)
		}
		e.fields.Login["uris"] = uris
	}
	if e.fields.Fields != nil || len(e.custom) > 0 {
		fields := make([]map[string]any, 0, len(e.custom))
		for _, f := range e.custom {
			source := cloneEditorMap(f.source)
			if f.editable {
				name, _ := source["name"].(string)
				if name != f.name {
					source["name"] = f.name
				}
				value, _ := source["value"].(string)
				if f.kind != "3" && value != f.value {
					source["value"] = f.value
				}
				if f.kind == "3" && f.linkedID != "" && source["linkedId"] != f.linkedID {
					source["linkedId"] = f.linkedID
					source["value"] = nil
				}
			}
			fields = append(fields, source)
		}
		e.fields.Fields = fields
	}
	if e.fields.Notes != nil || e.notes != "" {
		e.fields.Notes = &e.notes
	}
}
func cloneEditorMap(source map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range source {
		result[key] = value
	}
	return result
}
