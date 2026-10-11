// SPDX-License-Identifier: GPL-3.0-only
package kit

// Icons of the shared controls (controls.go) and of import and export.
func init() {
	for name, paths := range map[string]string{
		"check":    `<path d="m5 12.5 4.5 4.5L19 7.5"/>`,
		"info":     `<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-9.5v.5"/>`,
		"alert":    `<path d="M10.3 4.2 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z"/><path d="M12 9.5v4.5m0 3v.5"/>`,
		"download": `<path d="M12 3v12m-5-5 5 5 5-5M4 20h16"/>`,
		"upload":   `<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>`,
		"file":     `<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/><path d="M14 3v5h5"/>`,
	} {
		if _, ok := Icons[name]; !ok {
			Icons[name] = lineIcon(paths)
		}
	}
}
