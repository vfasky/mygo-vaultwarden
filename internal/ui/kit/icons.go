// SPDX-License-Identifier: GPL-3.0-only
package kit

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/resources"
)

var AppLogo = func() *ui.Bitmap {
	b, err := ui.DecodeBitmap(resources.AppLogo)
	if err != nil {
		return nil
	}
	return b
}()

// Small, local vector icons avoid remote favicon requests from a private vault.
func lineIcon(paths string) *ui.SVG {
	return ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">` + paths + `</svg>`))
}

var Icons = map[string]*ui.SVG{
	"panel-left":  lineIcon(`<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 3v18"/>`),
	"vault":       lineIcon(`<rect x="4" y="3" width="16" height="18" rx="4"/><circle cx="12" cy="11" r="3"/><path d="M12 8v6m-3-3h6M8 18h8"/>`),
	"grid":        lineIcon(`<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>`),
	"user":        lineIcon(`<circle cx="12" cy="8" r="4"/><path d="M4 21v-2a8 8 0 0 1 16 0v2"/>`),
	"star":        lineIcon(`<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z"/>`),
	"globe":       lineIcon(`<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>`),
	"card":        lineIcon(`<rect x="3" y="5" width="18" height="14" rx="3"/><path d="M3 10h18M7 15h4"/>`),
	"identity":    lineIcon(`<rect x="2" y="5" width="20" height="14" rx="3"/><circle cx="8" cy="10" r="2"/><path d="M5 16a3 3 0 0 1 6 0m4-7h4m-4 4h4"/>`),
	"note":        lineIcon(`<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Z"/><path d="M14 3v6h6M8 13h8m-8 4h5"/>`),
	"key":         lineIcon(`<circle cx="7" cy="12" r="4"/><path d="M11 12h10m-4 0v3m4-3v3"/>`),
	"folder":      lineIcon(`<path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>`),
	"folder-plus": lineIcon(`<path d="M3 7V5a2 2 0 0 1 2-2h5l3 4h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/><path d="M12 10.5v6m-3-3h6"/>`),
	"inbox":       lineIcon(`<path d="M3 13h5l1.5 2.5h5L16 13h5"/><path d="M5.5 5h13l2.5 8v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-5Z"/>`),
	"plus":        lineIcon(`<path d="M12 5v14M5 12h14"/>`),
	"bank":        lineIcon(`<path d="M12 3 3 8h18Z"/><path d="M5 11v6m4.7-6v6m4.6-6v6M19 11v6M3 20.5h18"/>`),
	"car":         lineIcon(`<path d="M5 17H3.5v-4.5L5.5 7h13l2 5.5V17H19"/><path d="M3.5 12.5h17"/><circle cx="7.5" cy="17" r="2"/><circle cx="16.5" cy="17" r="2"/><path d="M9.5 17h5"/>`),
	"passport":    lineIcon(`<rect x="5" y="2.5" width="14" height="19" rx="2.5"/><circle cx="12" cy="10" r="3.5"/><path d="M8.5 10h7M12 6.5c-1.4 1.2-1.4 5.8 0 7m0-7c1.4 1.2 1.4 5.8 0 7M9 17.5h6"/>`),
	"building":    lineIcon(`<rect x="4" y="3" width="16" height="18" rx="2.5"/><path d="M9.5 21v-4h5v4M8.5 7.5h2m3 0h2m-7 4h2m3 0h2"/>`),
	"stack":       lineIcon(`<path d="m12 3 9 4.5-9 4.5-9-4.5Z"/><path d="m3 12 9 4.5 9-4.5M3 16.5 12 21l9-4.5"/>`),
	"archive":     lineIcon(`<rect x="3" y="3" width="18" height="5" rx="1.5"/><path d="M5 8v12h14V8m-10 4h6"/>`),
	"trash":       lineIcon(`<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>`),
	"search":      lineIcon(`<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>`),
	"sync":        lineIcon(`<path d="M20 4v6h-6M4 20v-6h6M4.8 8A8 8 0 0 1 18 5l2 5M4 14l2 5a8 8 0 0 0 13.2-3"/>`),
	"lock":        lineIcon(`<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>`),
	"shield":      lineIcon(`<path d="m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6Z"/><path d="m8 12 3 3 5-6"/>`),
	"settings":    lineIcon(`<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2" fill="white"/><circle cx="16" cy="12" r="2" fill="white"/><circle cx="8" cy="18" r="2" fill="white"/>`),
	"copy":        lineIcon(`<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>`),
	"external":    lineIcon(`<path d="M14 3h7v7m0-7L10 14m-1-9H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/>`),
	"chevron":     lineIcon(`<path d="m9 5 7 7-7 7"/>`),
	"close":       lineIcon(`<path d="m6 6 12 12M6 18 18 6"/>`),
}

func Icon(c *ui.Context, name string, size float32) ui.Element {
	return ui.Icon(c, Icons[name]).Size(size, size).Shrink(0)
}
