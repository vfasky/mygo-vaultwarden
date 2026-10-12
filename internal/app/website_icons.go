// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"os"
	"path/filepath"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/websiteicons"
)

func (a *app) websiteIcon(c *ui.Context, item localstore.DisplayCredential) *ui.Bitmap {
	if !a.websiteIconsEnabled || !a.unlocked() || a.snapshot.Scope == nil || (item.Type != 0 && item.Type != 1) || item.RequiresPassword || websiteicons.Host(item.URL) == "" {
		return nil
	}
	scope := *a.snapshot.Scope
	if a.websiteIcons == nil || a.websiteIconScope != scope {
		a.websiteIcons.Close()
		directory := ""
		if base, err := os.UserCacheDir(); err == nil {
			directory = filepath.Join(base, "MyGo Vaultwarden", "WebsiteIcons")
		}
		a.websiteIcons = websiteicons.New(scope.Server, scope.Account, directory)
		a.websiteIconScope = scope
	}
	return a.websiteIcons.Lookup(item.URL, c.Services().Invalidate)
}
