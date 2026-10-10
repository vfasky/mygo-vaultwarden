// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

type vaultCategory struct {
	id, title, symbol string
	supported         bool
}

var vaultCategories = []vaultCategory{
	{"all", "所有项目", "grid", true},
	{"favorites", "收藏夹", "star", true},
	{"login", "登录", "globe", true},
	{"card", "支付卡", "card", true},
	{"identity", "身份", "identity", true},
	{"note", "安全笔记", "note", true},
	{"ssh", "SSH 密钥", "key", true},
	{"bank", "银行账户", "bank", true},
	{"license", "驾驶证", "car", true},
	{"passport", "护照", "passport", true},
	{"archive", "归档", "archive", true},
	{"trash", "回收站", "trash", true},
}

// categoryKinds maps type categories to Bitwarden cipher types.
var categoryKinds = map[string]int{"login": 1, "note": 2, "card": 3, "identity": 4, "ssh": 5, "bank": 6, "license": 7, "passport": 8}

func (a *app) currentCategory() vaultCategory {
	if a.category == "org-services" {
		return vaultCategory{"org-services", "紧急访问", "vault", true}
	}
	if a.category == "mfa" {
		return vaultCategory{"mfa", "两步验证设置", "shield", true}
	}
	if a.category == "account" {
		return vaultCategory{"account", "账号与安全", "user", true}
	}
	if a.category == "devices" {
		return vaultCategory{"devices", "设备与登录审批", "shield", true}
	}
	if a.category == "send" {
		return vaultCategory{"send", "Send", "send", true}
	}
	if a.category == "personal" {
		return vaultCategory{"personal", "我的密码库", "user", true}
	}
	for _, org := range a.organizations {
		if a.category == "org:"+org.ID {
			return vaultCategory{a.category, org.Name, "vault", true}
		}
	}
	for _, collection := range a.collections {
		if a.category == "collection:"+collection.ID {
			return vaultCategory{a.category, collection.Name, "vault", true}
		}
	}
	if strings.HasPrefix(a.category, "org:") || strings.HasPrefix(a.category, "collection:") {
		return vaultCategory{a.category, "组织权限已变化", "vault", false}
	}
	if strings.HasPrefix(a.category, "folder:") {
		id := strings.TrimPrefix(a.category, "folder:")
		if id == "" {
			return vaultCategory{a.category, "无文件夹", "vault", true}
		}
		for _, f := range a.folders {
			if f.ID == id {
				return vaultCategory{a.category, f.Name, "vault", true}
			}
		}
		return vaultCategory{a.category, "文件夹已不存在", "vault", false}
	}
	for _, category := range vaultCategories {
		if category.id == a.category {
			return category
		}
	}
	return vaultCategories[0]
}

func (a *app) releaseItemCount() int {
	count := 0
	for _, item := range a.items {
		if organizationUIEnabled || item.OrganizationID == "" {
			count++
		}
	}
	return count
}

// itemInCategory applies a sidebar destination's filter, without the search query.
func itemInCategory(item localstore.DisplayCredential, category string) bool {
	if (!organizationUIEnabled || category == "personal") && item.OrganizationID != "" {
		return false
	}
	if strings.HasPrefix(category, "org:") && item.OrganizationID != strings.TrimPrefix(category, "org:") {
		return false
	}
	if strings.HasPrefix(category, "collection:") && !slices.Contains(item.CollectionIDs, strings.TrimPrefix(category, "collection:")) {
		return false
	}
	if strings.HasPrefix(category, "folder:") && item.FolderID != strings.TrimPrefix(category, "folder:") {
		return false
	}
	if item.Deleted != (category == "trash") {
		return false
	}
	if category != "trash" && item.Archived != (category == "archive") {
		return false
	}
	if category == "favorites" && !item.Favorite {
		return false
	}
	kind := categoryKinds[category]
	return kind == 0 || item.Type == kind || (kind == 1 && item.Type == 0)
}

// sidebarCounts counts each destination shown with a badge in the sidebar.
func (a *app) sidebarCounts() map[string]int {
	counts := map[string]int{}
	if !a.unlocked() {
		return counts
	}
	for _, item := range a.items {
		for _, category := range vaultCategories {
			if itemInCategory(item, category.id) {
				counts[category.id]++
			}
		}
		if itemInCategory(item, "folder:"+item.FolderID) {
			counts["folder:"+item.FolderID]++
		}
	}
	return counts
}

func (a *app) filteredItems() []localstore.DisplayCredential {
	if !a.currentCategory().supported || !a.unlocked() {
		return nil
	}
	query := strings.ToLower(strings.TrimSpace(a.query))
	items := make([]localstore.DisplayCredential, 0, len(a.items))
	for _, item := range a.items {
		if !itemInCategory(item, a.category) {
			continue
		}
		if strings.Contains(strings.ToLower(item.Title+" "+item.Username+" "+item.URL), query) {
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		x, y := strings.ToLower(items[i].Title), strings.ToLower(items[j].Title)
		if x == y {
			return items[i].ID < items[j].ID
		}
		return x < y
	})
	return items
}

// Selection is always resolved against the current filtered metadata, never a
// retained credential. Locking, replacement and searches cannot leave stale details.
func (a *app) reconcileSelection(items []localstore.DisplayCredential) {
	a.selectedRow = -1
	for i, item := range items {
		if item.ID == a.selectedID {
			a.selectedRow = i
			return
		}
	}
	a.selectedID = ""
	if len(items) > 0 {
		a.selectedID, a.selectedRow = items[0].ID, 0
	}
}

func (a *app) unlocked() bool {
	return a.snapshot != nil && a.snapshot.Available && a.itemsRevision != "" && a.itemsRevision == a.snapshot.Revision
}

func (a *app) view(c *ui.Context) {
	if a.orgServices != nil && (a.category != "org-services" || a.showSettings) {
		a.advanceEpoch()
	}
	if runtime := a.runtimeVault; runtime != nil {
		if err := runtime.sourceCheck(runtime.source, *a.liveScope); err != nil {
			a.stopNetwork()
			a.status = "临时库的本机保护来源已变化，请重新认证。"
		} else {
			c.After(time.Second)
		}
	}
	if a.authManagement != nil && (a.category != "mfa" || a.showSettings) {
		a.advanceEpoch()
	}
	if a.accountForm != nil && a.accountForm.Mode != "register" && (a.category != "account" || a.showSettings) {
		a.advanceEpoch()
	}
	if a.devicePanel != nil && (a.category != "devices" || a.showSettings) {
		a.advanceEpoch()
	}
	if a.sendPanel != nil && (a.category != "send" || a.showSettings) {
		a.advanceEpoch()
	}
	c.SetTheme(kit.Theme)
	c.Root().Background(ui.Transparent)
	if a.showLogin || !a.unlocked() {
		a.authentication(c)
		return
	}
	if c.Shortcut(ui.Cmd, ui.KeyB) {
		a.sidebarCollapsed = !a.sidebarCollapsed
	}
	ui.Row(c).Fill().TextColor(kit.Ink).AlignItems(ui.Stretch).Children(func() {
		a.sidebar(c)
		ui.Column(c).Grow(1).MinWidth(0).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
			a.header(c)
			ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Gap(16).Children(func() { a.body(c) })
		})
	})
}

func (a *app) body(c *ui.Context) {
	if a.category == "org-services" && !a.showSettings {
		ui.Scroll(c).Grow(1).Children(func() {
			if a.orgServices != nil {
				a.orgServices.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, "打开紧急访问").Disabled(a.pending != 0).Clicked() {
					a.openEmergencyServices()
				}
			}
		})
		return
	}
	if a.category == "mfa" && !a.showSettings {
		ui.Scroll(c).Grow(1).Children(func() {
			if a.authManagement != nil {
				account.AuthManagementView(c, a.authManagement)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, "打开两步验证设置").Disabled(a.pending != 0).Clicked() {
					a.openAuthenticationManagement()
				}
			}
		})
		return
	}
	if a.category == "account" && !a.showSettings {
		ui.Scroll(c).Grow(1).Children(func() {
			if a.accountForm != nil {
				account.FormView(c, a.accountForm)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, "打开账号与安全").Disabled(a.pending != 0).Clicked() {
					a.openAccount()
				}
			}
		})
		return
	}
	if a.category == "devices" && !a.showSettings {
		ui.Scroll(c).Grow(1).Children(func() {
			if a.devicePanel != nil {
				a.devicePanel.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, "打开设备与登录审批").Disabled(a.pending != 0).Clicked() {
					a.openDevices()
				}
			}
		})
		return
	}
	if a.category == "send" && !a.showSettings {
		ui.Scroll(c).Grow(1).Children(func() {
			if a.sendPanel != nil {
				a.sendPanel.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, "打开 Send").Disabled(a.pending != 0).Clicked() {
					a.openSend()
				}
			}
		})
		return
	}
	ui.Row(c).Grow(1).MinHeight(0).Gap(16).AlignItems(ui.Stretch).Children(func() {
		items := a.filteredItems()
		a.reconcileSelection(items)
		a.credentialList(c, items)
		ui.Column(c.Key("detail-pane")).Grow(1).MinWidth(0).Gap(16).Children(func() {
			if a.backupEditor != nil {
				a.backupEditorView(c)
			} else if a.bulkEditor != nil {
				a.bulkEditorView(c)
			} else if a.organizationEditor != nil {
				a.organizationEditorView(c)
			} else if a.folderEditor != nil {
				a.folderEditorView(c)
			} else if a.editor != nil {
				a.cipherEditorView(c)
			} else if a.showSettings {
				a.settings(c)
			} else if a.selectedRow >= 0 && a.selectedRow < len(items) {
				a.credentialDetail(c, items[a.selectedRow])
			} else {
				a.emptyDetail(c)
			}
		})
	})
	ui.Row(c).Gap(8).Height(32).Shrink(0).Children(func() {
		kit.Icon(c, "shield", 15).TextColor(kit.Purple)
		ui.Text(c, a.status).FontSize(12).TextColor(kit.Muted).Grow(1).MinWidth(0).MaxLines(2).Tooltip(a.status).Role(ui.RoleStatus)
		if a.pending != 0 {
			ui.Text(c, "处理中…").FontSize(12).TextColor(kit.Purple)
		}
	})
}

func (a *app) sidebarToggle(c *ui.Context) {
	label := "折叠侧栏"
	if a.sidebarCollapsed {
		label = "展开侧栏"
	}
	if kit.TitleBarButton(c, label, "panel-left").Key("sidebar-toggle").Clicked() {
		a.sidebarCollapsed = !a.sidebarCollapsed
	}
}

// header is a unified toolbar: it sits beside the traffic lights' row and
// shares the content background, like a native macOS toolbar.
func (a *app) header(c *ui.Context) {
	bar := c.TitleBar()
	left := float32(20)
	if a.sidebarCollapsed {
		left = 12
	}
	ui.Row(c).Height(max(bar.Height, 52)).Shrink(0).Gap(10).AlignItems(ui.Center).
		Padding(0, 20, 0, max(left, bar.Left-a.sidebarWidth(c))).DragWindow().Children(func() {
		// The expanded sidebar carries the toggle; the collapsed rail only
		// fits the traffic lights, so it leads the toolbar instead.
		if a.sidebarCollapsed {
			a.sidebarToggle(c)
		}
		ui.Spacer(c)
		state := "未解锁"
		if a.unlocked() {
			state = "本机已解锁"
		}
		if a.session != nil {
			state = "可同步"
		}
		kit.Pill(c, state, kit.Lavender, kit.Purple)
		if kit.ToolbarButton(c, "导入导出", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBackupEditor()
		}
		if kit.ToolbarButton(c, "新增", "key", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			kind := categoryKinds[a.category]
			if kind == 0 {
				kind = 1
			}
			a.openCipherEditor("", kind)
		}
		if kit.ToolbarButton(c, "批量管理", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBulkEditor(false)
		}
		if a.category == "trash" && kit.ToolbarButton(c, "清空回收站", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBulkEditor(true)
		}
		if kit.ToolbarButton(c, "同步", "sync", false, a.pending != 0).Clicked() {
			a.syncVault(false)
		}
		if kit.ToolbarButton(c, "锁定", "lock", true, false).Clicked() {
			a.runStorage("lock")
		}
		if ui.Button(c, "").Label("账号与设置").Tooltip("账号与设置").Size(32, 32).Padding(7).Radius(16).
			Border(1, ui.RGBA(255, 255, 255, .7)).Background(ui.RGBA(255, 255, 255, .55)).
			Children(func() { kit.Icon(c, "settings", 16) }).Clicked() {
			a.showSettings = !a.showSettings
		}
	})
}

// sidebarWidth keeps the collapsed rail at least as wide as the traffic
// lights, so the rail runs unbroken from the top of the window.
func (a *app) sidebarWidth(c *ui.Context) float32 {
	if a.sidebarCollapsed {
		return max(64, c.TitleBar().Left+10)
	}
	return 236
}

func (a *app) sidebar(c *ui.Context) {
	bar := c.TitleBar()
	width := a.sidebarWidth(c)
	ui.Row(c).Width(width + 1).Shrink(0).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Width(width).Shrink(0).Background(kit.SidebarBackground).Children(func() {
			top := ui.Row(c).Height(max(bar.Height, 52)).Shrink(0).AlignItems(ui.Center).DragWindow()
			if !a.sidebarCollapsed {
				// Like native split views, the toggle sits just past the
				// traffic lights.
				top.Padding(0, 0, 0, max(14, bar.Left)).Children(func() { a.sidebarToggle(c) })
			}
			ui.Column(c).Grow(1).MinHeight(0).Padding(0, 0, 12, 0).Gap(6).Children(func() { a.sidebarContent(c, width) })
		})
		ui.Box(c).Width(1).Background(kit.Line)
	})
}

func (a *app) sidebarContent(c *ui.Context, width float32) {
	navItem := a.navItem
	collapsed := a.sidebarCollapsed
	counts := a.sidebarCounts()
	count := func(id string) string {
		if n := counts[id]; n > 0 {
			return fmt.Sprint(n)
		}
		return ""
	}
	// Expanded groups are titled; the rail separates them with short hairlines.
	first := true
	section := func(title string, action func()) {
		if collapsed {
			if !first {
				ui.Row(c).Justify(ui.Center).Padding(7, 0).Children(func() {
					ui.Box(c).Width(20).Height(1).Background(ui.RGBA(38, 30, 62, .1))
				})
			}
		} else {
			top := float32(16)
			if first {
				top = 4
			}
			ui.Row(c).Height(top+24).Padding(top, 4, 0, 10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, title).FontSize(11).FontWeight(600).TextColor(kit.SidebarFaint).Grow(1).SingleLine()
				if action != nil {
					action()
				}
			})
		}
		first = false
	}
	folderBusy := a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.backupEditor != nil
	// Rows are inset from the edges, but the scroll view spans the full width
	// so its bar runs along the sidebar's edge instead of over the counts.
	inset := float32(12)
	if collapsed {
		inset = (width - 40) / 2
	}

	brand := ui.Row(c).Padding(2, inset+6, 8, inset+6).Gap(10).AlignItems(ui.Center)
	if collapsed {
		brand.Padding(2, 0, 8, 0).Justify(ui.Center)
	}
	brand.Children(func() {
		if kit.AppLogo != nil {
			ui.Image(c, kit.AppLogo).Size(30, 30).Shrink(0)
		}
		if collapsed {
			return
		}
		ui.Column(c).Gap(2).MinWidth(0).Children(func() {
			ui.Text(c, "Vaultwarden").FontSize(14).FontWeight(650).TextColor(kit.Ink).SingleLine()
			ui.Text(c, "个人密码库").FontSize(11).TextColor(kit.Muted).SingleLine()
		})
	})
	ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(2, 3, 2, 0).Children(func() {
		ui.Column(c).Gap(2).Padding(0, inset, 8, inset).Children(func() {
			section("所有密码库", nil)
			if navItem(c, "我的密码库", "user", "", a.category == "personal" && !a.showSettings, false).Clicked() {
				a.category, a.query, a.showSettings = "personal", "", false
			}
			categoryGroup := func(title string, types bool) {
				section(title, nil)
				for _, category := range vaultCategories {
					if (categoryKinds[category.id] != 0) != types {
						continue
					}
					b := navItem(c, category.title, category.symbol, count(category.id), a.currentCategory().id == category.id && !a.showSettings, false)
					if !category.supported && !collapsed {
						b.Tooltip("此分类尚未同步")
					}
					if b.Clicked() {
						a.category, a.showSettings = category.id, false
						a.listState.ScrollTo(0, ui.Start)
					}
				}
			}
			categoryGroup("项目", false)
			categoryGroup("类型", true)
			if organizationUIEnabled {
				section("组织", nil)
				if navItem(c, "创建或加入组织", "plus", "", false, a.pending != 0 || a.vault == nil || a.organizationEditor != nil).Clicked() {
					a.openOrganizationEditor("")
				}
				if strings.HasPrefix(a.category, "org:") && navItem(c, "管理当前组织", "settings", "", false, a.pending != 0 || a.organizationEditor != nil).Clicked() {
					a.openOrganizationEditor(strings.TrimPrefix(a.category, "org:"))
				}
				for _, org := range a.organizations {
					if navItem(c, org.Name, "building", "", a.category == "org:"+org.ID, false).Clicked() {
						a.category, a.showSettings = "org:"+org.ID, false
					}
					for _, collection := range a.collections {
						if collection.OrganizationID == org.ID && navItem(c, "  "+collection.Name, "folder", "", a.category == "collection:"+collection.ID, false).Clicked() {
							a.category, a.showSettings = "collection:"+collection.ID, false
						}
					}
				}
				for _, org := range a.isolatedOrganizations {
					if navItem(c, "重新核验："+org.Name, "settings", "", false, a.pending != 0 || a.organizationEditor != nil).Clicked() {
						a.openOrganizationEditor(org.ID)
					}
				}
			}
			section("文件夹", func() {
				if kit.SidebarAction(c, "新建文件夹", "plus", folderBusy).Clicked() {
					a.openFolderEditor("")
				}
			})
			if navItem(c, "无文件夹", "inbox", count("folder:"), a.category == "folder:" && !a.showSettings, false).Clicked() {
				a.category, a.showSettings = "folder:", false
			}
			for _, f := range a.folders {
				if navItem(c, f.Name, "folder", count("folder:"+f.ID), a.category == "folder:"+f.ID && !a.showSettings, false).Clicked() {
					a.category, a.showSettings = "folder:"+f.ID, false
				}
			}
			// The rail has no section titles to carry the add action.
			if collapsed && navItem(c, "新建文件夹", "folder-plus", "", false, folderBusy).Clicked() {
				a.openFolderEditor("")
			}
			if strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
				if navItem(c, "管理文件夹", "settings", "", false, a.pending != 0 || a.editor != nil || a.folderEditor != nil || a.backupEditor != nil).Clicked() {
					a.openFolderEditor(strings.TrimPrefix(a.category, "folder:"))
				}
			}
		})
	})
	ui.Column(c).Gap(6).Shrink(0).Padding(0, inset).Children(func() {
		ui.Box(c).Height(1).Margin(0, 4).Background(ui.RGBA(38, 30, 62, .08))
		if navItem(c, "账号与设置", "settings", "", a.showSettings, false).Clicked() {
			a.showSettings = !a.showSettings
		}
	})
}

func (a *app) navItem(c *ui.Context, title, symbol, count string, selected, disabled bool) ui.Element {
	return kit.SidebarItem(c, title, symbol, count, selected, disabled, a.sidebarCollapsed)
}

func (a *app) credentialList(c *ui.Context, items []localstore.DisplayCredential) {
	w, _ := c.Size()
	width := float32(304)
	if w >= 1240 {
		width = 330
	}
	ui.Column(c).Width(width).Shrink(0).Padding(12).Gap(12).Background(kit.Panel).Radius(26).Border(1, ui.RGBA(255, 255, 255, .65)).Children(func() {
		ui.Row(c).Padding(10, 8, 0, 8).Children(func() {
			ui.Text(c, a.currentCategory().title).FontSize(22).FontWeight(650)
			ui.Spacer(c)
			kit.Pill(c, fmt.Sprint(len(items)), kit.White, kit.Muted)
		})
		field := ui.Row(c.Key("vault-search")).Background(kit.White).Radius(22).Padding(0, 12).Height(43).Gap(8)
		field.Children(func() {
			kit.Icon(c, "search", 18).TextColor(kit.Muted)
			search := ui.TextInput(c, &a.query).Label("搜索密码库").Placeholder("搜索密码库").Grow(1).MinWidth(0).Border(0, ui.Transparent).Background(ui.Transparent).Padding(0).FocusRing(false)
			if c.Shortcut(ui.Cmd, ui.KeyF) {
				search.Focus()
			}
			if search.Focused() {
				field.DrawOver(func(p *ui.Painter, r ui.Rect) {
					outer := ui.Rect{X: r.X - 2, Y: r.Y - 2, W: r.W + 4, H: r.H + 4}
					p.Stroke(outer, kit.Purple, 24, 2)
				})
			}
			if search.Changed() {
				a.listState.ScrollTo(0, ui.Start)
			}
			if a.query != "" {
				if kit.IconButton(c, "清除搜索", "close").Size(25, 25).Padding(5).Clicked() {
					a.query = ""
				}
			} else {
				ui.Text(c, "⌘ F").FontSize(10).TextColor(kit.Muted)
			}
		})
		ui.Row(c).Padding(0, 8).Children(func() {
			ui.Text(c, "名称").FontSize(11).TextColor(kit.Muted)
			ui.Spacer(c)
			ui.Text(c, "A – Z").FontSize(10).TextColor(kit.Muted)
		})
		if len(items) == 0 {
			ui.Column(c).Grow(1).Justify(ui.Center).AlignItems(ui.Center).Gap(12).Padding(20).Children(func() {
				kit.Icon(c, "search", 30).TextColor(kit.Purple)
				title, subtitle := a.emptyListMessage()
				ui.Text(c, title).FontSize(15).FontWeight(550).TextAlign(ui.Center)
				ui.Text(c, subtitle).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center)
			})
		} else {
			a.listState.Key = func(i int) any { return items[i].ID }
			a.listState.Label = func(i int) string { return items[i].Title }
			a.listState.Selected = &a.selectedRow
			listTheme := *kit.Theme
			listTheme.Accent, listTheme.AccentText, listTheme.Radius = kit.White, kit.Ink, 19
			c.SetTheme(&listTheme)
			list := ui.List(c, &a.listState, len(items), func(i int) {
				item := items[i]
				row := ui.Row(c.Key(item.ID)).TextColor(kit.Ink).Padding(12).Gap(12).Height(78).Radius(19)
				if a.selectedRow == i {
					row.Background(kit.White).Border(1, ui.Hex("#DDD5EE"))
				} else if row.Hovered() {
					row.Background(ui.RGBA(255, 255, 255, .55))
				}
				row.Children(func() {
					credentialAvatar(c, item, 40)
					ui.Column(c).Grow(1).MinWidth(0).Gap(5).Children(func() {
						ui.Text(c, displayTitle(item)).FontSize(14).FontWeight(600).SingleLine()
						subtitle := item.Username
						if subtitle == "" {
							subtitle = websiteHost(item.URL)
						}
						if subtitle == "" {
							subtitle = "未填写用户名"
						}
						ui.Text(c, subtitle).FontSize(12).TextColor(kit.Muted).SingleLine()
					})
					if a.selectedRow == i {
						kit.Icon(c, "chevron", 13).TextColor(kit.Purple)
					}
				})
			}).Label("密码库项目").Grow(1).MinHeight(0).Gap(5)
			c.SetTheme(kit.Theme)
			if list.Changed() && a.selectedRow >= 0 && a.selectedRow < len(items) {
				a.selectedID = items[a.selectedRow].ID
				a.showSettings = false
			}
		}
		ui.Text(c, fmt.Sprintf("已载入 %d 个项目 · 个人密码库", a.releaseItemCount())).FontSize(11).TextColor(kit.Muted).Padding(4, 8)
	})
}

func (a *app) emptyListMessage() (string, string) {
	if !a.currentCategory().supported {
		return "此分类尚未同步", "当前版本仅支持个人登录条目"
	}
	if !a.unlocked() {
		return "密码库尚未解锁", "登录同步或离线解锁后查看项目"
	}
	if strings.TrimSpace(a.query) != "" {
		return "没有找到匹配项目", "试试其他名称、用户名或网站"
	}
	return "密码库中暂无登录条目", "同步后，项目会显示在这里"
}

func displayTitle(item localstore.DisplayCredential) string {
	if strings.TrimSpace(item.Title) == "" {
		return "未命名登录"
	}
	return item.Title
}
func websiteHost(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return raw
}
func safeWebsite(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != "" && (u.Scheme == "https" || u.Scheme == "http")
}

func credentialAvatar(c *ui.Context, item localstore.DisplayCredential, size float32) {
	colors := []ui.Color{ui.Hex("#E9E2F7"), ui.Hex("#E0EAE9"), ui.Hex("#F2E7DE"), ui.Hex("#DFE7F2")}
	r, _ := utf8.DecodeRuneInString(displayTitle(item))
	index := int(r) % len(colors)
	ui.Row(c).Size(size, size).Shrink(0).Justify(ui.Center).Radius(size * .31).Background(colors[index]).Children(func() {
		ui.Text(c, strings.ToUpper(string(r))).FontSize(size * .43).FontWeight(650).TextColor(kit.Ink)
	})
}

func (a *app) credentialDetail(c *ui.Context, item localstore.DisplayCredential) {
	ui.Scroll(c.Key(item.ID)).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(14).Padding(10, 8, 8, 8).Children(func() {
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, "我的密码库").FontSize(12).TextColor(kit.Muted)
				kit.Icon(c, "chevron", 12).TextColor(kit.Muted)
				kind := "登录"
				if item.Type > 0 && item.Type < len(cipherTypeNames) {
					kind = cipherTypeNames[item.Type]
				}
				ui.Text(c, kind).FontSize(12).TextColor(kit.Muted)
				ui.Spacer(c)
				if kit.Action(c, "查看与编辑", "", false, a.pending != 0 || (!item.Editable && !item.Readable && !item.RequiresPassword) || a.vault == nil).Clicked() {
					a.openCipherEditor(item.ID, item.Type)
				}
			})
			ui.Row(c).Gap(16).Children(func() {
				credentialAvatar(c, item, 60)
				ui.Column(c).Grow(1).MinWidth(0).Gap(6).Children(func() {
					ui.Text(c, displayTitle(item)).FontSize(29).FontWeight(650).MaxLines(2).Tooltip(displayTitle(item))
					ui.Text(c, websiteHost(item.URL)).FontSize(13).TextColor(kit.Muted).SingleLine()
				})
			})
			ui.Row(c).Gap(8).Children(func() {
				if kit.Action(c, "打开网站", "external", true, !safeWebsite(item.URL)).Clicked() {
					c.OpenURL(item.URL)
				}
				if kit.Action(c, "复制用户名", "copy", false, item.Username == "").Clicked() {
					c.WriteClipboard(item.Username)
					a.status = "用户名已复制。"
				}
			})
			kit.DetailCard(c, "登录信息", func() {
				kit.DetailField(c, "用户名", item.Username, "未填写用户名")
				ui.Divider(c)
				ui.Row(c).Padding(12, 16).Gap(10).Children(func() {
					ui.Column(c).Grow(1).Gap(7).Children(func() {
						ui.Text(c, "密码").FontSize(11).TextColor(kit.Muted)
						ui.Text(c, "由系统安全自动填充").FontSize(14)
					})
					kit.Icon(c, "lock", 19).TextColor(kit.Purple)
				})
			})
			kit.DetailCard(c, "网站", func() { kit.DetailField(c, "登录地址", item.URL, "未填写网站") })
			ui.Column(c).Gap(8).Padding(14, 18).Background(kit.Lavender).Radius(22).Children(func() {
				ui.Row(c).Gap(9).Children(func() {
					kit.Icon(c, "shield", 20).TextColor(kit.Purple)
					ui.Text(c, "安全自动填充").FontWeight(600)
					ui.Spacer(c)
					if kit.IconButton(c, "自动填充设置", "settings").Size(30, 30).Padding(7).Clicked() {
						openAutoFillSettings(c)
					}
				})
				ui.Text(c, "在 Safari 中选择此凭据，完成系统认证后填充密码。").FontSize(12).LineHeight(1.5).TextColor(kit.Purple)
			})
		})
	})
}

func (a *app) emptyDetail(c *ui.Context) {
	ui.Column(c).Grow(1).Background(ui.RGBA(247, 246, 251, .6)).Radius(26).Padding(34).Justify(ui.Center).AlignItems(ui.Center).Gap(16).Children(func() {
		ui.Row(c).Size(76, 76).Justify(ui.Center).Radius(26).Background(kit.White).Children(func() { kit.Icon(c, "vault", 38).TextColor(kit.Purple) })
		ui.Text(c, "选择一个项目").FontSize(23).FontWeight(600).TextAlign(ui.Center)
		ui.Text(c, "项目的登录信息和网站会显示在这里。").FontSize(13).LineHeight(1.6).TextColor(kit.Muted).TextAlign(ui.Center)
	})
}

func openAutoFillSettings(c *ui.Context) {
	c.OpenURL("x-apple.systempreferences:com.apple.Passwords-Settings.extension")
}

func (a *app) settings(c *ui.Context) {
	ready := a.snapshot != nil && a.pending == 0
	available := a.snapshot != nil && a.snapshot.Available
	ui.Scroll(c.Key("settings")).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(18).Padding(10, 8).Children(func() {
			ui.Row(c).Children(func() {
				ui.Text(c, "账号与设置").FontSize(26).FontWeight(650)
				ui.Spacer(c)
				if kit.IconButton(c, "关闭设置", "close").Clicked() {
					a.showSettings = false
				}
			})
			kit.DetailCard(c, "账号服务", func() {
				if warning := a.mfaWarnings.warning(a.serverURL, a.email); warning != "" {
					ui.Text(c, warning).MaxLines(4)
				}
				if a.runtimeVault != nil {
					ui.Column(c.Key(a.secretInputVersion)).Padding(16).Gap(8).Children(func() {
						ui.Text(c, "临时在线库：不会持久保存会话或注册系统自动填充。原磁盘账号保持不变。").MaxLines(4)
						if a.diskSnapshot != nil && a.diskSnapshot.Scope != nil && a.liveScope != nil && *a.diskSnapshot.Scope != *a.liveScope {
							oldAccount := a.diskSnapshot.Scope.Account
							if a.diskSnapshot.PasswordUnlock != nil {
								oldAccount = a.diskSnapshot.PasswordUnlock.Email
							}
							ui.Text(c, "原本机账号："+a.diskSnapshot.Scope.Server+" / "+oldAccount+"\n新账号："+a.liveScope.Server+" / "+a.email).MaxLines(5)
							ui.Text(c, "需要系统认证原缓存；原账号仍有策略、组织隔离或恢复事项时将先拒绝。写入确认前保留旧密文与密钥，未知结果只检查同一次切换，不自动重试。").MaxLines(6)
							label := "明确同意替换以上本机账号"
							if a.runtimeReplaceConfirmed {
								label = "已同意替换（点击撤回）"
							}
							if kit.Action(c, label, "user", false, a.pending != 0).Clicked() {
								a.runtimeReplaceConfirmed = !a.runtimeReplaceConfirmed
							}
						}
						ui.TextInput(c, &a.masterPassword).Label("显式绑定当前账号主密码").Password().Disabled(a.pending != 0)
						if kit.Action(c, "绑定主密码并重新同步", "lock", true, a.pending != 0 || a.masterPassword == "").Clicked() {
							a.bindRuntimePasswordWith(a.window.Update, localstore.Call)
						}
					})
				}
				ui.Row(c).Padding(16).Gap(8).Wrap().Children(func() {
					if kit.Action(c, "核验目标账号恢复记录", "vault", false, a.pending != 0).Clicked() {
						a.openTargetRecovery()
					}
					if kit.Action(c, "紧急访问", "vault", false, !ready).Clicked() {
						a.openEmergencyServices()
					}
					if kit.Action(c, "Send", "send", false, !ready).Clicked() {
						a.openSend()
					}
					if kit.Action(c, "设备与登录审批", "shield", false, !ready).Clicked() {
						a.openDevices()
					}
					if kit.Action(c, "账号与安全", "user", false, !ready).Clicked() {
						a.openAccount()
					}
					if kit.Action(c, "两步验证设置", "shield", false, !ready).Clicked() {
						a.openAuthenticationManagement()
					}
				})
			})
			kit.DetailCard(c, "连接密码库", func() {
				ui.Column(c).Padding(16).Gap(13).Children(func() {
					ui.Text(c, a.connectedServer()).FontSize(14).MaxLines(2)
					ui.Text(c, "登录凭据在本地加密保存，解锁后可同步；也可连接其他服务器与账号。").FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
					if kit.Action(c, "登录服务器", "user", true, a.pending != 0).Clicked() {
						a.resetLoginForm()
						a.showLogin = true
						a.status = ""
					}
				})
			})
			kit.DetailCard(c, "本机存储与自动填充", func() {
				ui.Column(c).Padding(16).Gap(12).Children(func() {
					state := "尚无本机快照"
					if available {
						state = fmt.Sprintf("本机快照 · %d 个登录项目", a.snapshot.Count)
					}
					ui.Text(c, state).FontSize(13)
					if available && a.snapshot.UpdatedAt > 0 {
						ui.Text(c, "最近同步："+time.UnixMilli(a.snapshot.UpdatedAt).Format("2006-01-02 15:04")).FontSize(11).TextColor(kit.Muted)
					}
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if kit.Action(c, "离线解锁", "lock", false, !ready || !available).Clicked() {
							a.runStorage("list")
						}
						if kit.Action(c, "刷新状态", "sync", false, a.pending != 0).Clicked() {
							a.runStorage("status")
						}
					})
					ui.Divider(c)
					if a.snapshot != nil && a.snapshot.IndexPending {
						ui.Text(c, "系统候选尚未确认同步，请刷新状态或认证更新。").FontSize(12).TextColor(kit.Purple)
					}
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if kit.Action(c, "自动填充设置", "settings", false, false).Clicked() {
							openAutoFillSettings(c)
						}
						if kit.Action(c, "更新系统候选", "shield", false, !ready || !available).Clicked() {
							a.runStorage("reindex")
						}
					})
					if a.snapshot != nil && a.snapshot.CleanupPending {
						ui.Text(c, "旧密钥清理尚未完成。").FontSize(12).TextColor(kit.Purple)
						if kit.Action(c, "重试清理", "sync", false, !ready).Clicked() {
							a.runStorage("retryCleanup")
						}
					}
				})
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				logoutLabel := "退出账号"
				if a.runtimeVault != nil {
					logoutLabel = "结束临时在线会话（保留原缓存）"
				}
				if kit.Action(c, logoutLabel, "user", false, a.snapshot == nil).Clicked() {
					a.runStorage("logout")
				}
			})
			ui.Text(c, "MyGo Vaultwarden · macOS 原生\n支持个人八类型项目编辑；组织与更多功能仍在开发。").FontSize(11).TextColor(kit.Muted).LineHeight(1.6)
		})
	})
}
