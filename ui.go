// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/egoist/mygo/ui"
)

var (
	vaultInk      = ui.Hex("#29292F")
	vaultMuted    = ui.Hex("#777681")
	vaultPanel    = ui.Hex("#F4F3F8")
	vaultWhite    = ui.Hex("#FFFFFF")
	vaultLavender = ui.Hex("#EAE5FA")
	vaultPurple   = ui.Hex("#7561AA")
	vaultLine     = ui.Hex("#E7E5ED")
	vaultTheme    = makeVaultTheme()
)

func makeVaultTheme() *ui.Theme {
	t := ui.LightTheme()
	t.Background, t.Surface = vaultPanel, vaultWhite
	t.Text, t.TextMuted, t.Border = vaultInk, vaultMuted, vaultLine
	t.Accent, t.AccentHover, t.AccentPressed = vaultInk, ui.Hex("#41414B"), ui.Hex("#17171C")
	t.SurfaceHover, t.SurfacePressed = ui.Hex("#EFECF7"), vaultLavender
	t.Selection, t.Focus = ui.RGBA(142, 121, 198, .2), ui.RGBA(117, 97, 170, .55)
	t.FontSize, t.Radius = 14, 16
	return t
}

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
	{"bank", "银行账户", "card", true},
	{"license", "驾驶证", "identity", true},
	{"passport", "护照", "identity", true},
	{"archive", "归档", "vault", true},
	{"trash", "回收站", "vault", true},
}

func (a *app) currentCategory() vaultCategory {
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

func (a *app) filteredItems() []displayCredential {
	if !a.currentCategory().supported || !a.unlocked() {
		return nil
	}
	query := strings.ToLower(strings.TrimSpace(a.query))
	items := make([]displayCredential, 0, len(a.items))
	for _, item := range a.items {
		if a.category == "personal" && item.OrganizationID != "" {
			continue
		}
		if strings.HasPrefix(a.category, "org:") && item.OrganizationID != strings.TrimPrefix(a.category, "org:") {
			continue
		}
		if strings.HasPrefix(a.category, "collection:") {
			found := false
			for _, id := range item.CollectionIDs {
				if a.category == "collection:"+id {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if strings.HasPrefix(a.category, "folder:") && item.FolderID != strings.TrimPrefix(a.category, "folder:") {
			continue
		}
		if item.Deleted != (a.category == "trash") {
			continue
		}
		if a.category != "trash" && item.Archived != (a.category == "archive") {
			continue
		}
		if a.category == "favorites" && !item.Favorite {
			continue
		}
		kind := map[string]int{"login": 1, "note": 2, "card": 3, "identity": 4, "ssh": 5, "bank": 6, "license": 7, "passport": 8}[a.category]
		if kind != 0 && item.Type != kind && !(kind == 1 && item.Type == 0) {
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
func (a *app) reconcileSelection(items []displayCredential) {
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
	c.SetTheme(vaultTheme)
	c.Root().Background(ui.Transparent)
	if a.showLogin || !a.unlocked() {
		a.authentication(c)
		return
	}
	ui.Row(c).Fill().TextColor(vaultInk).AlignItems(ui.Stretch).Children(func() {
		a.sidebar(c)
		ui.Column(c).Grow(1).MinWidth(0).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
			a.header(c)
			ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Gap(16).Children(func() { a.body(c) })
		})
	})
}

func (a *app) body(c *ui.Context) {
	ui.Row(c).Grow(1).MinHeight(0).Gap(16).AlignItems(ui.Stretch).Children(func() {
		items := a.filteredItems()
		a.reconcileSelection(items)
		a.credentialList(c, items)
		ui.Column(c).Key("detail-pane").Grow(1).MinWidth(0).Gap(16).Children(func() {
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
		icon(c, "shield", 15).TextColor(vaultPurple)
		ui.Text(c, a.status).FontSize(12).TextColor(vaultMuted).Grow(1).MinWidth(0).MaxLines(2).Tooltip(a.status).Role(ui.RoleStatus)
		if a.pending != 0 {
			ui.Text(c, "处理中…").FontSize(12).TextColor(vaultPurple)
		}
	})
}

func pill(c *ui.Context, text string, bg, fg ui.Color) {
	ui.Text(c, text).FontSize(11).TextColor(fg).Background(bg).Padding(5, 10).Radius(20).Shrink(0)
}

func action(c *ui.Context, label, symbol string, primary, disabled bool) *ui.Element {
	var b *ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	b.Label(label).Height(38).Padding(0, 14).Radius(20).Border(0, ui.Transparent).Disabled(disabled).Children(func() {
		if symbol != "" {
			icon(c, symbol, 17)
		}
		ui.Text(c, label).FontSize(13)
	})
	return b
}

func iconButton(c *ui.Context, label, symbol string) *ui.Element {
	return ui.Button(c, "").Label(label).Tooltip(label).Size(36, 36).Padding(8).Radius(18).Border(0, ui.Transparent).
		Children(func() { icon(c, symbol, 18) })
}

func toolbarButton(c *ui.Context, label, symbol string, primary, disabled bool) *ui.Element {
	var b *ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	b.Label(label).Height(32).Padding(0, 13).Gap(6).Radius(16).Disabled(disabled).Children(func() {
		icon(c, symbol, 15)
		ui.Text(c, label).FontSize(13)
	})
	if !primary {
		b.Border(1, ui.RGBA(255, 255, 255, .7)).Background(ui.RGBA(255, 255, 255, .55))
	} else {
		b.Border(0, ui.Transparent)
	}
	return b
}

// header is a unified toolbar: it sits beside the traffic lights' row and
// shares the content background, like a native macOS toolbar.
func (a *app) header(c *ui.Context) {
	bar := c.TitleBar()
	ui.Row(c).Height(max(bar.Height, 52)).Shrink(0).Gap(10).AlignItems(ui.Center).
		Padding(0, 20, 0, 20).DragWindow().Children(func() {
		ui.Spacer(c)
		state := "未解锁"
		if a.unlocked() {
			state = "本机已解锁"
		}
		if a.session != nil {
			state = "可同步"
		}
		pill(c, state, vaultLavender, vaultPurple)
		if toolbarButton(c, "导入导出", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBackupEditor()
		}
		if toolbarButton(c, "新增", "key", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			kind := map[string]int{"login": 1, "note": 2, "card": 3, "identity": 4, "ssh": 5, "bank": 6, "license": 7, "passport": 8}[a.category]
			if kind == 0 {
				kind = 1
			}
			a.openCipherEditor("", kind)
		}
		if toolbarButton(c, "批量管理", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBulkEditor(false)
		}
		if a.category == "trash" && toolbarButton(c, "清空回收站", "vault", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil).Clicked() {
			a.openBulkEditor(true)
		}
		if toolbarButton(c, "同步", "sync", false, a.pending != 0).Clicked() {
			a.syncVault(false)
		}
		if toolbarButton(c, "锁定", "lock", true, false).Clicked() {
			a.runStorage("lock")
		}
		if ui.Button(c, "").Label("账号与设置").Tooltip("账号与设置").Size(32, 32).Padding(7).Radius(16).
			Border(1, ui.RGBA(255, 255, 255, .7)).Background(ui.RGBA(255, 255, 255, .55)).
			Children(func() { icon(c, "settings", 16) }).Clicked() {
			a.showSettings = !a.showSettings
		}
	})
}

func (a *app) sidebar(c *ui.Context) {
	bar := c.TitleBar()
	ui.Row(c).Shrink(0).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Width(236).Shrink(0).Padding(0, 12, 12, 12).Gap(8).Background(ui.Hex("#F2F1F7")).Children(func() { a.sidebarContent(c, bar) })
		ui.Box(c).Width(1).Background(vaultLine)
	})
}

func (a *app) sidebarContent(c *ui.Context, bar ui.TitleBar) {
	{
		ui.Box(c).Height(max(bar.Height, 52) - 8).Shrink(0).DragWindow()
		ui.Row(c).Padding(2, 8, 8, 8).Gap(10).AlignItems(ui.Center).Children(func() {
			if appLogo != nil {
				ui.Image(c, appLogo).Size(32, 32).Shrink(0)
			}
			ui.Column(c).Gap(1).Children(func() {
				ui.Text(c, "Vaultwarden").FontSize(14).FontWeight(650).SingleLine()
				ui.Text(c, "个人密码库").FontSize(11).TextColor(vaultMuted).SingleLine()
			})
		})
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				sectionLabel(c, "所有密码库")
				if navItem(c, "我的密码库", "user", "", a.category == "personal", false).Clicked() {
					a.category, a.query, a.showSettings = "personal", "", false
				}
				ui.Box(c).Height(10)
				sectionLabel(c, "项目")
				for _, category := range vaultCategories {
					count := ""
					if category.supported && a.unlocked() {
						count = fmt.Sprint(len(a.items))
					}
					b := navItem(c, category.title, category.symbol, count, a.currentCategory().id == category.id && !a.showSettings, false)
					if !category.supported {
						b.Tooltip("此分类尚未同步")
					}
					if b.Clicked() {
						a.category, a.showSettings = category.id, false
						a.listState.ScrollTo(0, ui.Start)
					}
				}
				sectionLabel(c, "组织")
				if navItem(c, "创建组织", "vault", "", false, a.pending != 0 || a.vault == nil || a.organizationEditor != nil).Clicked() {
					a.openOrganizationEditor("")
				}
				if strings.HasPrefix(a.category, "org:") && navItem(c, "管理当前组织", "settings", "", false, a.pending != 0 || a.organizationEditor != nil).Clicked() {
					a.openOrganizationEditor(strings.TrimPrefix(a.category, "org:"))
				}
				for _, org := range a.organizations {
					if navItem(c, org.Name, "vault", "", a.category == "org:"+org.ID, false).Clicked() {
						a.category, a.showSettings = "org:"+org.ID, false
					}
					for _, collection := range a.collections {
						if collection.OrganizationID == org.ID && navItem(c, "  "+collection.Name, "vault", "", a.category == "collection:"+collection.ID, false).Clicked() {
							a.category, a.showSettings = "collection:"+collection.ID, false
						}
					}
				}
				for _, org := range a.isolatedOrganizations {
					if navItem(c, "重新核验："+org.Name, "settings", "", false, a.pending != 0 || a.organizationEditor != nil).Clicked() {
						a.openOrganizationEditor(org.ID)
					}
				}
				sectionLabel(c, "文件夹")
				if navItem(c, "无文件夹", "vault", "", a.category == "folder:", false).Clicked() {
					a.category, a.showSettings = "folder:", false
				}
				for _, f := range a.folders {
					if navItem(c, f.Name, "vault", "", a.category == "folder:"+f.ID, false).Clicked() {
						a.category, a.showSettings = "folder:"+f.ID, false
					}
				}
				if navItem(c, "新建文件夹", "vault", "", false, a.pending != 0 || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.backupEditor != nil).Clicked() {
					a.openFolderEditor("")
				}
				if strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
					if navItem(c, "管理文件夹", "settings", "", false, a.pending != 0 || a.editor != nil || a.folderEditor != nil || a.backupEditor != nil).Clicked() {
						a.openFolderEditor(strings.TrimPrefix(a.category, "folder:"))
					}
				}
			})
		})
		if navItem(c, "账号与设置", "settings", "", a.showSettings, false).Clicked() {
			a.showSettings = !a.showSettings
		}
	}
}

func sectionLabel(c *ui.Context, text string) {
	ui.Text(c, text).Padding(3, 10).FontSize(11).TextColor(vaultMuted)
}

func navItem(c *ui.Context, title, symbol, count string, selected, disabled bool) *ui.Element {
	b := ui.ButtonBase(c).Label(title).Height(32).Padding(0, 11).Gap(10).Radius(20).Disabled(disabled).TextColor(vaultMuted)
	if selected {
		b.Background(vaultWhite).TextColor(vaultInk).Shadow(0, 2, 6, 0, ui.RGBA(38, 30, 62, .06))
	} else if b.Hovered() && !disabled {
		b.Background(ui.RGBA(255, 255, 255, .6))
	}
	if disabled {
		b.Opacity(.5)
	}
	b.Children(func() {
		icon(c, symbol, 18)
		ui.Text(c, title).Grow(1).FontSize(13).SingleLine()
		if count != "" {
			ui.Text(c, count).FontSize(11).Background(ui.RGBA(255, 255, 255, .7)).Padding(2, 6).Radius(9)
		}
	})
	return b
}

func (a *app) credentialList(c *ui.Context, items []displayCredential) {
	w, _ := c.Size()
	width := float32(304)
	if w >= 1240 {
		width = 330
	}
	ui.Column(c).Width(width).Shrink(0).Padding(12).Gap(12).Background(vaultPanel).Radius(26).Border(1, ui.RGBA(255, 255, 255, .65)).Children(func() {
		ui.Row(c).Padding(10, 8, 0, 8).Children(func() {
			ui.Text(c, a.currentCategory().title).FontSize(22).FontWeight(650)
			ui.Spacer(c)
			pill(c, fmt.Sprint(len(items)), vaultWhite, vaultMuted)
		})
		field := ui.Row(c).Key("vault-search").Background(vaultWhite).Radius(22).Padding(0, 12).Height(43).Gap(8)
		field.Children(func() {
			icon(c, "search", 18).TextColor(vaultMuted)
			search := ui.TextInput(c, &a.query).Label("搜索密码库").Placeholder("搜索密码库").Grow(1).MinWidth(0).Border(0, ui.Transparent).Background(ui.Transparent).Padding(0).FocusRing(false)
			if c.Shortcut(ui.Cmd, ui.KeyF) {
				search.Focus()
			}
			if search.Focused() {
				field.DrawOver(func(p *ui.Painter, r ui.Rect) {
					outer := ui.Rect{X: r.X - 2, Y: r.Y - 2, W: r.W + 4, H: r.H + 4}
					p.Stroke(outer, vaultPurple, 24, 2)
				})
			}
			if search.Changed() {
				a.listState.ScrollTo(0, ui.Start)
			}
			if a.query != "" {
				if iconButton(c, "清除搜索", "close").Size(25, 25).Padding(5).Clicked() {
					a.query = ""
				}
			} else {
				ui.Text(c, "⌘ F").FontSize(10).TextColor(vaultMuted)
			}
		})
		ui.Row(c).Padding(0, 8).Children(func() {
			ui.Text(c, "名称").FontSize(11).TextColor(vaultMuted)
			ui.Spacer(c)
			ui.Text(c, "A – Z").FontSize(10).TextColor(vaultMuted)
		})
		if len(items) == 0 {
			ui.Column(c).Grow(1).Justify(ui.Center).AlignItems(ui.Center).Gap(12).Padding(20).Children(func() {
				icon(c, "search", 30).TextColor(vaultPurple)
				title, subtitle := a.emptyListMessage()
				ui.Text(c, title).FontSize(15).FontWeight(550).TextAlign(ui.Center)
				ui.Text(c, subtitle).FontSize(12).TextColor(vaultMuted).TextAlign(ui.Center)
			})
		} else {
			a.listState.Key = func(i int) any { return items[i].ID }
			a.listState.Label = func(i int) string { return items[i].Title }
			a.listState.Selected = &a.selectedRow
			listTheme := *vaultTheme
			listTheme.Accent, listTheme.AccentText, listTheme.Radius = vaultWhite, vaultInk, 19
			c.SetTheme(&listTheme)
			list := ui.List(c, &a.listState, len(items), func(i int) {
				item := items[i]
				row := ui.Row(c).Key(item.ID).TextColor(vaultInk).Padding(12).Gap(12).Height(78).Radius(19)
				if a.selectedRow == i {
					row.Background(vaultWhite).Border(1, ui.Hex("#DDD5EE"))
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
						ui.Text(c, subtitle).FontSize(12).TextColor(vaultMuted).SingleLine()
					})
					if a.selectedRow == i {
						icon(c, "chevron", 13).TextColor(vaultPurple)
					}
				})
			}).Label("密码库项目").Grow(1).MinHeight(0).Gap(5)
			c.SetTheme(vaultTheme)
			if list.Changed() && a.selectedRow >= 0 && a.selectedRow < len(items) {
				a.selectedID = items[a.selectedRow].ID
				a.showSettings = false
			}
		}
		ui.Text(c, fmt.Sprintf("已载入 %d 个项目 · 个人密码库", len(a.items))).FontSize(11).TextColor(vaultMuted).Padding(4, 8)
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

func displayTitle(item displayCredential) string {
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

func credentialAvatar(c *ui.Context, item displayCredential, size float32) {
	colors := []ui.Color{ui.Hex("#E9E2F7"), ui.Hex("#E0EAE9"), ui.Hex("#F2E7DE"), ui.Hex("#DFE7F2")}
	r, _ := utf8.DecodeRuneInString(displayTitle(item))
	index := int(r) % len(colors)
	ui.Row(c).Size(size, size).Shrink(0).Justify(ui.Center).Radius(size * .31).Background(colors[index]).Children(func() {
		ui.Text(c, strings.ToUpper(string(r))).FontSize(size * .43).FontWeight(650).TextColor(vaultInk)
	})
}

func (a *app) credentialDetail(c *ui.Context, item displayCredential) {
	ui.Scroll(c).Key(item.ID).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(14).Padding(10, 8, 8, 8).Children(func() {
			ui.Row(c).Gap(8).Children(func() {
				ui.Text(c, "我的密码库").FontSize(12).TextColor(vaultMuted)
				icon(c, "chevron", 12).TextColor(vaultMuted)
				kind := "登录"
				if item.Type > 0 && item.Type < len(cipherTypeNames) {
					kind = cipherTypeNames[item.Type]
				}
				ui.Text(c, kind).FontSize(12).TextColor(vaultMuted)
				ui.Spacer(c)
				if action(c, "查看与编辑", "", false, a.pending != 0 || (!item.Editable && !item.Readable && !item.RequiresPassword) || a.vault == nil).Clicked() {
					a.openCipherEditor(item.ID, item.Type)
				}
			})
			ui.Row(c).Gap(16).Children(func() {
				credentialAvatar(c, item, 60)
				ui.Column(c).Grow(1).MinWidth(0).Gap(6).Children(func() {
					ui.Text(c, displayTitle(item)).FontSize(29).FontWeight(650).MaxLines(2).Tooltip(displayTitle(item))
					ui.Text(c, websiteHost(item.URL)).FontSize(13).TextColor(vaultMuted).SingleLine()
				})
			})
			ui.Row(c).Gap(8).Children(func() {
				if action(c, "打开网站", "external", true, !safeWebsite(item.URL)).Clicked() {
					c.OpenURL(item.URL)
				}
				if action(c, "复制用户名", "copy", false, item.Username == "").Clicked() {
					c.WriteClipboard(item.Username)
					a.status = "用户名已复制。"
				}
			})
			detailCard(c, "登录信息", func() {
				detailField(c, "用户名", item.Username, "未填写用户名")
				ui.Divider(c)
				ui.Row(c).Padding(12, 16).Gap(10).Children(func() {
					ui.Column(c).Grow(1).Gap(7).Children(func() {
						ui.Text(c, "密码").FontSize(11).TextColor(vaultMuted)
						ui.Text(c, "由系统安全自动填充").FontSize(14)
					})
					icon(c, "lock", 19).TextColor(vaultPurple)
				})
			})
			detailCard(c, "网站", func() { detailField(c, "登录地址", item.URL, "未填写网站") })
			ui.Column(c).Gap(8).Padding(14, 18).Background(vaultLavender).Radius(22).Children(func() {
				ui.Row(c).Gap(9).Children(func() {
					icon(c, "shield", 20).TextColor(vaultPurple)
					ui.Text(c, "安全自动填充").FontWeight(600)
					ui.Spacer(c)
					if iconButton(c, "自动填充设置", "settings").Size(30, 30).Padding(7).Clicked() {
						openAutoFillSettings(c)
					}
				})
				ui.Text(c, "在 Safari 中选择此凭据，完成系统认证后填充密码。").FontSize(12).LineHeight(1.5).TextColor(vaultPurple)
			})
		})
	})
}

func detailCard(c *ui.Context, title string, content func()) {
	ui.Column(c).Gap(8).Padding(10).Background(vaultPanel).Radius(24).Children(func() {
		ui.Text(c, title).Padding(3, 6).FontSize(14).FontWeight(550)
		ui.Column(c).Background(vaultWhite).Radius(16).Clip().Children(content)
	})
}

func detailField(c *ui.Context, label, value, empty string) {
	ui.Column(c).Gap(8).Padding(12, 16).Children(func() {
		ui.Text(c, label).FontSize(11).TextColor(vaultMuted)
		if value == "" {
			ui.Text(c, empty).FontSize(14).TextColor(vaultMuted)
		} else {
			ui.Text(c, value).FontSize(14).MaxLines(3).Tooltip(value)
		}
	})
}

func (a *app) emptyDetail(c *ui.Context) {
	ui.Column(c).Grow(1).Background(ui.RGBA(247, 246, 251, .6)).Radius(26).Padding(34).Justify(ui.Center).AlignItems(ui.Center).Gap(16).Children(func() {
		ui.Row(c).Size(76, 76).Justify(ui.Center).Radius(26).Background(vaultWhite).Children(func() { icon(c, "vault", 38).TextColor(vaultPurple) })
		ui.Text(c, "选择一个项目").FontSize(23).FontWeight(600).TextAlign(ui.Center)
		ui.Text(c, "项目的登录信息和网站会显示在这里。").FontSize(13).LineHeight(1.6).TextColor(vaultMuted).TextAlign(ui.Center)
	})
}

func openAutoFillSettings(c *ui.Context) {
	c.OpenURL("x-apple.systempreferences:com.apple.Passwords-Settings.extension")
}

func (a *app) settings(c *ui.Context) {
	ready := a.snapshot != nil && a.pending == 0
	available := a.snapshot != nil && a.snapshot.Available
	ui.Scroll(c).Key("settings").Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(18).Padding(10, 8).Children(func() {
			ui.Row(c).Children(func() {
				ui.Text(c, "账号与设置").FontSize(26).FontWeight(650)
				ui.Spacer(c)
				if iconButton(c, "关闭设置", "close").Clicked() {
					a.showSettings = false
				}
			})
			detailCard(c, "连接密码库", func() {
				ui.Column(c).Padding(16).Gap(13).Children(func() {
					ui.Text(c, a.connectedServer()).FontSize(14).MaxLines(2)
					ui.Text(c, "登录凭据在本地加密保存，解锁后可同步；也可连接其他服务器与账号。").FontSize(12).LineHeight(1.5).TextColor(vaultMuted)
					if action(c, "登录服务器", "user", true, a.pending != 0).Clicked() {
						a.resetLoginForm()
						a.showLogin = true
						a.status = ""
					}
				})
			})
			detailCard(c, "本机存储与自动填充", func() {
				ui.Column(c).Padding(16).Gap(12).Children(func() {
					state := "尚无本机快照"
					if available {
						state = fmt.Sprintf("本机快照 · %d 个登录项目", a.snapshot.Count)
					}
					ui.Text(c, state).FontSize(13)
					if available && a.snapshot.UpdatedAt > 0 {
						ui.Text(c, "最近同步："+time.UnixMilli(a.snapshot.UpdatedAt).Format("2006-01-02 15:04")).FontSize(11).TextColor(vaultMuted)
					}
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if action(c, "离线解锁", "lock", false, !ready || !available).Clicked() {
							a.runStorage("list")
						}
						if action(c, "刷新状态", "sync", false, a.pending != 0).Clicked() {
							a.runStorage("status")
						}
					})
					ui.Divider(c)
					if a.snapshot != nil && a.snapshot.IndexPending {
						ui.Text(c, "系统候选尚未确认同步，请刷新状态或认证更新。").FontSize(12).TextColor(vaultPurple)
					}
					ui.Row(c).Gap(8).Wrap().Children(func() {
						if action(c, "自动填充设置", "settings", false, false).Clicked() {
							openAutoFillSettings(c)
						}
						if action(c, "更新系统候选", "shield", false, !ready || !available).Clicked() {
							a.runStorage("reindex")
						}
					})
					if a.snapshot != nil && a.snapshot.CleanupPending {
						ui.Text(c, "旧密钥清理尚未完成。").FontSize(12).TextColor(vaultPurple)
						if action(c, "重试清理", "sync", false, !ready).Clicked() {
							a.runStorage("retryCleanup")
						}
					}
				})
			})
			ui.Row(c).Gap(8).Wrap().Children(func() {
				if action(c, "退出账号", "user", false, a.snapshot == nil).Clicked() {
					a.runStorage("logout")
				}
			})
			ui.Text(c, "MyGo Vaultwarden · macOS 原生\n支持个人八类型项目编辑；组织与更多功能仍在开发。").FontSize(11).TextColor(vaultMuted).LineHeight(1.6)
		})
	})
}
