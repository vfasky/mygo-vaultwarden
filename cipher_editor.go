// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type editorField struct {
	key, label, value string
	secret            bool
}
type editorURI struct {
	source    map[string]any
	value     string
	showMatch bool
}

type editorCustom struct {
	source           map[string]any
	name, value      string
	hidden, editable bool
	kind             string
	linkedID         json.Number
	showLinks        bool
}

type cipherEditor struct {
	attachments                            []vaultwarden.AttachmentInfo
	attachmentsLoaded, attachmentBusy      bool
	attachmentDelete                       string
	defaultURIMatch                        int
	organizationID, collectionID           string
	shareOrganizationID, shareCollectionID string
	document                               vaultwarden.CipherDocument
	fields                                 vaultwarden.CipherFields
	inputs                                 []editorField
	notes                                  string
	uris                                   []editorURI
	custom                                 []editorCustom
	conflict                               bool
	comparison                             *vaultwarden.CipherRebase
	changes                                []vaultwarden.CipherChange
	localChoices                           map[string]bool
	compareAuthorization                   bool
	uncertain                              bool
	saved                                  bool
	revision                               string
	confirm                                vaultwarden.CipherAction
	showHistory                            bool
	confirmHistoryDelete                   bool
	authorization                          *vaultwarden.ItemAuthorization
	repromptID, repromptPassword           string
	authorizationExpires                   time.Time
	shownSecret                            string
	shownSecretExpires                     time.Time
}

var cipherTypeNames = []string{"", "登录", "安全笔记", "支付卡", "身份", "SSH 密钥", "银行账户", "驾驶证", "护照"}
var editorSpecs = map[int][]editorField{
	1: {{key: "username", label: "用户名"}, {key: "password", label: "密码", secret: true}, {key: "totp", label: "验证码密钥", secret: true}},
	2: {},
	3: {{key: "cardholderName", label: "持卡人"}, {key: "brand", label: "卡组织"}, {key: "number", label: "卡号", secret: true}, {key: "expMonth", label: "到期月"}, {key: "expYear", label: "到期年"}, {key: "code", label: "安全码", secret: true}},
	4: {{key: "title", label: "称谓"}, {key: "firstName", label: "名"}, {key: "middleName", label: "中间名"}, {key: "lastName", label: "姓"}, {key: "address1", label: "地址一"}, {key: "address2", label: "地址二"}, {key: "address3", label: "地址三"}, {key: "city", label: "城市"}, {key: "state", label: "省/州"}, {key: "postalCode", label: "邮编"}, {key: "country", label: "国家"}, {key: "company", label: "公司"}, {key: "email", label: "邮箱"}, {key: "phone", label: "电话"}, {key: "ssn", label: "社会保障号码", secret: true}, {key: "username", label: "用户名"}, {key: "passportNumber", label: "护照号码", secret: true}, {key: "licenseNumber", label: "驾驶证号码", secret: true}},
	5: {{key: "privateKey", label: "私钥", secret: true}, {key: "publicKey", label: "公钥"}, {key: "keyFingerprint", label: "指纹"}},
	6: {{key: "bankName", label: "银行名称"}, {key: "nameOnAccount", label: "账户姓名"}, {key: "accountType", label: "账户类型"}, {key: "accountNumber", label: "账号", secret: true}, {key: "routingNumber", label: "路由号码"}, {key: "branchNumber", label: "分行号码"}, {key: "pin", label: "PIN", secret: true}, {key: "swiftCode", label: "SWIFT"}, {key: "iban", label: "IBAN"}, {key: "bankContactPhone", label: "银行电话"}},
	7: {{key: "firstName", label: "名"}, {key: "middleName", label: "中间名"}, {key: "lastName", label: "姓"}, {key: "dateOfBirth", label: "出生日期"}, {key: "licenseNumber", label: "驾驶证号码", secret: true}, {key: "issuingCountry", label: "签发国家"}, {key: "issuingState", label: "签发省/州"}, {key: "issueDate", label: "签发日期"}, {key: "expirationDate", label: "到期日期"}, {key: "issuingAuthority", label: "签发机关"}, {key: "licenseClass", label: "准驾车型"}},
	8: {{key: "surname", label: "姓"}, {key: "givenName", label: "名"}, {key: "dateOfBirth", label: "出生日期"}, {key: "sex", label: "性别"}, {key: "birthPlace", label: "出生地"}, {key: "nationality", label: "国籍"}, {key: "issuingCountry", label: "签发国家"}, {key: "passportNumber", label: "护照号码", secret: true}, {key: "passportType", label: "护照类型"}, {key: "nationalIdentificationNumber", label: "身份证号码", secret: true}, {key: "issuingAuthority", label: "签发机关"}, {key: "issueDate", label: "签发日期"}, {key: "expirationDate", label: "到期日期"}},
}

func sectionFields(f *vaultwarden.CipherFields) map[string]any {
	switch f.Type {
	case 1:
		return f.Login
	case 2:
		return f.SecureNote
	case 3:
		return f.Card
	case 4:
		return f.Identity
	case 5:
		return f.SSHKey
	case 6:
		return f.BankAccount
	case 7:
		return f.DriversLicense
	case 8:
		return f.Passport
	}
	return nil
}
func (a *app) adoptVault(vault *vaultwarden.VaultData) error {
	a.clearOrganizationEditor()
	organizationPrompt := a.editor != nil && a.organizationItem(a.editor.repromptID)
	a.vault = nil
	a.folders = nil
	a.organizations, a.collections, a.isolatedOrganizations = nil, nil, nil
	if vault == nil {
		return nil
	}
	a.items = nil
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.liveScope == nil || vault.Scope != *a.liveScope {
		return vaultwarden.ErrIdentity
	}
	if err := session.ValidateAuthenticatedSnapshot(vault, a.sessionRevision); err != nil {
		return err
	}
	entries, err := session.PersonalEntries(vault)
	if err != nil {
		return err
	}
	folders, err := session.PersonalFolders(vault)
	if err != nil {
		return err
	}
	organizations, collections, err := session.Organizations(vault)
	if err != nil {
		return err
	}
	isolated, err := session.IsolatedOrganizations(vault)
	if err != nil {
		return err
	}
	orgEntries, err := session.OrganizationEntries(vault)
	if err != nil {
		return err
	}
	entries = append(entries, orgEntries...)
	items := make([]displayCredential, 0, len(entries))
	for _, e := range entries {
		items = append(items, displayCredential{OrganizationID: e.OrganizationID, CollectionIDs: e.CollectionIDs, Readable: e.Readable, ID: e.ID, Title: e.Title, Username: e.Username, URL: e.URL, Type: e.Type, Favorite: e.Favorite, Archived: e.Archived, Deleted: e.Deleted, Editable: e.Editable, RequiresPassword: e.RequiresPassword, FolderID: e.FolderID})
	}
	a.clearSecretClipboard()
	if a.editor != nil {
		e := a.editor
		organizationDraft := organizationPrompt || e.fields.OrganizationID != nil || e.organizationID != "" || e.shareOrganizationID != ""
		for _, entry := range entries {
			if entry.ID == e.fields.ID && entry.OrganizationID != "" {
				organizationDraft = true
			}
		}
		if organizationDraft {
			// A new organization sync may revoke access or replace its owner key.
			// Personal conflict retention must not keep organization plaintext alive.
			*e = cipherEditor{}
			a.editor = nil
			a.secretInputVersion++
		}
	}
	a.organizations, a.collections, a.isolatedOrganizations = organizations, collections, isolated
	a.vault, a.items, a.folders = vault, items, folders
	if strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
		found := false
		for _, folder := range folders {
			if a.category == "folder:"+folder.ID {
				found = true
				break
			}
		}
		if !found {
			a.category = "folder:"
		}
	}
	return nil
}
func (a *app) openCipherEditor(id string, kind int) {
	a.openCipherEditorAuthorized(id, kind, nil)
}

func (a *app) openCipherEditorAuthorized(id string, kind int, grant *vaultwarden.ItemAuthorization) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.organizationEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	defaultMatch, err := session.DefaultURIMatch(a.vault)
	if err != nil {
		a.status = err.Error()
		return
	}
	editor := &cipherEditor{revision: a.sessionRevision, authorization: grant, defaultURIMatch: defaultMatch}
	if grant != nil {
		editor.authorizationExpires = grant.ExpiresAt()
	}
	if err := session.BindSnapshotRevision(*a.liveScope, a.sessionRevision); err != nil {
		a.status = err.Error()
		return
	}
	if id != "" {
		var err error
		if a.organizationItem(id) {
			editor.document, editor.fields, err = session.ReadOrganizationCipher(a.vault, id, grant)
		} else {
			editor.document, editor.fields, err = session.ReadPersonalCipherAuthorized(a.vault, id, grant)
		}
		if err != nil {
			if errors.Is(err, vaultwarden.ErrPermission) && grant == nil && (session.PersonalItemRequiresPassword(a.vault, id) || a.organizationItemRequiresPassword(id)) {
				editor.repromptID = id
				a.editor = editor
				a.secretInputVersion++
			}
			a.status = err.Error()
			return
		}
		if (!editor.fields.Edit && editor.fields.OrganizationID == nil) || !editor.fields.ViewPassword {
			a.status = vaultwarden.ErrPermission.Error()
			return
		}
	} else {
		editor.fields = vaultwarden.CipherFields{Type: kind, Login: map[string]any{}, SecureNote: map[string]any{}, Card: map[string]any{}, Identity: map[string]any{}, SSHKey: map[string]any{}, BankAccount: map[string]any{}, DriversLicense: map[string]any{}, Passport: map[string]any{}}
	}
	populateCipherEditor(editor)
	if id == "" {
		for _, collection := range a.collections {
			if a.category == "collection:"+collection.ID {
				if collection.ReadOnly || collection.HidePasswords {
					a.status = vaultwarden.ErrPermission.Error()
					return
				}
				editor.organizationID, editor.collectionID = collection.OrganizationID, collection.ID
			}
		}
		if strings.HasPrefix(a.category, "org:") {
			a.status = "请先选择可写集合，再新增组织项目。"
			return
		}
	}
	a.editor = editor
	a.folderEditor = nil
	if id == "" && strings.HasPrefix(a.category, "folder:") && a.category != "folder:" {
		folder := strings.TrimPrefix(a.category, "folder:")
		editor.fields.FolderID = &folder
	}
	a.secretInputVersion++
	a.showSettings = false
}

func populateCipherEditor(editor *cipherEditor) {
	editor.inputs, editor.uris, editor.custom = nil, nil, nil
	editor.notes = ""
	editor.inputs = append([]editorField(nil), editorSpecs[editor.fields.Type]...)
	section := sectionFields(&editor.fields)
	for i := range editor.inputs {
		editor.inputs[i].value, _ = section[editor.inputs[i].key].(string)
	}
	if uris, ok := editor.fields.Login["uris"].([]any); ok {
		for _, raw := range uris {
			if uri, ok := raw.(map[string]any); ok {
				value, _ := uri["uri"].(string)
				editor.uris = append(editor.uris, editorURI{source: uri, value: value})
			}
		}
	}
	for _, field := range editor.fields.Fields {
		name, _ := field["name"].(string)
		value, _ := field["value"].(string)
		kind, _ := field["type"].(json.Number)
		linked, _ := field["linkedId"].(json.Number)
		editor.custom = append(editor.custom, editorCustom{source: field, name: name, value: value, hidden: kind == "1", editable: kind == "0" || kind == "1" || kind == "2" || kind == "3", kind: string(kind), linkedID: linked})
	}
	if editor.fields.Notes != nil {
		editor.notes = *editor.fields.Notes
	}
}
func (a *app) cipherEditorView(c *ui.Context) {
	e := a.editor
	if e.fields.OrganizationID != nil && !e.fields.Edit && e.repromptID == "" {
		a.readOnlyOrganizationCipherView(c, e)
		return
	}
	if e.repromptID != "" && !e.compareAuthorization {
		a.itemAuthorizationView(c)
		return
	}
	if !e.authorizationExpires.IsZero() {
		if !time.Now().Before(e.authorizationExpires) {
			e.shownSecret = ""
			if a.pending == 0 {
				*e = cipherEditor{}
			}
			a.editor = nil
			a.secretInputVersion++
			a.status = "项目授权已到期，请重新验证主密码。"
			return
		}
		c.After(time.Until(e.authorizationExpires))
	}
	if e.shownSecret != "" {
		if !time.Now().Before(e.shownSecretExpires) || !a.sessionOwnsSnapshot() || e.revision != a.sessionRevision {
			e.shownSecret = ""
		} else {
			c.After(time.Until(e.shownSecretExpires))
		}
	}
	if e.repromptID != "" {
		a.itemAuthorizationView(c)
		return
	}
	if e.comparison != nil {
		a.cipherComparisonView(c)
		return
	}
	ui.Scroll(c).Key(fmt.Sprintf("cipher-editor-%d", a.secretInputVersion)).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Gap(12).Padding(18).Children(func() {
			title := "编辑"
			if e.fields.ID == "" {
				title = "新增"
			}
			ui.Text(c, title+cipherTypeNames[e.fields.Type]).FontSize(23).FontWeight(600)
			if e.fields.OrganizationID != nil || e.organizationID != "" {
				ui.Text(c, "组织权限以最新同步为准；同步会关闭此表单并清除未保存更改。").FontSize(12)
			}
			if e.organizationID != "" && e.fields.ID == "" {
				a.organizationTypePicker(c, e)
			}
			ui.Text(c, "标题").FontSize(12)
			ui.TextInput(c, &e.fields.Name).Label("标题").Disabled(a.pending != 0 || e.uncertain)
			for i := range e.inputs {
				f := &e.inputs[i]
				ui.Text(c, f.label).FontSize(12)
				ui.Column(c).Key(f.key).Children(func() {
					var input *ui.Element
					if f.key == "privateKey" || f.key == "publicKey" {
						input = ui.TextArea(c, &f.value).MinHeight(100)
					} else {
						input = ui.TextInput(c, &f.value)
					}
					input.Label(f.label).Disabled(a.pending != 0 || e.uncertain)
					if f.secret {
						input.Password()
					}
				})
			}
			if e.fields.Type == 1 {
				if e.fields.ID != "" {
					ui.Row(c).Gap(8).Children(func() {
						if action(c, "显示已保存密码", "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.showPersonalSecret("password", callStorage)
						}
						if action(c, "显示当前验证码", "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.showPersonalSecret("totp", callStorage)
						}
						if action(c, "复制已保存密码", "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.copyPersonalSecret("password", callStorage)
						}
						if action(c, "复制当前验证码", "", false, a.pending != 0 || e.uncertain).Clicked() {
							a.copyPersonalSecret("totp", callStorage)
						}
					})
					if e.shownSecret != "" {
						ui.Text(c, e.shownSecret).FontSize(20)
						if action(c, "隐藏", "", false, false).Clicked() {
							e.shownSecret = ""
						}
					}
					ui.Text(c, "显示与复制使用已保存内容，最多显示 30 秒；剪贴板可被其他应用读取。").FontSize(12)
				}
				ui.Text(c, "网站").FontSize(12)
				remove := -1
				for i := range e.uris {
					uri := &e.uris[i]
					ui.Row(c).Key(fmt.Sprintf("uri-%d", i)).Gap(8).Children(func() {
						ui.TextInput(c, &uri.value).Label(fmt.Sprintf("网站 %d", i+1)).Grow(1).Disabled(a.pending != 0 || e.uncertain)
						if action(c, "移除", "", false, a.pending != 0 || e.uncertain).Clicked() {
							remove = i
						}
					})
					a.uriMatchPicker(c, uri, a.pending != 0 || e.uncertain)
				}
				if remove >= 0 {
					e.uris = append(e.uris[:remove], e.uris[remove+1:]...)
				}
				if action(c, "添加网站", "", false, a.pending != 0 || e.uncertain || len(e.uris) >= 128).Clicked() {
					e.uris = append(e.uris, editorURI{source: map[string]any{"match": nil}})
				}
			}
			a.folderPicker(c, &e.fields.FolderID, a.pending != 0 || e.uncertain)
			favorite := "加入收藏"
			if e.fields.Favorite {
				favorite = "取消收藏"
			}
			if action(c, favorite, "star", false, a.pending != 0 || e.uncertain).Clicked() {
				e.fields.Favorite = !e.fields.Favorite
			}
			ui.Text(c, "自定义字段").FontSize(12)
			removeCustom := -1
			for i := range e.custom {
				field := &e.custom[i]
				ui.Column(c).Key(fmt.Sprintf("custom-%d", i)).Gap(6).Children(func() {
					ui.TextInput(c, &field.name).Label("字段名称").Disabled(a.pending != 0 || e.uncertain || !field.editable)
					a.customValueEditor(c, e, field)
					if action(c, "删除字段", "", false, a.pending != 0 || e.uncertain).Clicked() {
						removeCustom = i
					}
				})
			}
			if removeCustom >= 0 {
				e.custom = append(e.custom[:removeCustom], e.custom[removeCustom+1:]...)
			}
			ui.Row(c).Gap(8).Children(func() {
				if action(c, "添加文本字段", "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("0")}, editable: true, kind: "0"})
				}
				if action(c, "添加隐藏字段", "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("1")}, hidden: true, editable: true, kind: "1"})
				}
			})
			ui.Row(c).Gap(8).Children(func() {
				if action(c, "添加布尔字段", "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("2")}, value: "false", editable: true, kind: "2"})
				}
				if len(linkedFields[e.fields.Type]) > 0 && action(c, "添加关联字段", "", false, a.pending != 0 || e.uncertain).Clicked() {
					e.custom = append(e.custom, editorCustom{source: map[string]any{"type": json.Number("3")}, editable: true, kind: "3", linkedID: linkedFields[e.fields.Type][0].id})
				}
			})
			a.passwordHistoryView(c, e)
			a.attachmentView(c, e)
			ui.Text(c, "备注").FontSize(12)
			ui.TextArea(c, &e.notes).Label("备注").MinHeight(100).Disabled(a.pending != 0 || e.uncertain)
			if e.uncertain {
				ui.Text(c, "请先同步核对服务器结果，当前表单不会重复提交。").FontSize(12).TextColor(vaultPurple)
			}
			if e.fields.OrganizationID == nil && e.fields.ID != "" && (e.conflict || e.uncertain || e.revision != a.sessionRevision) {
				ui.Text(c, "草稿已保留。先同步核实结果，再比较改动；不会自动重试。秘密比较仅显示是否更改。")
				if action(c, "同步最新版本", "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
				if action(c, "比较本地与远端改动", "", false, a.pending != 0 || e.revision == a.sessionRevision).Clicked() {
					a.compareCipher(nil)
				}
			}
			ui.Row(c).Gap(8).Children(func() {
				if action(c, "保存", "sync", true, a.pending != 0 || e.conflict || e.revision != a.sessionRevision || e.uncertain || e.fields.Name == "").Clicked() {
					a.saveCipher()
				}
				if action(c, "取消", "", false, a.pending != 0).Clicked() {
					a.editor = nil
				}
				if e.uncertain && action(c, "同步核对", "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			})
			if e.fields.ID != "" && e.fields.OrganizationID == nil {
				a.organizationShareView(c, e)
				a.cipherStateButtons(c, e)
			}
		})
	})
}

const copyCipherAction vaultwarden.CipherAction = "copyDraft"

func (a *app) cipherStateButtons(c *ui.Context, e *cipherEditor) {
	if e.confirm != "" {
		text := "确认将项目移入回收站？"
		if e.confirm == vaultwarden.CipherDeletePermanently {
			text = "永久删除无法恢复。确认删除此项目及其附件？"
		}
		if e.confirm == copyCipherAction {
			text = "将当前表单复制为独立项目，原项目不变。副本保留文件夹、收藏和密码历史，恢复为未归档状态。含附件、通行密钥或尚不支持的数据时会拒绝复制。"
		}
		ui.Text(c, text).TextColor(vaultPurple)
		ui.Row(c).Gap(8).Children(func() {
			if action(c, "确认", "", true, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(e.confirm)
			}
			if action(c, "取消操作", "", false, a.pending != 0).Clicked() {
				e.confirm = ""
			}
		})
		return
	}
	ui.Row(c).Gap(8).Children(func() {
		if action(c, "复制为新项目", "", false, a.pending != 0 || e.uncertain).Clicked() {
			e.confirm = copyCipherAction
		}
		if e.fields.DeletedDate != nil {
			if action(c, "恢复", "", false, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(vaultwarden.CipherRestore)
			}
			if action(c, "永久删除", "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = vaultwarden.CipherDeletePermanently
			}
		} else {
			label, op := "归档", vaultwarden.CipherArchive
			if e.fields.ArchivedDate != nil {
				label, op = "取消归档", vaultwarden.CipherUnarchive
			}
			if action(c, label, "", false, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateCipher(op)
			}
			if action(c, "移入回收站", "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = vaultwarden.CipherTrash
			}
		}
	})
}
func (a *app) saveCipher() { a.mutateCipher("") }
func (a *app) mutateCipher(action vaultwarden.CipherAction) {
	if a.pending != 0 || a.editor == nil || a.editor.conflict || a.editor.uncertain || !a.sessionOwnsSnapshot() {
		return
	}
	if !a.editor.authorizationExpires.IsZero() && !time.Now().Before(a.editor.authorizationExpires) {
		*a.editor = cipherEditor{}
		a.editor = nil
		a.secretInputVersion++
		a.status = "项目授权已到期，请重新验证主密码。"
		return
	}
	if a.editor.revision != a.sessionRevision {
		a.status = "密码库版本已变化，已保留表单内容。请核对最新项目后重新编辑。"
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	editor := a.editor
	editor.applyInputs()
	vault := a.vault
	scope, prior := *a.liveScope, a.snapshot
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	a.status = "正在保存修改…"
	go func() {
		var reply storageReply
		var checkpointState *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpointState = reply.State
			}
			return err
		}
		current := callStorage(storageRequest{Operation: "status"})
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			switch {
			case action == shareOrganizationAction:
				_, err = session.SharePersonalCipher(ctx, vault, editor.shareOrganizationID, editor.shareCollectionID, editor.document, editor.fields, editor.authorization, persist)
			case editor.organizationID != "":
				_, err = session.CreateOrganizationCipher(ctx, vault, editor.organizationID, editor.collectionID, editor.fields, persist)
			case editor.fields.OrganizationID != nil:
				if action != "" {
					err = vaultwarden.ErrPermission
				} else {
					_, err = session.UpdateOrganizationCipher(ctx, vault, editor.document, editor.fields, editor.authorization, persist)
				}
			case action == copyCipherAction:
				_, err = session.CopyPersonalCipherAuthorized(ctx, scope, editor.document, editor.fields, editor.authorization, persist)
			case action != "":
				err = session.ChangePersonalCipherStateAuthorized(ctx, scope, editor.document, action, editor.authorization, persist)
			case editor.fields.ID == "":
				_, err = session.CreatePersonalCipher(ctx, scope, editor.fields, persist)
			default:
				_, err = session.UpdatePersonalCipherAuthorized(ctx, scope, editor.document, editor.fields, editor.authorization, persist)
			}
		}
		a.window.Update(func() { a.completeCipherMutation(epoch, editor, checkpointState, reply, err, cancel) })
	}()
}

func (a *app) completeCipherMutation(epoch uint64, editor *cipherEditor, checkpointState *snapshotStatus, reply storageReply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		// This operation has finished using its private draft. A lock/account
		// switch already detached it from the app; release its remaining secrets.
		*editor = cipherEditor{}
		return
	}
	a.cancel = nil
	if checkpointState != nil && !a.adoptSessionCheckpoint(checkpointState) {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
		return
	}
	if err != nil {
		var unknown *vaultwarden.MutationUncertainError
		editor.conflict = errors.Is(err, vaultwarden.ErrConflict)
		editor.uncertain = errors.As(err, &unknown)
		a.syncFailed(reply, err)
		return
	}
	editor.uncertain, editor.saved = true, true
	a.status = "修改已提交，正在同步核对…"
	a.syncVault(false)
}
