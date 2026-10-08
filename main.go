// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type app struct {
	category, selectedID                      string
	showSettings, showLogin                   bool
	sidebarCollapsed                          bool
	listState                                 ui.ListState
	selectedRow                               int
	window                                    *mygo.Window
	uiDispatcher                              func(func())                      // immutable after controller construction
	storageBackend                            func(storageRequest) storageReply // immutable after construction
	serverURL, email, query, status, deviceID string
	snapshot                                  *snapshotStatus
	items                                     []displayCredential
	vault                                     *vaultwarden.VaultData
	editor                                    *cipherEditor
	isolatedOrganizations                     []vaultwarden.Organization
	organizations                             []vaultwarden.Organization
	collections                               []vaultwarden.Collection
	folders                                   []vaultwarden.Folder
	organizationEditor                        *organizationEditor
	folderEditor                              *folderEditor
	bulkEditor                                *bulkEditor
	backupEditor                              *backupEditor
	itemsRevision                             string
	pending                                   int
	epoch                                     uint64
	workerEpoch                               atomic.Uint64
	componentLease                            *controllerLease
	sendPanel                                 *SendPanel
	devicePanel                               *DevicePanel
	accountForm                               *accountForm
	recoveryForm                              *accountRecoveryForm
	authManagement                            *authManagementForm
	componentCancel                           context.CancelFunc
	runtimeVault                              *runtimeVault
	diskSnapshot                              *snapshotStatus
	deviceLoginPanel                          *DeviceLoginPanel
	deviceLifecycle                           *deviceLoginLifecycle
	deviceFlow                                *vaultwarden.DeviceLogin
	runtimeExpiry                             *time.Timer
	deviceAccountID                           string
	deviceLoginSetup                          bool
	runtimeReplaceConfirmed                   bool
	switchReceipt                             *accountSwitchReceipt
	mfaLogin                                  *controllerMFA
	mfaWarnings                               mfaRecoveryWarnings
	loginSSO                                  bool
	notificationsEnabled                      bool
	notifications                             *controllerNotifications
	notificationSyncPending                   bool
	session                                   vaultSession
	sessionRevision                           string
	liveScope                                 *vaultwarden.Scope
	cancel                                    context.CancelFunc
	masterPassword, verificationCode          string
	secretInputVersion                        uint64
	showVerification                          bool
	loginChallenge                            *loginChallenge
	secretClipboardOwned                      bool
}

func (a *app) lockInterface() {
	a.stopNetwork()
	a.showLogin, a.showSettings = false, false
	a.query = ""
}

func (a *app) runStorage(operation string) {
	if runtime := a.runtimeVault; runtime != nil {
		if operation == "logout" {
			operation = "lock"
		}
		if operation == "status" {
			epoch := a.epoch + 1
			request := storageRequest{Operation: "status"}
			a.startStorage(request, func() storageReply { return runtime.call(epoch, request) })
			return
		}
		if operation == "reindex" || operation == "list" {
			a.status = "临时在线库不注册系统自动填充，也不保存离线登录；请先绑定主密码并同步。"
			return
		}
	}
	if operation == "lock" || operation == "logout" {
		a.lockInterface()
	}
	if operation == "list" {
		if a.pending != 0 {
			return
		}
		a.clearLoginInputs()
	}
	request := storageRequest{Operation: operation}
	if operation == "confirmAccountSwitch" {
		if a.switchReceipt == nil {
			a.status = "请先系统认证检查这次账号切换。"
			return
		}
		request.SwitchOperationID = a.switchReceipt.Binding.OperationID
	}
	if a.snapshot != nil {
		request.ExpectedRevision = a.snapshot.Revision
		request.Scope = a.snapshot.Scope
	}
	storage := a.storageCall
	a.startStorage(request, func() storageReply {
		if operation == "logout" {
			// An unconditional lock is the cancellation barrier for pending logins.
			locked := storage(storageRequest{Operation: "lock"})
			if locked.State != nil {
				request.ExpectedRevision = locked.State.Revision
			}
		}
		return storage(request)
	})
}

func (a *app) startStorage(request storageRequest, work func() storageReply) {
	a.advanceEpoch()
	epoch := a.epoch
	a.pending++
	if request.Operation != "status" && request.Operation != "settings" {
		a.status = "正在处理；如系统要求认证，请完成认证。"
	}
	go func() {
		reply := work()
		a.dispatchUI(func() { a.completeStorage(request, epoch, reply) })
	}()
}

func (a *app) completeStorage(request storageRequest, epoch uint64, reply storageReply) {
	defer clear(reply.Session)
	a.pending--
	if a.epoch != epoch {
		return
	}
	isUnlock := request.Operation == "list" || request.Operation == "listPassword"
	if isUnlock && reply.OK && (reply.State == nil || !reply.State.Available ||
		reply.State.Revision == "" || reply.State.Revision != request.ExpectedRevision ||
		reply.State.Scope == nil || request.Scope == nil || *reply.State.Scope != *request.Scope) {
		reply.OK, reply.Message = false, "密码库状态已变化，请重新解锁。"
	}
	if reply.State != nil {
		a.observeSnapshot(reply.State)
	}
	if reply.DeviceID != "" {
		a.deviceID = reply.DeviceID
	}
	if request.Operation == "settings" && reply.State != nil && reply.State.Scope != nil && reply.State.Scope.Server != "https://demo.invalid" {
		a.serverURL = reply.State.Scope.Server
	}
	if !reply.OK {
		a.status = reply.Message
		return
	}
	if isUnlock {
		a.items = nil
		if a.restoreUnlockedSession(reply) {
			if err := a.adoptVault(reply.Vault); err != nil {
				a.status = err.Error()
			}
		}
		a.itemsRevision = reply.State.Revision
		a.showSettings, a.showLogin = false, false
		a.startNotifications(a.window.Update, callStorage)
		return
	}
	switch request.Operation {
	case "inspectAccountSwitch":
		if reply.AccountSwitch == nil || reply.State == nil || reply.State.Scope == nil || reply.AccountSwitch.NewSnapshotID != reply.State.SnapshotID || reply.AccountSwitch.Binding.Target != *reply.State.Scope {
			a.status = vaultwarden.ErrIdentity.Error()
			return
		}
		a.switchReceipt = reply.AccountSwitch
		a.status = "已认证这次本机账号切换；请核对原账号与新账号后确认。"
	case "confirmAccountSwitch":
		if reply.AccountSwitch == nil || reply.AccountSwitch.Phase != "confirmed" || reply.AccountSwitch.Binding.OperationID != request.SwitchOperationID || reply.State == nil || reply.State.AccountSwitchPending || reply.State.Scope == nil || reply.AccountSwitch.Binding.Target != *reply.State.Scope || reply.AccountSwitch.NewSnapshotID != reply.State.SnapshotID {
			a.status = vaultwarden.ErrIdentity.Error()
			return
		}
		a.switchReceipt = nil
		if reply.Vault == nil || len(reply.Session) == 0 {
			a.status = reply.Message
			return
		}
		if a.restoreUnlockedSession(reply) {
			if err := a.adoptVault(reply.Vault); err != nil {
				a.stopNetwork()
				a.status = err.Error()
				return
			}
			a.itemsRevision = reply.State.Revision
			a.showLogin, a.showSettings = false, false
			a.startNotifications(a.dispatchUI, a.storageCall)
		}
	case "lock":
		a.status = "已锁定，请输入主密码或使用 Touch ID 解锁。"
	case "logout":
		a.status = "本机账号和快照已撤销；不会修改服务器上的密码库。"
	case "reindex":
		a.status = "候选更新已提交，请刷新状态查看系统回执。"
	default:
		a.status = reply.Message
	}
}

func main() {
	a := &app{status: "正在读取本机存储状态…", notificationsEnabled: true}
	mygo.App.WhenReady(func() {
		a.window = mygo.NewWindow(mygo.WindowOptions{Title: "MyGo Vaultwarden", Width: 1280, Height: 820, MinWidth: 1060, MinHeight: 700, StateKey: "main", TitleBarStyle: mygo.TitleBarHiddenInset, Content: ui.View(a.view)})
		a.runStorage("settings")
		mygo.Power.OnLockScreen(func() { a.window.Update(func() { a.runStorage("lock") }) })
		mygo.Power.OnSuspend(func() { a.window.Update(func() { a.runStorage("lock") }) })
	})
	mygo.App.OnWillQuit(func(_ *mygo.QuitEvent) { a.stopNetwork() })
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
