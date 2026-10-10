// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"log"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type app struct {
	category, selectedID                      string
	showLogin                                 bool
	sidebarCollapsed                          bool
	listState                                 ui.ListState
	selectedRow                               int
	windows                                   windowSet // which windows are open and their native handles (windows.go)
	mainWindow                                *mygo.Window
	uiDispatcher                              func(func())                              // immutable after controller construction
	storageBackend                            func(localstore.Request) localstore.Reply // immutable after construction
	serverURL, email, query, status, deviceID string
	snapshot                                  *localstore.SnapshotStatus
	items                                     []localstore.DisplayCredential
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
	sendPanel                                 *send.Panel
	devicePanel                               *account.DevicePanel
	orgServices                               *orgServicesController
	targetRecovery                            *targetRecoveryController
	accountForm                               *account.Form
	recoveryForm                              *accountRecoveryForm
	authManagement                            *account.AuthManagementForm
	componentCancel                           context.CancelFunc
	runtimeVault                              *runtimeVault
	diskSnapshot                              *localstore.SnapshotStatus
	deviceLoginPanel                          *account.DeviceLoginPanel
	deviceLifecycle                           *deviceLoginLifecycle
	deviceFlow                                *vaultwarden.DeviceLogin
	runtimeExpiry                             *time.Timer
	deviceAccountID                           string
	deviceLoginSetup                          bool
	runtimeReplaceConfirmed                   bool
	switchReceipt                             *localstore.AccountSwitchReceipt
	mfaLogin                                  *controllerMFA
	mfaWarnings                               mfaRecoveryWarnings
	targetOutcomeWarnings                     map[vaultwarden.Scope]string
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
	a.showLogin = false
	a.query = ""
}

func (a *app) runStorage(operation string) {
	if runtime := a.runtimeVault; runtime != nil {
		if operation == "logout" {
			operation = "lock"
		}
		if operation == "status" {
			epoch := a.epoch + 1
			request := localstore.Request{Operation: "status"}
			a.startStorage(request, func() localstore.Reply { return runtime.call(epoch, request) })
			return
		}
		if operation == "reindex" || operation == "list" {
			a.status = i18n.T("app.sync.runtime_bind_password_hint")
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
	request := localstore.Request{Operation: operation}
	if operation == "confirmAccountSwitch" {
		if a.switchReceipt == nil {
			a.status = i18n.T("login.account_switch.authentication_required_hint")
			return
		}
		request.SwitchOperationID = a.switchReceipt.Binding.OperationID
	}
	if a.snapshot != nil {
		request.ExpectedRevision = a.snapshot.Revision
		request.Scope = a.snapshot.Scope
	}
	storage := a.storageCall
	a.startStorage(request, func() localstore.Reply {
		if operation == "logout" {
			// An unconditional lock is the cancellation barrier for pending logins.
			locked := storage(localstore.Request{Operation: "lock"})
			if locked.State != nil {
				request.ExpectedRevision = locked.State.Revision
			}
		}
		return storage(request)
	})
}

func (a *app) startStorage(request localstore.Request, work func() localstore.Reply) {
	a.advanceEpoch()
	epoch := a.epoch
	a.pending++
	if request.Operation != "status" && request.Operation != "settings" {
		a.status = i18n.T("app.sync.status_authenticating")
	}
	go func() {
		reply := work()
		a.dispatchUI(func() { a.completeStorage(request, epoch, reply) })
	}()
}

func (a *app) completeStorage(request localstore.Request, epoch uint64, reply localstore.Reply) {
	defer clear(reply.Session)
	a.pending--
	if a.epoch != epoch {
		return
	}
	isUnlock := request.Operation == "list" || request.Operation == "listPassword"
	if isUnlock && reply.OK && (reply.State == nil || !reply.State.Available ||
		reply.State.Revision == "" || reply.State.Revision != request.ExpectedRevision ||
		reply.State.Scope == nil || request.Scope == nil || *reply.State.Scope != *request.Scope) {
		reply.OK, reply.Message = false, i18n.T("app.sync.err_vault_changed")
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
		a.showLogin = false
		a.startNotifications(a.postUI, localstore.Call)
		return
	}
	switch request.Operation {
	case "inspectAccountSwitch":
		if reply.AccountSwitch == nil || reply.State == nil || reply.State.Scope == nil || reply.AccountSwitch.NewSnapshotID != reply.State.SnapshotID || reply.AccountSwitch.Binding.Target != *reply.State.Scope {
			a.status = vaultwarden.ErrIdentity.Error()
			return
		}
		a.switchReceipt = reply.AccountSwitch
		a.status = i18n.T("login.account_switch.status_authenticated")
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
			a.showLogin = false
			a.startNotifications(a.dispatchUI, a.storageCall)
		}
	case "lock":
		a.status = i18n.T("login.unlock.status_locked")
	case "logout":
		a.status = i18n.T("app.settings.status_account_revoked")
	case "reindex":
		a.status = i18n.T("app.settings.status_autofill_submitted")
	default:
		a.status = reply.Message
	}
}

// Run starts the MyGo Vaultwarden application and blocks until it quits.
func Run() {
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}
	a := &app{status: i18n.T("app.sync.status_reading_storage"), notificationsEnabled: true}
	useUpdater(func() { a.invalidateWindows(nil) })
	mygo.App.WhenReady(func() {
		a.windows.native = true
		a.openMainWindow()
		mygo.App.SetMenu(a.menu())
		a.runStorage("settings")
		mygo.Power.OnLockScreen(func() { a.postUI(func() { a.runStorage("lock") }) })
		mygo.Power.OnSuspend(func() { a.postUI(func() { a.runStorage("lock") }) })
	})
	mygo.App.OnSecondInstance(func(_ []string, _ string) { a.showMainWindow() })
	mygo.App.OnBeforeQuit(func(_ *mygo.QuitEvent) { a.windows.quitting = true })
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if !hasVisibleWindows && !a.windows.quitting {
			a.showMainWindow()
		}
	})
	mygo.App.OnWillQuit(func(_ *mygo.QuitEvent) { a.stopNetwork() })
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
