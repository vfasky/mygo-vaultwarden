// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type app struct {
	category, selectedID                      string
	showSettings                              bool
	listState                                 ui.ListState
	selectedRow                               int
	credential                                demoCredential
	server                                    demoServer
	window                                    *mygo.Window
	serverURL, email, query, status, deviceID string
	snapshot                                  *snapshotStatus
	items                                     []displayCredential
	itemsRevision                             string
	pending                                   int
	epoch                                     uint64
	session                                   vaultSession
	sessionRevision                           string
	liveScope                                 *vaultwarden.Scope
	cancel                                    context.CancelFunc
}

func (a *app) runStorage(operation string) {
	if operation == "lock" || operation == "logout" {
		a.stopNetwork()
	}
	request := storageRequest{Operation: operation}
	if a.snapshot != nil {
		request.ExpectedRevision = a.snapshot.Revision
	}
	a.epoch++
	epoch := a.epoch
	a.pending++
	if operation != "status" && operation != "settings" {
		a.status = "正在处理；如系统要求认证，请完成认证。"
	}
	go func() {
		if operation == "logout" {
			// An unconditional lock is the cancellation barrier for pending logins.
			locked := callStorage(storageRequest{Operation: "lock"})
			if locked.State != nil {
				request.ExpectedRevision = locked.State.Revision
			}
		}
		reply := callStorage(request)
		a.window.Update(func() {
			a.pending--
			if a.epoch != epoch {
				return
			}
			a.observeSnapshot(reply.State)
			if reply.DeviceID != "" {
				a.deviceID = reply.DeviceID
			}
			if operation == "settings" && reply.State != nil && reply.State.Scope != nil && reply.State.Scope.Server != "https://demo.invalid" {
				a.serverURL = reply.State.Scope.Server
			}
			if !reply.OK {
				a.status = reply.Message
				return
			}
			if operation == "list" {
				a.items = reply.Items
				a.itemsRevision = reply.State.Revision
				a.showSettings = false
			}
			switch operation {
			case "lock":
				a.status = "已锁定。在线会话已清除；离线快照可通过系统认证重新解锁。"
			case "logout":
				a.status = "本机账号和快照已撤销；不会修改服务器上的密码库。"
			case "list":
				a.status = "离线快照已解锁。"
				if reply.Truncated {
					a.status += "当前显示前 200 条；系统填充使用完整快照。"
				}
			case "reindex":
				a.status = "候选更新已提交，请刷新状态查看系统回执。"
			default:
				a.status = reply.Message
			}
		})
	}()
}

func (a *app) openDemo() {
	if err := a.server.start(); err != nil {
		a.status = err.Error()
		return
	}
	go func() { _ = exec.Command("/usr/bin/open", "-b", "com.apple.Safari", a.credential.URL).Run() }()
}

func storageDiagnostic(credential demoCredential) bool {
	if len(os.Args) != 3 || os.Args[1] != "--storage-action" {
		return false
	}
	operation := os.Args[2]
	allowed := map[string]bool{"status": true, "publish": true, "lock": true, "logout": true, "retryCleanup": true, "verify": true, "verifyWithoutUI": true, "reindex": true, "delete": true}
	if !allowed[operation] {
		_ = json.NewEncoder(os.Stdout).Encode(storageReply{Code: "invalid_input", Message: "未知诊断操作。"})
		os.Exit(1)
	}
	request := storageRequest{Operation: operation}
	if operation == "publish" || operation == "logout" || operation == "delete" {
		status := callStorage(storageRequest{Operation: "status"})
		if !status.OK || status.State == nil {
			_ = json.NewEncoder(os.Stdout).Encode(status)
			os.Exit(1)
		}
		// Diagnostics must not overwrite/remove a real account's snapshot.
		if status.State.Scope != nil && status.State.Scope.Account != "public-demo-account" && operation != "logout" {
			_ = json.NewEncoder(os.Stdout).Encode(storageReply{Code: "wrong_scope", Message: "真实密码库不能由演示诊断覆盖。"})
			os.Exit(1)
		}
		request.ExpectedRevision = status.State.Revision
	}
	if operation == "publish" {
		request.Credentials = []demoCredential{credential}
	}
	if operation == "delete" {
		request.CredentialID = credential.ID
	}
	reply := callStorage(request)
	_ = json.NewEncoder(os.Stdout).Encode(reply)
	if !reply.OK {
		os.Exit(1)
	}
	return true
}

func main() {
	credential, err := loadDemoCredential()
	if err != nil {
		log.Fatal(err)
	}
	if storageDiagnostic(credential) {
		return
	}
	a := &app{credential: credential, status: "正在读取本机存储状态…"}
	defer a.server.close()
	mygo.App.WhenReady(func() {
		a.window = mygo.NewWindow(mygo.WindowOptions{Title: "MyGo Vaultwarden", Width: 1280, Height: 820, MinWidth: 1060, MinHeight: 700, StateKey: "main", Content: ui.View(a.view)})
		a.runStorage("settings")
		mygo.Power.OnLockScreen(func() { a.window.Update(func() { a.runStorage("lock") }) })
		mygo.Power.OnSuspend(func() { a.window.Update(func() { a.runStorage("lock") }) })
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
