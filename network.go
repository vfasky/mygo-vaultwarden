// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type vaultSession interface {
	SyncWithCheckpoint(context.Context, func(vaultwarden.SessionCheckpoint) error) (vaultwarden.SyncResult, error)
	Close()
}

// Only this session's successful publication/checkpoint or a fresh authenticated
// unlock grants a CAS revision. Reading status never renews write authority.
func (a *app) sessionOwnsSnapshot() bool {
	return a.session != nil && a.sessionRevision != "" && a.snapshot != nil &&
		a.snapshot.Available && a.snapshot.Revision == a.sessionRevision &&
		a.liveScope != nil && a.snapshot.Scope != nil && *a.liveScope == *a.snapshot.Scope
}

func (a *app) observeSnapshot(state *snapshotStatus) {
	a.snapshot = state
	if state == nil || state.Revision != a.itemsRevision {
		if a.editor != nil {
			a.editor.shownSecret = ""
			a.editor.repromptPassword = ""
			if a.pending == 0 {
				*a.editor = cipherEditor{}
			}
		}
		a.items = nil
		a.vault, a.editor = nil, nil
		a.organizations, a.collections, a.isolatedOrganizations = nil, nil, nil
		a.clearOrganizationEditor()
		a.folders, a.folderEditor = nil, nil
		a.bulkEditor = nil
		a.clearBackupEditor()
		a.itemsRevision = ""
		a.selectedID = ""
	}
	if a.session != nil && !a.sessionOwnsSnapshot() {
		a.stopNetwork()
	}
}

func (a *app) syncFailed(reply storageReply, err error) {
	if reply.State != nil {
		a.observeSnapshot(reply.State)
	}
	var storageErr *storageFailure
	if errors.As(err, &storageErr) || errors.Is(err, vaultwarden.ErrExpired) || errors.Is(err, vaultwarden.ErrIdentity) {
		a.stopNetwork()
	}
	a.status = err.Error()
	if storageErr != nil {
		a.status += " 请重新解锁后再同步。"
	}
}

func (a *app) stopNetwork() {
	a.clearSecretClipboard()
	if a.editor != nil {
		a.editor.shownSecret = ""
		a.editor.repromptPassword = ""
		if a.pending == 0 {
			*a.editor = cipherEditor{}
		}
	}
	// Invalidate every pending callback, including writes whose server response
	// arrives after an observed external lock or account switch.
	a.epoch++
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.resetLoginForm()
	if a.session != nil {
		session := a.session
		a.session = nil
		go session.Close()
	}
	a.liveScope = nil
	a.sessionRevision = ""
	a.items = nil
	a.vault, a.editor = nil, nil
	a.organizations, a.collections, a.isolatedOrganizations = nil, nil, nil
	a.clearOrganizationEditor()
	a.folders, a.folderEditor = nil, nil
	a.itemsRevision = ""
	a.selectedID = ""
	a.bulkEditor = nil
	a.clearBackupEditor()
}

func (a *app) syncVault(login bool) {
	if a.pending != 0 || a.snapshot == nil {
		return
	}
	server, email := a.serverURL, vaultwarden.NormalizeEmail(a.email)
	var password []byte
	if login {
		canonical, err := vaultwarden.CanonicalServer(server)
		if err != nil {
			a.status = err.Error()
			return
		}
		if !strings.Contains(email, "@") || len(email) > 1024 {
			a.status = "请输入登录邮箱。"
			return
		}
		if len(a.masterPassword) == 0 {
			a.status = "请输入主密码。"
			return
		}
		if len(a.masterPassword) > 8192 {
			a.clearLoginInputs()
			a.status = "主密码过长，请检查输入。"
			return
		}
		password = []byte(a.masterPassword)
		server = canonical
		a.showLogin = true
		a.stopNetwork()
	} else if a.session == nil {
		if a.unlocked() {
			a.openUnlockLogin()
		}
		a.status = "请重新登录一次以安全保存登录凭据，之后解锁即可同步。"
		return
	} else if !a.sessionOwnsSnapshot() {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
		return
	}
	existing := a.session
	initialSnapshot := a.snapshot
	priorVault := a.vault
	var isolatedIDs []string
	if a.vault != nil {
		isolatedIDs = append(isolatedIDs, a.vault.QuarantinedOrganizations...)
	}
	deviceID := a.deviceID
	expected := a.snapshot.Revision
	if !login {
		expected = a.sessionRevision
	}
	a.epoch++
	epoch := a.epoch
	var ctx context.Context
	var cancel context.CancelFunc
	if login {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	a.cancel = cancel
	a.pending++
	a.status = "正在登录并同步…"
	if !login {
		a.status = "正在同步密码库…"
	}
	go func() {
		defer clear(password)
		var session vaultSession = existing
		var result vaultwarden.SyncResult
		var metadata []displayCredential
		var reply storageReply
		var workErr error
		var checkpointState *snapshotStatus
		if login {
			// Revoke the previous account before prompting, including offline copies.
			reply = callStorage(storageRequest{Operation: "logout", ExpectedRevision: expected})
			if !reply.OK || reply.State == nil {
				workErr = reply.failure()
				if reply.OK {
					workErr = (storageReply{Code: "invalid_reply", Message: "未能确认本机账号撤销结果。"}).failure()
				}
			} else {
				expected = reply.State.Revision
			}
			if workErr == nil && ctx.Err() == nil {
				client, err := vaultwarden.NewClient(server, deviceID)
				if err != nil {
					workErr = err
				} else {
					attempt := 0
					var loggedIn *vaultwarden.Session
					loggedIn, workErr = client.Login(ctx, email, password, func() ([]byte, error) {
						// Login has already derived the keys and authorization hash.
						// The raw master password is unnecessary while waiting for MFA.
						clear(password)
						attempt++
						return a.requestLoginCode(ctx, epoch, attempt, a.window.Update)
					})
					if workErr == nil {
						session = loggedIn
					}
				}
				clear(password)
			}
		}
		if workErr == nil && ctx.Err() != nil {
			workErr = vaultwarden.ErrCancelled
		}
		if workErr == nil {
			var persist func(vaultwarden.SessionCheckpoint) error
			if !login {
				prior := initialSnapshot
				persist = func(checkpoint vaultwarden.SessionCheckpoint) error {
					var err error
					reply, err = saveSessionCheckpoint(prior, checkpoint, callStorage)
					if err == nil {
						checkpointState, prior = reply.State, reply.State
						expected = reply.State.Revision
					}
					return err
				}
			}
			result, workErr = session.SyncWithCheckpoint(ctx, persist)
		}
		if workErr == nil && ctx.Err() == nil {
			metadata = make([]displayCredential, 0, len(result.Credentials))
			for _, item := range result.Credentials {
				metadata = append(metadata, displayCredential{ID: item.ID, Title: item.Title, Username: item.Username, URL: item.URL})
			}
			reply = callStorage(storageRequest{Operation: "publishVault", ExpectedRevision: expected, Scope: &result.Scope, Credentials: result.Credentials, PasswordUnlock: result.PasswordUnlock, Session: result.Session, Vault: result.Vault})
			if reply.OK && reply.Vault != nil {
				result.Vault = reply.Vault
			}
			if !login && !reply.Vault.PreservesPendingPolicies(priorVault) {
				reply.OK, reply.Code, reply.Message = false, "invalid_reply", "未能确认策略待核验状态，请重新解锁。"
			}
			for _, isolatedID := range isolatedIDs {
				found := false
				if reply.Vault != nil {
					for _, id := range reply.Vault.QuarantinedOrganizations {
						if id == isolatedID {
							found = true
						}
					}
				}
				if !found {
					reply.OK, reply.Code, reply.Message = false, "invalid_reply", "未能确认组织隔离状态，请重新解锁核对。"
				}
			}
			if !reply.OK {
				workErr = reply.failure()
			} else if reply.Vault == nil || reply.State == nil || !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != result.Scope || reply.State.SnapshotID == "" || reply.State.Revision == "" || reply.State.Revision == expected {
				workErr = (storageReply{Code: "invalid_reply", Message: "未能确认本次快照的发布版本。"}).failure()
			}
		}
		// No password-bearing results live in the UI model.
		clear(result.Session)
		result.Session = nil
		if result.PasswordUnlock != nil {
			clear(result.PasswordUnlock.Key)
			result.PasswordUnlock = nil
		}
		for i := range result.Credentials {
			result.Credentials[i].Password = ""
		}
		result.Credentials = nil
		if errors.Is(workErr, vaultwarden.ErrExpired) || errors.Is(workErr, vaultwarden.ErrIdentity) {
			reply = callStorage(storageRequest{Operation: "logout", ExpectedRevision: expected})
			if session != nil {
				session.Close()
			}
		}
		if workErr == nil && ctx.Err() != nil {
			workErr = vaultwarden.ErrCancelled
		}
		a.window.Update(func() {
			a.pending--
			if a.epoch != epoch {
				if login && session != nil {
					go session.Close()
				}
				return
			}
			a.cancel = nil
			timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
			cancel()
			if login {
				a.resetLoginForm()
			}
			if checkpointState != nil && !a.adoptSessionCheckpoint(checkpointState) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if workErr != nil {
				if login && session != nil {
					go session.Close()
				}
				a.syncFailed(reply, workErr)
				if timedOut {
					a.status = "登录已超时，请重新输入主密码。"
				}
				return
			}
			if concrete, ok := session.(*vaultwarden.Session); ok {
				if err := concrete.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); err != nil {
					if login {
						go session.Close()
					}
					a.stopNetwork()
					a.status = err.Error()
					return
				}
			}
			a.snapshot = reply.State
			a.session = session
			a.liveScope = &result.Scope
			a.sessionRevision = reply.State.Revision
			a.items = metadata
			if err := a.adoptVault(result.Vault); err != nil {
				a.status = err.Error()
				return
			}
			if a.folderEditor != nil && a.folderEditor.saved {
				a.folderEditor = nil
			}
			if a.editor != nil && a.editor.saved {
				a.editor = nil
			}
			a.itemsRevision = a.snapshot.Revision
			a.showSettings, a.showLogin = false, false
			s := result.Summary
			a.status = fmt.Sprintf("已同步 %d 个项目；可填充登录 %d。填充排除：未授权组织 %d、其他类型 %d、再次验证 %d、归档 %d、权限受限 %d；不支持的网址规则 %d。", len(a.items), s.Logins, s.Organizations, s.OtherTypes, s.Reprompt, s.Archived, s.Restricted, s.UnsupportedURIs)
			a.reconcileBulk()
			a.reconcileImport()
		})
	}()
}
