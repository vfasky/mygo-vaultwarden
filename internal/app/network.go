// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/sysauth"
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

func (a *app) observeSnapshot(state *localstore.SnapshotStatus) {
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

func (a *app) syncFailed(reply localstore.Reply, err error) {
	if reply.State != nil {
		a.observeSnapshot(reply.State)
	}
	var storageErr *localstore.Failure
	if errors.As(err, &storageErr) || errors.Is(err, vaultwarden.ErrExpired) || errors.Is(err, vaultwarden.ErrIdentity) {
		a.stopNetwork()
	}
	a.status = vaultwarden.ErrorMessage(err)
	if storageErr != nil {
		a.status = i18n.Tf("app.sync.unlock_again_hint", a.status)
	}
}

func (a *app) stopNetwork() {
	a.websiteIcons.Close()
	a.websiteIcons = nil
	a.websiteIconScope = vaultwarden.Scope{}
	a.idleLock.stop()
	a.runtimeReplaceConfirmed = false
	a.switchReceipt = nil
	// Invalidate worker leases before native cleanup or any Session close.
	a.advanceEpoch()
	a.closeDeviceLogin()
	if a.notifications != nil {
		a.notifications.close()
		a.notifications = nil
	}
	a.notificationSyncPending = false
	a.clearSecretClipboard()
	if a.runtimeVault != nil {
		a.runtimeVault.close()
		a.runtimeVault = nil
		a.snapshot, a.diskSnapshot = a.diskSnapshot, nil
	}
	if a.editor != nil {
		a.editor.shownSecret = ""
		a.editor.repromptPassword = ""
		if a.pending == 0 {
			*a.editor = cipherEditor{}
		}
	}
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
	a.syncVaultWith(login, a.dispatchUI, a.storageCall)
}

func (a *app) syncVaultWith(login bool, dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if a.pending != 0 || a.snapshot == nil {
		return
	}
	useSSO := a.loginSSO
	a.loginSSO = false
	server, email := a.serverURL, vaultcrypto.NormalizeEmail(a.email)
	var password []byte
	if login {
		canonical, err := vaultwarden.CanonicalServer(server)
		if err != nil {
			a.status = vaultwarden.ErrorMessage(err)
			return
		}
		if !strings.Contains(email, "@") || len(email) > 1024 {
			a.status = i18n.T("login.err_email_required")
			return
		}
		if len(a.masterPassword) == 0 {
			a.status = i18n.T("login.err_password_required")
			return
		}
		if len(a.masterPassword) > 8192 {
			a.clearLoginInputs()
			a.status = i18n.T("login.err_password_too_long")
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
		a.status = i18n.T("app.sync.login_required_hint")
		return
	} else if !a.sessionOwnsSnapshot() {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
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
	a.advanceEpoch()
	epoch := a.epoch
	storage = a.routeStorage(storage, epoch)
	runtime := a.runtimeVault
	var ctx context.Context
	var cancel context.CancelFunc
	if login {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	a.cancel = cancel
	a.pending++
	a.status = i18n.T("login.status_syncing")
	if !login {
		a.status = i18n.T("app.sync.status_syncing")
	}
	// Capture on the UI thread; only the successful authenticated publication
	// below may consume this continuation. Status observations cannot mint one.
	backupContinuation := a.captureBackupContinuation(epoch)
	platform := sysauth.NewAuthenticationPlatform(a.mainWindow)
	go func() {
		defer clear(password)
		var session vaultSession = existing
		var result vaultwarden.SyncResult
		var metadata []localstore.DisplayCredential
		var reply localstore.Reply
		var workErr error
		var checkpointState *localstore.SnapshotStatus
		if login {
			// Revoke the previous account before prompting, including offline copies.
			reply = storage(localstore.Request{Operation: localstore.OperationLogout, ExpectedRevision: expected})
			if !reply.OK || reply.State == nil {
				workErr = reply.Failure()
				if reply.OK {
					workErr = (localstore.Reply{Code: "invalid_reply", Message: i18n.T("app.sync.err_revocation_unconfirmed")}).Failure()
				}
			} else {
				expected = reply.State.Revision
			}
			if workErr == nil && ctx.Err() == nil {
				client, err := vaultwarden.NewClient(server, deviceID)
				if err != nil {
					workErr = err
				} else {
					prompt := func(promptCtx context.Context, challenge vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error) {
						return a.requestMFA(promptCtx, server, email, epoch, challenge, dispatch, platform.MFA(server, epoch))
					}
					if useSSO {
						raw, err := platform.SSO(ctx, client, epoch, prompt)
						workErr = err
						if err == nil {
							var unlocked *vaultwarden.Session
							unlocked, workErr = client.UnlockSSOVault(ctx, raw, email, password)
							if workErr == nil {
								session = unlocked
							}
						}
						clear(raw)
					} else {
						loggedIn, loginErr := client.LoginMFA(ctx, email, password, "", prompt)
						workErr = loginErr
						loggedIn.RememberToken = ""
						if loggedIn.RemovedAllMFA {
							a.mfaWarnings.record(server, email, true)
						}
						if workErr == nil {
							session = loggedIn.Session
						}
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
					reply, err = localstore.SaveSessionCheckpoint(prior, checkpoint, storage)
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
			metadata = make([]localstore.DisplayCredential, 0, len(result.Credentials))
			for _, item := range result.Credentials {
				metadata = append(metadata, localstore.DisplayCredential{ID: item.ID, Title: item.Title, Username: item.Username, URL: item.URL})
			}
			reply = storage(localstore.Request{Operation: localstore.OperationPublishVault, ExpectedRevision: expected, Scope: &result.Scope, Credentials: result.Credentials, PasswordUnlock: result.PasswordUnlock, Session: result.Session, Vault: result.Vault})
			if reply.OK && reply.Vault != nil {
				result.Vault = reply.Vault
			}
			if !login && !reply.Vault.PreservesPendingPolicies(priorVault) {
				reply.OK, reply.Code, reply.Message = false, "invalid_reply", i18n.T("app.sync.err_policy_unconfirmed")
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
					reply.OK, reply.Code, reply.Message = false, "invalid_reply", i18n.T("app.sync.err_quarantine_unconfirmed")
				}
			}
			if !reply.OK {
				workErr = reply.Failure()
			} else if reply.Vault == nil || reply.State == nil || !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != result.Scope || reply.State.SnapshotID == "" || reply.State.Revision == "" || reply.State.Revision == expected {
				workErr = (localstore.Reply{Code: "invalid_reply", Message: i18n.T("app.sync.err_revision_unconfirmed")}).Failure()
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
			reply = storage(localstore.Request{Operation: localstore.OperationLogout, ExpectedRevision: expected})
			if session != nil {
				session.Close()
			}
		}
		if workErr == nil && ctx.Err() != nil {
			workErr = vaultwarden.ErrCancelled
		}
		dispatch(func() {
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
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if workErr != nil {
				if login && session != nil {
					go session.Close()
				}
				a.syncFailed(reply, workErr)
				if timedOut {
					a.status = i18n.T("login.err_timeout")
				}
				return
			}
			if !backupContinuation.current(a) {
				backupContinuation = nil
			}
			if concrete, ok := session.(*vaultwarden.Session); ok && runtime == nil {
				if err := concrete.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); err != nil {
					if login {
						go session.Close()
					}
					a.stopNetwork()
					a.status = vaultwarden.ErrorMessage(err)
					return
				}
			}
			a.snapshot = reply.State
			a.session = session
			a.liveScope = &result.Scope
			a.sessionRevision = reply.State.Revision
			a.items = metadata
			if err := a.adoptVault(result.Vault); err != nil {
				a.status = vaultwarden.ErrorMessage(err)
				return
			}
			if a.folderEditor != nil && a.folderEditor.saved {
				a.folderEditor = nil
			}
			if a.editor != nil && a.editor.saved {
				a.editor = nil
			}
			a.itemsRevision = a.snapshot.Revision
			a.showLogin = false
			s := result.Summary
			a.status = syncSummaryText(len(a.items), s)
			a.syncSummary = &syncSummaryStatus{count: len(a.items), summary: s, text: a.status}
			a.reconcileBulk()
			a.reconcileImport(backupContinuation)
			a.startNotifications(dispatch, storage)
			if a.notificationSyncPending {
				a.notificationSyncPending = false
				a.syncVaultWith(false, dispatch, storage)
			}
		})
	}()
}

// syncSummaryStatus remembers the numbers behind the status line a sync left,
// so a change of language words it again instead of leaving the old language.
type syncSummaryStatus struct {
	count   int
	summary vaultwarden.Summary
	text    string
}

func syncSummaryText(count int, s vaultwarden.Summary) string {
	return i18n.Tf("app.sync.summary", count, s.Logins, s.Organizations, s.OtherTypes, s.Reprompt, s.Archived, s.Restricted, s.UnsupportedURIs)
}

// retranslateStatus rewords the sync summary in the language now in force and
// drops any other status line, which was worded in the previous language.
func (a *app) retranslateStatus() {
	if a.status == "" {
		return
	}
	if sum := a.syncSummary; sum != nil && a.status == sum.text {
		sum.text = syncSummaryText(sum.count, sum.summary)
		a.status = sum.text
		return
	}
	a.status = ""
	a.syncSummary = nil
}
