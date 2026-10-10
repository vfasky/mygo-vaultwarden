// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/sysauth"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type targetRecoveryWorkspace struct {
	session    *vaultwarden.Session
	inspection *vaultwarden.TargetRecoveryInspection
	once       sync.Once
}

func (w *targetRecoveryWorkspace) close() {
	if w != nil {
		w.once.Do(func() { w.session.Close(); w.inspection.Close() })
	}
}

type targetRecoveryController struct {
	owner                           *app // UI thread only
	epoch                           uint64
	generation                      uint64
	server, email, password, status string
	source                          *localstore.SnapshotStatus
	records                         []localstore.TargetRecoveryRecord
	workspace                       *targetRecoveryWorkspace
	replaceForeign, running, closed bool
	ctx                             context.Context
	cancel                          context.CancelFunc
	dispatch                        func(func())
	storage                         func(localstore.Request) localstore.Reply
}

func (p *targetRecoveryController) Close() {
	p.closed = true
	p.generation++
	p.password = ""
	if p.cancel != nil {
		p.cancel()
	}
	if !p.running && p.workspace != nil {
		go p.workspace.close()
		p.workspace = nil
	}
	for i := range p.records {
		p.records[i].Close()
	}
	p.records = nil
}
func targetStorageEvidence(e vaultwarden.TargetRecoveryEvidence) localstore.TargetRecoveryVerification {
	return localstore.TargetRecoveryVerification{Kind: e.Kind, AuthorityHash: e.AuthorityHash, KeyHash: e.KeyHash, MembershipHash: e.MembershipHash, MFAHash: e.MFAHash, ConfirmationHash: e.ConfirmationHash, AuthenticationEpoch: e.AuthenticationEpoch}
}
func targetDiscoveryAdapter(ctx context.Context, workspace *targetRecoveryWorkspace, state *localstore.SnapshotStatus, epoch uint64, current func() uint64, storage func(localstore.Request) localstore.Reply) (*localstore.TargetRecoveryStorage, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	evidence, err := workspace.session.TargetRecoveryDiscoveryEvidence(workspace.inspection, hex.EncodeToString(nonce[:]))
	if err != nil {
		return nil, err
	}
	return localstore.NewTargetRecoveryLoginStorage(state, epoch, func() uint64 {
		if ctx.Err() != nil {
			return 0
		}
		return current()
	}, workspace.inspection.Fresh, targetStorageEvidence(evidence), storage)
}
func (a *app) openTargetRecovery() { a.openTargetRecoveryWith(a.dispatchUI, a.storageCall) }
func (a *app) openTargetRecoveryWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if a.pending != 0 {
		return
	}
	server, email := a.serverURL, a.email
	a.stopNetwork()
	a.showLogin = true
	a.targetRecovery = &targetRecoveryController{owner: a, epoch: a.epoch, server: server, email: email, source: a.snapshot, dispatch: dispatch, storage: storage}
}
func (p *targetRecoveryController) inspect() {
	if p.running || p.closed || p.password == "" {
		return
	}
	server, err := vaultwarden.CanonicalServer(p.server)
	if err != nil {
		p.status = vaultwarden.ErrorMessage(err)
		return
	}
	email, password := vaultcrypto.NormalizeEmail(p.email), []byte(p.password)
	p.password = ""
	p.generation++
	if !strings.Contains(email, "@") {
		clear(password)
		p.status = i18n.T("crossaccount.recovery.err_email_required")
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	if p.workspace != nil {
		go p.workspace.close()
		p.workspace = nil
	}
	p.ctx, p.cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	ctx, epoch, generation := p.ctx, p.epoch, p.generation
	a := p.owner
	device := a.deviceID
	platform := sysauth.NewAuthenticationPlatform(a.window)
	clock := &a.workerEpoch
	p.running = true
	a.pending++
	go func() {
		defer clear(password)
		var workspace *targetRecoveryWorkspace
		var reply localstore.Reply
		client, err := vaultwarden.NewClient(server, device)
		if err == nil {
			result, e := client.LoginMFA(ctx, email, password, "", func(promptCtx context.Context, challenge vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error) {
				return a.requestMFA(promptCtx, server, email, epoch, challenge, p.dispatch, platform.MFA(server, epoch))
			})
			err = e
			result.RememberToken = ""
			if result.RemovedAllMFA {
				a.mfaWarnings.record(server, email, true)
			}
			if result.Session != nil {
				workspace = &targetRecoveryWorkspace{session: result.Session}
			}
		}
		clear(password)
		if err == nil {
			workspace.inspection, err = workspace.session.InspectFreshTargetRecovery(ctx)
		}
		if err == nil {
			reply = p.storage(localstore.Request{Operation: localstore.OperationStatus})
			if !reply.OK || reply.State == nil {
				err = reply.Failure()
			}
		}
		if err == nil {
			var adapter *localstore.TargetRecoveryStorage
			adapter, err = targetDiscoveryAdapter(ctx, workspace, reply.State, epoch, clock.Load, p.storage)
			if err == nil {
				reply, err = adapter.Pending()
				adapter.Close()
			}
		}
		p.dispatch(func() {
			a.pending--
			p.running = false
			if p.closed || a.targetRecovery != p || a.epoch != epoch || p.generation != generation || ctx.Err() != nil {
				if workspace != nil {
					go workspace.close()
				}
				for i := range reply.TargetRecords {
					reply.TargetRecords[i].Close()
				}
				return
			}
			if err != nil {
				if workspace != nil {
					go workspace.close()
				}
				p.status = i18n.Tf("crossaccount.recovery.err_inspection_failed", vaultwarden.ErrorMessage(err))
				return
			}
			p.workspace = workspace
			p.source = reply.State
			a.snapshot = reply.State
			for i := range p.records {
				p.records[i].Close()
			}
			p.records = reply.TargetRecords
			p.server, p.email = server, email
			p.status = i18n.T("crossaccount.recovery.status_inspected")
		})
	}()
}
func targetAllVerified(records []localstore.TargetRecoveryRecord, fresh vaultwarden.SyncResult) bool {
	found := false
	for _, record := range records {
		if record.RequireTargetLogin && record.Binding.Target == fresh.Scope && record.Phase != "resolved" {
			found = true
			if record.Phase != "verified" || record.VerifiedVaultHash != localstore.TargetRecoveryHash(fresh.Vault.Sync) || record.VerifiedSessionHash != localstore.TargetRecoveryHash(fresh.Session) || record.VerifiedUnlockHash != localstore.TargetRecoveryHash(fresh.PasswordUnlock.Key) {
				return false
			}
		}
	}
	return found
}
func (p *targetRecoveryController) verify(index int) {
	if p.running || p.closed || p.workspace == nil || index < 0 || index >= len(p.records) {
		return
	}
	record := p.records[index]
	record.Summary = append([]byte(nil), record.Summary...)
	if !record.RequireTargetLogin || record.Binding.Target != p.workspace.inspection.Fresh.Scope || record.Phase == "resolved" {
		record.Close()
		return
	}
	workspace, source, ctx, epoch, generation, replace := p.workspace, p.source, p.ctx, p.epoch, p.generation, p.replaceForeign
	a := p.owner
	clock := &a.workerEpoch
	p.running = true
	a.pending++
	go func() {
		defer record.Close()
		var reply localstore.Reply
		var notes []string
		adopted := false
		adapter, err := targetDiscoveryAdapter(ctx, workspace, source, epoch, clock.Load, p.storage)
		if adapter != nil {
			defer adapter.Close()
		}
		if err == nil {
			err = adapter.Select(record)
		}
		if err == nil {
			reply, err = adapter.Query()
		}
		var evidence vaultwarden.TargetRecoveryEvidence
		if err == nil {
			if len(reply.TargetRecords) != 1 {
				err = localstore.ErrTargetRecovery
			} else {
				current := reply.TargetRecords[0]
				var description vaultwarden.RecoveryDispatch
				description, err = vaultwarden.DecodeRecoveryDispatch(current.Summary)
				if err == nil {
					evidence, err = workspace.session.VerifyTargetRecovery(workspace.inspection, description, current.OriginalResult, current.Binding.SummaryHash, description.OperationID)
				}
			}
		}
		if err == nil {
			notes = evidence.Notes
			reply, err = adapter.StageVerified(workspace.inspection.Fresh, targetStorageEvidence(evidence))
		}
		if err == nil {
			reply, err = adapter.Pending()
		}
		if err == nil && targetAllVerified(reply.TargetRecords, workspace.inspection.Fresh) {
			fresh := workspace.inspection.Fresh
			switch {
			case reply.State.Scope != nil && *reply.State.Scope != fresh.Scope:
				if replace {
					var binding localstore.AccountSwitchBinding
					binding, err = localstore.NewAccountSwitchBinding(reply.State, fresh.Scope)
					if err == nil {
						reply, err = localstore.PublishBoundAccount(ctx, reply.State, fresh, binding, p.storage)
						adopted = err == nil
					}
				} else {
					notes = append(notes, i18n.T("crossaccount.recovery.status_replace_confirmation_required"))
				}
			case reply.State.Scope != nil:
				reply, err = adapter.ResolveVerifiedWithLocalAuthentication(fresh, targetStorageEvidence(evidence))
				adopted = err == nil
			default:
				reply, err = adapter.ResolveVerified(fresh, targetStorageEvidence(evidence))
				adopted = err == nil
			}
		} else if err == nil {
			notes = append(notes, i18n.T("crossaccount.recovery.status_partially_verified"))
		}
		if err != nil {
			status := p.storage(localstore.Request{Operation: localstore.OperationStatus})
			if status.OK {
				reply.State = status.State
			}
		}
		p.dispatch(func() {
			a.pending--
			p.running = false
			if p.closed || a.targetRecovery != p || a.epoch != epoch || p.generation != generation || ctx.Err() != nil {
				go workspace.close()
				return
			}
			if reply.State != nil {
				p.source = reply.State
				a.snapshot = reply.State
			}
			if err != nil {
				p.status = i18n.Tf("crossaccount.recovery.err_barrier_retained", vaultwarden.ErrorMessage(err))
				if reply.State != nil && reply.State.AccountSwitchPending {
					p.workspace = nil
					go workspace.close()
					a.targetRecovery = nil
					p.Close()
					a.status = i18n.T("crossaccount.recovery.status_switch_pending")
				}
				return
			}
			if !adopted {
				for i := range p.records {
					p.records[i].Close()
				}
				p.records = reply.TargetRecords
				p.status = strings.Join(notes, "\n")
				return
			}
			if reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != workspace.inspection.Fresh.Scope || !reply.State.Available || reply.Vault == nil || !reply.Vault.PreservesPendingPolicies(workspace.inspection.Fresh.Vault) {
				p.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			for _, id := range workspace.inspection.Fresh.Vault.QuarantinedOrganizations {
				found := false
				for _, actual := range reply.Vault.QuarantinedOrganizations {
					if actual == id {
						found = true
					}
				}
				if !found {
					p.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
					return
				}
			}
			if e := workspace.session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); e != nil {
				p.status = vaultwarden.ErrorMessage(e)
				return
			}
			// Transfer only the newly authenticated Session and the dedicated merged receipt.
			p.workspace = nil
			a.targetRecovery = nil
			p.Close()
			a.advanceEpoch()
			a.session = workspace.session
			a.snapshot = reply.State
			a.liveScope = reply.State.Scope
			a.sessionRevision = reply.State.Revision
			if e := a.adoptVault(reply.Vault); e != nil {
				a.stopNetwork()
				workspace.inspection.Close()
				a.status = vaultwarden.ErrorMessage(e)
				return
			}
			a.itemsRevision = reply.State.Revision
			a.serverURL, a.email = workspace.inspection.Fresh.Scope.Server, workspace.inspection.Fresh.PasswordUnlock.Config.Email
			workspace.inspection.Close()
			a.showLogin = false
			a.category = "all"
			a.status = i18n.T("crossaccount.recovery.status_published")
			a.startNotifications(p.dispatch, p.storage)
		})
	}()
}
func (p *targetRecoveryController) View(c *ui.Context) {
	if p.closed {
		return
	}
	ui.Text(c, i18n.T("crossaccount.recovery.title")).FontSize(20)
	ui.Text(c, i18n.T("crossaccount.recovery.authentication_hint")).MaxLines(4)
	ui.TextInput(c, &p.server).Label(i18n.T("crossaccount.recovery.server")).Disabled(p.running)
	ui.TextInput(c, &p.email).Label(i18n.T("crossaccount.recovery.email")).Disabled(p.running)
	ui.Column(c.Key(fmt.Sprintf("target-password-%d", p.generation))).Children(func() {
		ui.TextInput(c, &p.password).Label(i18n.T("crossaccount.recovery.master_password")).Password().Disabled(p.running)
	})
	if ui.Button(c, i18n.T("crossaccount.recovery.login_inspect")).Disabled(p.running || p.password == "").Clicked() {
		p.inspect()
	}
	if p.workspace != nil && p.source != nil && p.source.Scope != nil && *p.source.Scope != p.workspace.inspection.Fresh.Scope {
		old, new := *p.source.Scope, p.workspace.inspection.Fresh.Scope
		ui.Text(c, i18n.Tf("crossaccount.recovery.confirm_replace_hint", old.Server, old.Account, new.Server, new.Account)).MaxLines(10)
		label := i18n.T("crossaccount.recovery.confirm_replace")
		if p.replaceForeign {
			label = i18n.T("crossaccount.recovery.revoke_replace")
		}
		if ui.Button(c, label).Disabled(p.running).Clicked() {
			p.replaceForeign = !p.replaceForeign
		}
	}
	for index, record := range p.records {
		ui.Text(c, i18n.Tf("crossaccount.recovery.operation_summary", record.Binding.OperationID, record.Phase, record.Binding.Target.Server, record.Binding.Target.Account)).MaxLines(5)
		candidate := p.workspace != nil && record.RequireTargetLogin && record.Binding.Target == p.workspace.inspection.Fresh.Scope && record.Phase != "resolved"
		if ui.Button(c, i18n.Tf("crossaccount.recovery.confirm_verify", record.Binding.OperationID)).Disabled(p.running || !candidate).Clicked() {
			p.verify(index)
		}
	}
	ui.Text(c, p.status).MaxLines(20)
	if ui.Button(c, i18n.T("crossaccount.recovery.finish")).Clicked() {
		p.owner.stopNetwork()
	}
}
