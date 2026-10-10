// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
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
	source                          *snapshotStatus
	records                         []targetRecoveryRecord
	workspace                       *targetRecoveryWorkspace
	replaceForeign, running, closed bool
	ctx                             context.Context
	cancel                          context.CancelFunc
	dispatch                        func(func())
	storage                         func(storageRequest) storageReply
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
func targetStorageEvidence(e vaultwarden.TargetRecoveryEvidence) targetRecoveryVerification {
	return targetRecoveryVerification{Kind: e.Kind, AuthorityHash: e.AuthorityHash, KeyHash: e.KeyHash, MembershipHash: e.MembershipHash, MFAHash: e.MFAHash, ConfirmationHash: e.ConfirmationHash, AuthenticationEpoch: e.AuthenticationEpoch}
}
func targetDiscoveryAdapter(ctx context.Context, workspace *targetRecoveryWorkspace, state *snapshotStatus, epoch uint64, current func() uint64, storage func(storageRequest) storageReply) (*targetRecoveryStorage, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	evidence, err := workspace.session.TargetRecoveryDiscoveryEvidence(workspace.inspection, hex.EncodeToString(nonce[:]))
	if err != nil {
		return nil, err
	}
	return newTargetRecoveryLoginStorage(state, epoch, func() uint64 {
		if ctx.Err() != nil {
			return 0
		}
		return current()
	}, workspace.inspection.Fresh, targetStorageEvidence(evidence), storage)
}
func (a *app) openTargetRecovery() { a.openTargetRecoveryWith(a.dispatchUI, a.storageCall) }
func (a *app) openTargetRecoveryWith(dispatch func(func()), storage func(storageRequest) storageReply) {
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
		p.status = err.Error()
		return
	}
	email, password := vaultwarden.NormalizeEmail(p.email), []byte(p.password)
	p.password = ""
	p.generation++
	if !strings.Contains(email, "@") {
		clear(password)
		p.status = "请输入目标本人的登录邮箱。"
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
		var reply storageReply
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
			reply = p.storage(storageRequest{Operation: "status"})
			if !reply.OK || reply.State == nil {
				err = reply.failure()
			}
		}
		if err == nil {
			var adapter *targetRecoveryStorage
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
				p.status = "重新认证或读取核验事实失败，屏障保留：" + err.Error()
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
			p.status = "已完成本人全新认证和实际状态读取；请选择具体操作确认核验。未启用普通库或AutoFill。"
		})
	}()
}
func targetAllVerified(records []targetRecoveryRecord, fresh vaultwarden.SyncResult) bool {
	found := false
	for _, record := range records {
		if record.RequireTargetLogin && record.Binding.Target == fresh.Scope && record.Phase != "resolved" {
			found = true
			if record.Phase != "verified" || record.VerifiedVaultHash != targetRecoveryHash(fresh.Vault.Sync) || record.VerifiedSessionHash != targetRecoveryHash(fresh.Session) || record.VerifiedUnlockHash != targetRecoveryHash(fresh.PasswordUnlock.Key) {
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
		var reply storageReply
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
				err = errTargetRecovery
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
					var binding accountSwitchBinding
					binding, err = newAccountSwitchBinding(reply.State, fresh.Scope)
					if err == nil {
						reply, err = publishBoundAccount(ctx, reply.State, fresh, binding, p.storage)
						adopted = err == nil
					}
				} else {
					notes = append(notes, "全部当前目标记录已核验；尚未替换原本机账号。请明确确认下方旧/新账号及影响后再次选择记录。")
				}
			case reply.State.Scope != nil:
				reply, err = adapter.ResolveVerifiedWithLocalAuthentication(fresh, targetStorageEvidence(evidence))
				adopted = err == nil
			default:
				reply, err = adapter.ResolveVerified(fresh, targetStorageEvidence(evidence))
				adopted = err == nil
			}
		} else if err == nil {
			notes = append(notes, "此操作已核验；其它目标记录仍须逐项以本次材料核验，整体屏障继续保留。")
		}
		if err != nil {
			status := p.storage(storageRequest{Operation: "status"})
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
				p.status = "未解除屏障；不重放原操作：" + err.Error()
				if reply.State != nil && reply.State.AccountSwitchPending {
					p.workspace = nil
					go workspace.close()
					a.targetRecovery = nil
					p.Close()
					a.status = "账号替换回执尚未确认，请通过系统认证检查同一切换，不重试或回滚。"
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
				p.status = vaultwarden.ErrIdentity.Error()
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
					p.status = vaultwarden.ErrIdentity.Error()
					return
				}
			}
			if e := workspace.session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); e != nil {
				p.status = e.Error()
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
				a.status = e.Error()
				return
			}
			a.itemsRevision = reply.State.Revision
			a.serverURL, a.email = workspace.inspection.Fresh.Scope.Server, workspace.inspection.Fresh.PasswordUnlock.Config.Email
			workspace.inspection.Close()
			a.showLogin = false
			a.category = "all"
			a.status = "目标恢复记录已通过专用认证发布；既有本机保护已合并。"
			a.startNotifications(p.dispatch, p.storage)
		})
	}()
}
func (p *targetRecoveryController) View(c *ui.Context) {
	if p.closed {
		return
	}
	ui.Text(c, "目标本人重新认证与恢复核验").FontSize(20)
	ui.Text(c, "不会复用旧会话、重发恢复请求或清除其它账号记录。密码与MFA须属于目标本人。").MaxLines(4)
	ui.TextInput(c, &p.server).Label("目标服务器").Disabled(p.running)
	ui.TextInput(c, &p.email).Label("目标当前邮箱").Disabled(p.running)
	ui.Column(c).Key(fmt.Sprintf("target-password-%d", p.generation)).Children(func() { ui.TextInput(c, &p.password).Label("目标当前主密码").Password().Disabled(p.running) })
	if ui.Button(c, "全新登录并读取待核验记录").Disabled(p.running || p.password == "").Clicked() {
		p.inspect()
	}
	if p.workspace != nil && p.source != nil && p.source.Scope != nil && *p.source.Scope != p.workspace.inspection.Fresh.Scope {
		old, new := *p.source.Scope, p.workspace.inspection.Fresh.Scope
		ui.Text(c, "原本机账号："+old.Server+" / "+old.Account+"\n核验目标："+new.Server+" / "+new.Account+"\n确认后将系统认证并原子保存目标；成功确认前保留旧密文与密钥。旧账号有未决保护时拒绝替换。").MaxLines(10)
		label := "明确同意替换原本机账号并保存核验目标"
		if p.replaceForeign {
			label = "已同意替换（点击撤回）"
		}
		if ui.Button(c, label).Disabled(p.running).Clicked() {
			p.replaceForeign = !p.replaceForeign
		}
	}
	for index, record := range p.records {
		ui.Text(c, "操作 "+record.Binding.OperationID+" · "+record.Phase+"\n目标："+record.Binding.Target.Server+" / "+record.Binding.Target.Account).MaxLines(5)
		candidate := p.workspace != nil && record.RequireTargetLogin && record.Binding.Target == p.workspace.inspection.Fresh.Scope && record.Phase != "resolved"
		if ui.Button(c, "确认核验并仅解除此目标操作 "+record.Binding.OperationID).Disabled(p.running || !candidate).Clicked() {
			p.verify(index)
		}
	}
	ui.Text(c, p.status).MaxLines(20)
	if ui.Button(c, "结束核验并保留未决记录").Clicked() {
		p.owner.stopNetwork()
	}
}
