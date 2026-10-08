// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// SendHost is the integration boundary. All callbacks run on the UI thread,
// except Check, Checkpoint and file chooser callbacks, which must be safe on the
// worker. Dispatch must schedule on window.Update. Check verifies current
// account, epoch, unlocked state and storage revision. Checkpoint must durably
// save and authenticate its receipt before returning. No global app registry.
type SendHost struct {
	Busy              func(bool) // UI-thread worker accounting, including late completion
	Dispatch          func(func())
	Check             func() error
	Checkpoint        func(vaultwarden.SessionCheckpoint) error
	ChooseSource      func(context.Context) (io.ReadCloser, int64, string, error)
	ChooseDestination func(context.Context, string) (string, error)
	Copy              func(string) error
	Changed           func() // successful owner mutation: sync/publish, then replace panel
}
type SendPanel struct {
	host                                                                    SendHost
	session                                                                 *vaultwarden.Session
	client                                                                  *vaultwarden.Client
	vault                                                                   *vaultwarden.VaultData
	scope                                                                   vaultwarden.Scope
	ctx                                                                     context.Context
	cancel                                                                  context.CancelFunc
	generation                                                              uint64
	closed, busy, uncertain, confirmDelete, showText                        bool
	status, link, password, receivePassword, deletion, expiration, maxCount string
	rows                                                                    []*vaultwarden.SendDraft
	draft                                                                   *vaultwarden.SendDraft
	receiver                                                                *vaultwarden.SendReceiver
	fields                                                                  vaultwarden.SendFields
}

func NewSendPanel(session *vaultwarden.Session, client *vaultwarden.Client, vault *vaultwarden.VaultData, scope vaultwarden.Scope, host SendHost) *SendPanel {
	ctx, cancel := context.WithCancel(context.Background())
	p := &SendPanel{session: session, client: client, vault: vault, scope: scope, host: host, ctx: ctx, cancel: cancel}
	if host.Dispatch == nil || host.Check == nil {
		p.closed = true
		p.status = "Send 生命周期回调未配置"
		cancel()
	}
	return p
}

// Close must run on UI thread BEFORE account/epoch/revision replacement or lock.
// In-flight tasks own their moved draft/receiver; cancellation plus generation
// checks close late results instead of allowing a stale callback to revive UI.
func (p *SendPanel) Close() {
	if p == nil {
		return
	}
	p.cancel()
	p.generation++
	p.closed = true
	p.clearViews()
	p.fields = vaultwarden.SendFields{}
	p.link = ""
	p.password = ""
	p.receivePassword = ""
	p.status = ""
}
func (p *SendPanel) clearViews() {
	for _, d := range p.rows {
		d.Close()
	}
	p.rows = nil
	if p.draft != nil {
		p.draft.Close()
		p.draft = nil
	}
	if p.receiver != nil {
		p.receiver.Close()
		p.receiver = nil
	}
	p.fields = vaultwarden.SendFields{}
	p.password = ""
	p.receivePassword = ""
	p.showText = false
	p.confirmDelete = false
}

type sendPanelResult struct {
	rows     []*vaultwarden.SendDraft
	draft    *vaultwarden.SendDraft
	receiver *vaultwarden.SendReceiver
	err      error
	changed  bool
	message  string
}

func (r *sendPanelResult) close() {
	for _, d := range r.rows {
		d.Close()
	}
	if r.draft != nil {
		r.draft.Close()
	}
	if r.receiver != nil {
		r.receiver.Close()
	}
}
func (p *SendPanel) run(work func(context.Context) sendPanelResult) {
	if p.closed || p.busy {
		return
	}
	p.busy = true
	if p.host.Busy != nil {
		p.host.Busy(true)
	}
	generation := p.generation
	go func() {
		r := work(p.ctx)
		p.host.Dispatch(func() {
			if p.host.Busy != nil {
				p.host.Busy(false)
			}
			if p.closed || generation != p.generation {
				r.close()
				return
			}
			p.busy = false
			if e := p.host.Check(); e != nil {
				r.close()
				p.Close()
				return
			}
			if r.err != nil {
				p.status = r.err.Error()
				var unknown *vaultwarden.MutationUncertainError
				var upload *vaultwarden.SendUploadError
				p.uncertain = errors.As(r.err, &unknown) || errors.As(r.err, &upload)
				if !p.uncertain && r.draft != nil && r.draft.CanEdit() {
					p.clearViews()
					p.installDraft(r.draft)
					if r.draft.Fields.Password != nil {
						p.password = *r.draft.Fields.Password
					}
					r.draft = nil
				}
				r.close()
				return
			}
			if r.rows != nil {
				p.clearViews()
				p.rows = r.rows
				p.uncertain = false
			}
			if r.draft != nil {
				p.clearViews()
				p.installDraft(r.draft)
			}
			if r.receiver != nil {
				p.link = ""
				p.clearViews()
				p.receiver = r.receiver
				p.fields, _ = r.receiver.Fields()
			}
			p.status = r.message
			if r.changed && p.host.Changed != nil {
				p.host.Changed()
			}
		})
	}()
}
func (p *SendPanel) Refresh() {
	if p.session == nil {
		return
	}
	p.run(func(ctx context.Context) sendPanelResult {
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		rows, e := p.session.ListSends(ctx, p.scope, p.host.Checkpoint)
		if rows == nil && e == nil {
			rows = []*vaultwarden.SendDraft{}
		}
		return sendPanelResult{rows: rows, err: e}
	})
}
func (p *SendPanel) Offline() {
	if p.closed || p.busy || p.session == nil {
		return
	}
	if e := p.host.Check(); e != nil {
		p.status = e.Error()
		return
	}
	rows, e := p.session.Sends(p.vault)
	if e != nil {
		p.status = e.Error()
		return
	}
	p.clearViews()
	p.rows = rows
	p.status = "离线受信快照；访问次数可能已变化"
}
func (p *SendPanel) New(kind int) {
	if p.closed || p.busy || p.session == nil {
		return
	}
	if e := p.host.Check(); e != nil {
		p.status = e.Error()
		return
	}
	d, e := p.session.NewSend(p.vault, kind)
	if e != nil {
		p.status = e.Error()
		return
	}
	p.clearViews()
	p.installDraft(d)
	p.uncertain = false
}
func (p *SendPanel) installDraft(d *vaultwarden.SendDraft) {
	p.draft = d
	p.fields = d.Fields
	p.password = ""
	p.deletion = d.Fields.DeletionDate.Format(time.RFC3339)
	p.expiration = ""
	p.maxCount = ""
	if d.Fields.ExpirationDate != nil {
		p.expiration = d.Fields.ExpirationDate.Format(time.RFC3339)
	}
	if d.Fields.MaxAccessCount != nil {
		p.maxCount = strconv.Itoa(*d.Fields.MaxAccessCount)
	}
}
func (p *SendPanel) openRow(index int) {
	d := p.rows[index]
	p.rows = append(p.rows[:index], p.rows[index+1:]...)
	p.clearViews()
	p.installDraft(d)
	p.uncertain = false
}
func (p *SendPanel) form() error {
	date, e := time.Parse(time.RFC3339, p.deletion)
	if e != nil {
		return vaultwarden.ErrValidation
	}
	p.fields.DeletionDate = date
	p.fields.ExpirationDate = nil
	p.fields.MaxAccessCount = nil
	p.fields.Password = nil
	if p.expiration != "" {
		v, e := time.Parse(time.RFC3339, p.expiration)
		if e != nil {
			return vaultwarden.ErrValidation
		}
		p.fields.ExpirationDate = &v
	}
	if p.maxCount != "" {
		n, e := strconv.Atoi(p.maxCount)
		if e != nil {
			return vaultwarden.ErrValidation
		}
		p.fields.MaxAccessCount = &n
	}
	if p.password != "" {
		v := p.password
		p.fields.Password = &v
	}
	return nil
}
func (p *SendPanel) Save() {
	if p.closed || p.busy || p.uncertain || p.draft == nil {
		return
	}
	if e := p.host.Check(); e != nil {
		p.status = e.Error()
		return
	}
	if e := p.form(); e != nil {
		p.status = "请检查日期与访问次数。日期使用 RFC3339（含时区）。"
		return
	}
	d := p.draft
	d.Fields = p.fields
	p.draft = nil
	p.fields = vaultwarden.SendFields{}
	p.password = ""
	p.run(func(ctx context.Context) (result sendPanelResult) {
		defer func() {
			if result.err != nil && d.CanEdit() {
				result.draft = d
			} else {
				d.Close()
			}
		}()
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		var source io.ReadCloser
		var size int64
		if d.Fields.Type == 1 && d.ID() == "" {
			if p.host.ChooseSource == nil {
				return sendPanelResult{err: vaultwarden.ErrPermission}
			}
			var name string
			var e error
			source, size, name, e = p.host.ChooseSource(ctx)
			if e != nil {
				return sendPanelResult{err: e}
			}
			if source == nil {
				return sendPanelResult{err: vaultwarden.ErrCancelled}
			}
			defer source.Close()
			d.Fields.FileName = name
		}
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		next, e := p.session.SaveSend(ctx, d, source, size, p.host.Checkpoint)
		return sendPanelResult{draft: next, err: e, changed: e == nil, message: "Send 已保存，请同步后重新打开以复制分享链接。"}
	})
}
func (p *SendPanel) change(remove bool) {
	if p.closed || p.busy || p.uncertain || p.draft == nil || (remove && !p.confirmDelete) {
		return
	}
	if e := p.host.Check(); e != nil {
		p.status = e.Error()
		return
	}
	d := p.draft
	p.draft = nil
	p.fields = vaultwarden.SendFields{}
	p.password = ""
	p.run(func(ctx context.Context) (result sendPanelResult) {
		defer func() {
			if result.err != nil && d.CanEdit() {
				result.draft = d
			} else {
				d.Close()
			}
		}()
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		var e error
		if remove {
			e = p.session.DeleteSend(ctx, d, p.host.Checkpoint)
		} else {
			e = p.session.RemoveSendPassword(ctx, d, p.host.Checkpoint)
		}
		return sendPanelResult{err: e, changed: e == nil, message: "修改已提交，请同步核对。"}
	})
}
func (p *SendPanel) Receive() {
	if p.closed || p.busy || p.client == nil {
		return
	}
	link, password := p.link, p.receivePassword
	p.receivePassword = ""
	p.run(func(ctx context.Context) sendPanelResult {
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		r, e := p.client.OpenSend(ctx, link, password)
		return sendPanelResult{receiver: r, err: e}
	})
}
func (p *SendPanel) saveReceived() {
	if p.receiver == nil || p.busy || p.closed || p.host.ChooseDestination == nil {
		return
	}
	r := p.receiver
	p.receiver = nil
	name := p.fields.FileName
	p.fields = vaultwarden.SendFields{}
	p.run(func(ctx context.Context) sendPanelResult {
		defer r.Close()
		if e := p.host.Check(); e != nil {
			return sendPanelResult{err: e}
		}
		path, e := p.host.ChooseDestination(ctx, name)
		if e == nil {
			if e = p.host.Check(); e == nil {
				e = r.SaveFile(ctx, path)
			}
		}
		return sendPanelResult{err: e, message: "文件已验证并保存。"}
	})
}
func (p *SendPanel) View(c *ui.Context) {
	ui.Scroll(c).Children(func() {
		ui.Column(c).Key("send-panel").Padding(18).Gap(10).Children(func() {
			ui.Text(c, "Send 安全分享").FontSize(23)
			if p.closed {
				ui.Text(c, "Send 已关闭")
				return
			}
			disabled := p.busy || p.uncertain
			button := func(label string, off bool, f func()) {
				if ui.Button(c, label).Disabled(off).Clicked() {
					f()
				}
			}
			ui.Row(c).Gap(8).Children(func() {
				button("刷新 Send", p.busy || p.session == nil, p.Refresh)
				button("离线列表", p.busy || p.session == nil, p.Offline)
				button("新建文本", p.busy || p.session == nil, func() { p.New(0) })
				button("新建文件", p.busy || p.session == nil, func() { p.New(1) })
			})
			if p.status != "" {
				ui.Text(c, p.status).MaxLines(4)
			}
			if p.busy {
				ui.Text(c, "正在处理…关闭面板可取消。")
			}
			if p.uncertain {
				ui.Text(c, "结果未确认，请刷新或同步核对。不会自动重试。")
			}
			for i, d := range p.rows {
				index := i
				button(d.Fields.Name+" · 访问 "+strconv.Itoa(d.AccessCount()), p.busy, func() { p.openRow(index) })
			}
			if p.draft != nil {
				ui.TextInput(c, &p.fields.Name).Label("名称").Disabled(disabled)
				if p.fields.Type == 0 {
					ui.TextArea(c, &p.fields.Text).Label("分享文本").MinHeight(110).Disabled(disabled)
					button("隐藏接收文本："+strconv.FormatBool(p.fields.Hidden), disabled, func() { p.fields.Hidden = !p.fields.Hidden })
				} else {
					ui.Text(c, "文件内容不可编辑；新建时选择本地文件。")
					if p.fields.FileName != "" {
						ui.Text(c, p.fields.FileName)
					}
				}
				ui.TextArea(c, &p.fields.Notes).Label("私人备注").MinHeight(70).Disabled(disabled)
				ui.TextInput(c, &p.deletion).Label("删除日期（最多31天，RFC3339）").Disabled(disabled)
				ui.TextInput(c, &p.expiration).Label("过期日期（可留空，RFC3339）").Disabled(disabled)
				ui.TextInput(c, &p.maxCount).Label("最大访问次数（空为不限）").Disabled(disabled)
				ui.TextInput(c, &p.password).Label("设置访问口令（留空保留）").Password().Disabled(disabled)
				button("禁用："+strconv.FormatBool(p.fields.Disabled), disabled, func() { p.fields.Disabled = !p.fields.Disabled })
				button("隐藏邮箱："+strconv.FormatBool(p.fields.HideEmail), disabled, func() { p.fields.HideEmail = !p.fields.HideEmail })
				ui.Text(c, "此服务器版本不支持邮件验证型 Send。")
				button("保存 Send", disabled, p.Save)
				if p.draft.ID() != "" {
					ui.Text(c, "已访问："+strconv.Itoa(p.draft.AccessCount()))
					button("复制分享链接", disabled || p.host.Copy == nil, func() {
						if e := p.host.Check(); e != nil {
							p.status = e.Error()
							return
						}
						link, e := p.draft.ShareLink()
						if e == nil {
							e = p.host.Copy(link)
						}
						if e != nil {
							p.status = e.Error()
						} else {
							p.status = "分享链接已复制（包含解密密钥）。"
						}
					})
					if p.draft.HasPassword() {
						button("移除访问口令", disabled, func() { p.change(false) })
					}
					if !p.confirmDelete {
						button("删除 Send", disabled, func() { p.confirmDelete = true })
					} else {
						ui.Text(c, "删除后分享链接将失效，确认删除？")
						button("确认删除 Send", disabled, func() { p.change(true) })
						button("取消删除", p.busy, func() { p.confirmDelete = false })
					}
				}
			}
			ui.TextInput(c, &p.link).Label("接收分享链接").Password().Disabled(p.busy)
			ui.TextInput(c, &p.receivePassword).Label("接收访问口令").Password().Disabled(p.busy)
			button("打开分享链接", p.busy || p.link == "", p.Receive)
			if p.receiver != nil {
				ui.Text(c, p.fields.Name)
				if p.fields.CreatorIdentifier != "" {
					ui.Text(c, "发送者："+p.fields.CreatorIdentifier)
				}
				if p.fields.Type == 0 {
					if p.fields.Hidden && !p.showText {
						button("显示分享文本", false, func() { p.showText = true })
					} else {
						ui.Text(c, p.fields.Text).MaxLines(30)
					}
				} else {
					ui.Text(c, p.fields.FileName)
					button("保存接收文件", p.busy, p.saveReceived)
				}
			}
			button("关闭 Send", false, p.Close)
		})
	})
}
