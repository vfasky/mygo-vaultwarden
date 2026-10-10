// SPDX-License-Identifier: GPL-3.0-only
// Package send provides the Send panel and native file dialogs.
package send

import (
	"context"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// SendHost is the integration boundary. All callbacks run on the UI thread,
// except Check, Checkpoint and file chooser callbacks, which must be safe on the
// worker. Dispatch must schedule on window.Update. Check verifies current
// account, epoch, unlocked state and storage revision. Checkpoint must durably
// save and authenticate its receipt before returning. No global app registry.
type Host struct {
	Busy              func(bool) // UI-thread worker accounting, including late completion
	Dispatch          func(func())
	Check             func() error
	Checkpoint        func(vaultwarden.SessionCheckpoint) error
	ChooseSource      func(context.Context) (io.ReadCloser, int64, string, error)
	ChooseDestination func(context.Context, string) (string, error)
	Copy              func(string) error
	Changed           func() // successful owner mutation: sync/publish, then replace panel
}
type Panel struct {
	Host                                                                    Host
	session                                                                 *vaultwarden.Session
	Client                                                                  *vaultwarden.Client
	vault                                                                   *vaultwarden.VaultData
	scope                                                                   vaultwarden.Scope
	ctx                                                                     context.Context
	cancel                                                                  context.CancelFunc
	generation                                                              uint64
	Closed, Busy, Uncertain, confirmDelete, showText                        bool
	Status, Link, Password, ReceivePassword, Deletion, expiration, maxCount string
	Rows                                                                    []*vaultwarden.SendDraft
	Draft                                                                   *vaultwarden.SendDraft
	Receiver                                                                *vaultwarden.SendReceiver
	Fields                                                                  vaultwarden.SendFields
}

func NewPanel(session *vaultwarden.Session, client *vaultwarden.Client, vault *vaultwarden.VaultData, scope vaultwarden.Scope, host Host) *Panel {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Panel{session: session, Client: client, vault: vault, scope: scope, Host: host, ctx: ctx, cancel: cancel}
	if host.Dispatch == nil || host.Check == nil {
		p.Closed = true
		p.Status = i18n.T("Send 生命周期回调未配置")
		cancel()
	}
	return p
}

// Close must run on UI thread BEFORE account/epoch/revision replacement or lock.
// In-flight tasks own their moved draft/receiver; cancellation plus generation
// checks close late results instead of allowing a stale callback to revive UI.
func (p *Panel) Close() {
	if p == nil {
		return
	}
	p.cancel()
	p.generation++
	p.Closed = true
	p.clearViews()
	p.Fields = vaultwarden.SendFields{}
	p.Link = ""
	p.Password = ""
	p.ReceivePassword = ""
	p.Status = ""
}
func (p *Panel) clearViews() {
	for _, d := range p.Rows {
		d.Close()
	}
	p.Rows = nil
	if p.Draft != nil {
		p.Draft.Close()
		p.Draft = nil
	}
	if p.Receiver != nil {
		p.Receiver.Close()
		p.Receiver = nil
	}
	p.Fields = vaultwarden.SendFields{}
	p.Password = ""
	p.ReceivePassword = ""
	p.showText = false
	p.confirmDelete = false
}

type Result struct {
	rows     []*vaultwarden.SendDraft
	Draft    *vaultwarden.SendDraft
	receiver *vaultwarden.SendReceiver
	Err      error
	changed  bool
	message  string
}

func (r *Result) close() {
	for _, d := range r.rows {
		d.Close()
	}
	if r.Draft != nil {
		r.Draft.Close()
	}
	if r.receiver != nil {
		r.receiver.Close()
	}
}
func (p *Panel) Run(work func(context.Context) Result) {
	if p.Closed || p.Busy {
		return
	}
	p.Busy = true
	if p.Host.Busy != nil {
		p.Host.Busy(true)
	}
	generation := p.generation
	go func() {
		r := work(p.ctx)
		p.Host.Dispatch(func() {
			if p.Host.Busy != nil {
				p.Host.Busy(false)
			}
			if p.Closed || generation != p.generation {
				r.close()
				return
			}
			p.Busy = false
			if e := p.Host.Check(); e != nil {
				r.close()
				p.Close()
				return
			}
			if r.Err != nil {
				p.Status = r.Err.Error()
				var unknown *vaultwarden.MutationUncertainError
				var upload *vaultwarden.SendUploadError
				p.Uncertain = errors.As(r.Err, &unknown) || errors.As(r.Err, &upload)
				if !p.Uncertain && r.Draft != nil && r.Draft.CanEdit() {
					p.clearViews()
					p.installDraft(r.Draft)
					if r.Draft.Fields.Password != nil {
						p.Password = *r.Draft.Fields.Password
					}
					r.Draft = nil
				}
				r.close()
				return
			}
			if r.rows != nil {
				p.clearViews()
				p.Rows = r.rows
				p.Uncertain = false
			}
			if r.Draft != nil {
				p.clearViews()
				p.installDraft(r.Draft)
			}
			if r.receiver != nil {
				p.Link = ""
				p.clearViews()
				p.Receiver = r.receiver
				p.Fields, _ = r.receiver.Fields()
			}
			p.Status = r.message
			if r.changed && p.Host.Changed != nil {
				p.Host.Changed()
			}
		})
	}()
}
func (p *Panel) Refresh() {
	if p.session == nil {
		return
	}
	p.Run(func(ctx context.Context) Result {
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		rows, e := p.session.ListSends(ctx, p.scope, p.Host.Checkpoint)
		if rows == nil && e == nil {
			rows = []*vaultwarden.SendDraft{}
		}
		return Result{rows: rows, Err: e}
	})
}
func (p *Panel) Offline() {
	if p.Closed || p.Busy || p.session == nil {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = e.Error()
		return
	}
	rows, e := p.session.Sends(p.vault)
	if e != nil {
		p.Status = e.Error()
		return
	}
	p.clearViews()
	p.Rows = rows
	p.Status = i18n.T("离线受信快照；访问次数可能已变化")
}
func (p *Panel) New(kind int) {
	if p.Closed || p.Busy || p.session == nil {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = e.Error()
		return
	}
	d, e := p.session.NewSend(p.vault, kind)
	if e != nil {
		p.Status = e.Error()
		return
	}
	p.clearViews()
	p.installDraft(d)
	p.Uncertain = false
}
func (p *Panel) installDraft(d *vaultwarden.SendDraft) {
	p.Draft = d
	p.Fields = d.Fields
	p.Password = ""
	p.Deletion = d.Fields.DeletionDate.Format(time.RFC3339)
	p.expiration = ""
	p.maxCount = ""
	if d.Fields.ExpirationDate != nil {
		p.expiration = d.Fields.ExpirationDate.Format(time.RFC3339)
	}
	if d.Fields.MaxAccessCount != nil {
		p.maxCount = strconv.Itoa(*d.Fields.MaxAccessCount)
	}
}
func (p *Panel) openRow(index int) {
	d := p.Rows[index]
	p.Rows = append(p.Rows[:index], p.Rows[index+1:]...)
	p.clearViews()
	p.installDraft(d)
	p.Uncertain = false
}
func (p *Panel) form() error {
	date, e := time.Parse(time.RFC3339, p.Deletion)
	if e != nil {
		return vaultwarden.ErrValidation
	}
	p.Fields.DeletionDate = date
	p.Fields.ExpirationDate = nil
	p.Fields.MaxAccessCount = nil
	p.Fields.Password = nil
	if p.expiration != "" {
		v, e := time.Parse(time.RFC3339, p.expiration)
		if e != nil {
			return vaultwarden.ErrValidation
		}
		p.Fields.ExpirationDate = &v
	}
	if p.maxCount != "" {
		n, e := strconv.Atoi(p.maxCount)
		if e != nil {
			return vaultwarden.ErrValidation
		}
		p.Fields.MaxAccessCount = &n
	}
	if p.Password != "" {
		v := p.Password
		p.Fields.Password = &v
	}
	return nil
}
func (p *Panel) Save() {
	if p.Closed || p.Busy || p.Uncertain || p.Draft == nil {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = e.Error()
		return
	}
	if e := p.form(); e != nil {
		p.Status = i18n.T("请检查日期与访问次数。日期使用 RFC3339（含时区）。")
		return
	}
	d := p.Draft
	d.Fields = p.Fields
	p.Draft = nil
	p.Fields = vaultwarden.SendFields{}
	p.Password = ""
	p.Run(func(ctx context.Context) (result Result) {
		defer func() {
			if result.Err != nil && d.CanEdit() {
				result.Draft = d
			} else {
				d.Close()
			}
		}()
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		var source io.ReadCloser
		var size int64
		if d.Fields.Type == 1 && d.ID() == "" {
			if p.Host.ChooseSource == nil {
				return Result{Err: vaultwarden.ErrPermission}
			}
			var name string
			var e error
			source, size, name, e = p.Host.ChooseSource(ctx)
			if e != nil {
				return Result{Err: e}
			}
			if source == nil {
				return Result{Err: vaultwarden.ErrCancelled}
			}
			defer source.Close()
			d.Fields.FileName = name
		}
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		next, e := p.session.SaveSend(ctx, d, source, size, p.Host.Checkpoint)
		return Result{Draft: next, Err: e, changed: e == nil, message: i18n.T("Send 已保存，请同步后重新打开以复制分享链接。")}
	})
}
func (p *Panel) change(remove bool) {
	if p.Closed || p.Busy || p.Uncertain || p.Draft == nil || (remove && !p.confirmDelete) {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = e.Error()
		return
	}
	d := p.Draft
	p.Draft = nil
	p.Fields = vaultwarden.SendFields{}
	p.Password = ""
	p.Run(func(ctx context.Context) (result Result) {
		defer func() {
			if result.Err != nil && d.CanEdit() {
				result.Draft = d
			} else {
				d.Close()
			}
		}()
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		var e error
		if remove {
			e = p.session.DeleteSend(ctx, d, p.Host.Checkpoint)
		} else {
			e = p.session.RemoveSendPassword(ctx, d, p.Host.Checkpoint)
		}
		return Result{Err: e, changed: e == nil, message: i18n.T("修改已提交，请同步核对。")}
	})
}
func (p *Panel) Receive() {
	if p.Closed || p.Busy || p.Client == nil {
		return
	}
	link, password := p.Link, p.ReceivePassword
	p.ReceivePassword = ""
	p.Run(func(ctx context.Context) Result {
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		r, e := p.Client.OpenSend(ctx, link, password)
		return Result{receiver: r, Err: e}
	})
}
func (p *Panel) saveReceived() {
	if p.Receiver == nil || p.Busy || p.Closed || p.Host.ChooseDestination == nil {
		return
	}
	r := p.Receiver
	p.Receiver = nil
	name := p.Fields.FileName
	p.Fields = vaultwarden.SendFields{}
	p.Run(func(ctx context.Context) Result {
		defer r.Close()
		if e := p.Host.Check(); e != nil {
			return Result{Err: e}
		}
		path, e := p.Host.ChooseDestination(ctx, name)
		if e == nil {
			if e = p.Host.Check(); e == nil {
				e = r.SaveFile(ctx, path)
			}
		}
		return Result{Err: e, message: i18n.T("文件已验证并保存。")}
	})
}
func (p *Panel) View(c *ui.Context) {
	ui.Scroll(c).Children(func() {
		ui.Column(c.Key("send-panel")).Padding(18).Gap(10).Children(func() {
			ui.Text(c, i18n.T("Send 安全分享")).FontSize(23)
			if p.Closed {
				ui.Text(c, i18n.T("Send 已关闭"))
				return
			}
			disabled := p.Busy || p.Uncertain
			button := func(label string, off bool, f func()) {
				if ui.Button(c, label).Disabled(off).Clicked() {
					f()
				}
			}
			ui.Row(c).Gap(8).Children(func() {
				button(i18n.T("刷新 Send"), p.Busy || p.session == nil, p.Refresh)
				button(i18n.T("离线列表"), p.Busy || p.session == nil, p.Offline)
				button(i18n.T("新建文本"), p.Busy || p.session == nil, func() { p.New(0) })
				button(i18n.T("新建文件"), p.Busy || p.session == nil, func() { p.New(1) })
			})
			if p.Status != "" {
				ui.Text(c, p.Status).MaxLines(4)
			}
			if p.Busy {
				ui.Text(c, i18n.T("正在处理…关闭面板可取消。"))
			}
			if p.Uncertain {
				ui.Text(c, i18n.T("结果未确认，请刷新或同步核对。不会自动重试。"))
			}
			for i, d := range p.Rows {
				index := i
				button(i18n.Tf("%s · 访问 %d", d.Fields.Name, d.AccessCount()), p.Busy, func() { p.openRow(index) })
			}
			if p.Draft != nil {
				ui.TextInput(c, &p.Fields.Name).Label(i18n.T("名称")).Disabled(disabled)
				if p.Fields.Type == 0 {
					ui.TextArea(c, &p.Fields.Text).Label(i18n.T("分享文本")).MinHeight(110).Disabled(disabled)
					button(i18n.Tf("隐藏接收文本：%t", p.Fields.Hidden), disabled, func() { p.Fields.Hidden = !p.Fields.Hidden })
				} else {
					ui.Text(c, i18n.T("文件内容不可编辑；新建时选择本地文件。"))
					if p.Fields.FileName != "" {
						ui.Text(c, p.Fields.FileName)
					}
				}
				ui.TextArea(c, &p.Fields.Notes).Label(i18n.T("私人备注")).MinHeight(70).Disabled(disabled)
				ui.TextInput(c, &p.Deletion).Label(i18n.T("删除日期（最多31天，RFC3339）")).Disabled(disabled)
				ui.TextInput(c, &p.expiration).Label(i18n.T("过期日期（可留空，RFC3339）")).Disabled(disabled)
				ui.TextInput(c, &p.maxCount).Label(i18n.T("最大访问次数（空为不限）")).Disabled(disabled)
				ui.TextInput(c, &p.Password).Label(i18n.T("设置访问口令（留空保留）")).Password().Disabled(disabled)
				button(i18n.Tf("禁用：%t", p.Fields.Disabled), disabled, func() { p.Fields.Disabled = !p.Fields.Disabled })
				button(i18n.Tf("隐藏邮箱：%t", p.Fields.HideEmail), disabled, func() { p.Fields.HideEmail = !p.Fields.HideEmail })
				ui.Text(c, i18n.T("此服务器版本不支持邮件验证型 Send。"))
				button(i18n.T("保存 Send"), disabled, p.Save)
				if p.Draft.ID() != "" {
					ui.Text(c, i18n.Tf("已访问：%d", p.Draft.AccessCount()))
					button(i18n.T("复制分享链接"), disabled || p.Host.Copy == nil, func() {
						if e := p.Host.Check(); e != nil {
							p.Status = e.Error()
							return
						}
						link, e := p.Draft.ShareLink()
						if e == nil {
							e = p.Host.Copy(link)
						}
						if e != nil {
							p.Status = e.Error()
						} else {
							p.Status = i18n.T("分享链接已复制（包含解密密钥）。")
						}
					})
					if p.Draft.HasPassword() {
						button(i18n.T("移除访问口令"), disabled, func() { p.change(false) })
					}
					if !p.confirmDelete {
						button(i18n.T("删除 Send"), disabled, func() { p.confirmDelete = true })
					} else {
						ui.Text(c, i18n.T("删除后分享链接将失效，确认删除？"))
						button(i18n.T("确认删除 Send"), disabled, func() { p.change(true) })
						button(i18n.T("取消删除"), p.Busy, func() { p.confirmDelete = false })
					}
				}
			}
			ui.TextInput(c, &p.Link).Label(i18n.T("接收分享链接")).Password().Disabled(p.Busy)
			ui.TextInput(c, &p.ReceivePassword).Label(i18n.T("接收访问口令")).Password().Disabled(p.Busy)
			button(i18n.T("打开分享链接"), p.Busy || p.Link == "", p.Receive)
			if p.Receiver != nil {
				ui.Text(c, p.Fields.Name)
				if p.Fields.CreatorIdentifier != "" {
					ui.Text(c, i18n.Tf("发送者：%s", p.Fields.CreatorIdentifier))
				}
				if p.Fields.Type == 0 {
					if p.Fields.Hidden && !p.showText {
						button(i18n.T("显示分享文本"), false, func() { p.showText = true })
					} else {
						ui.Text(c, p.Fields.Text).MaxLines(30)
					}
				} else {
					ui.Text(c, p.Fields.FileName)
					button(i18n.T("保存接收文件"), p.Busy, p.saveReceived)
				}
			}
			button(i18n.T("关闭 Send"), false, p.Close)
		})
	})
}
