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
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
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
	confirmRemovePassword                                                   bool
	Closed, Busy, Uncertain, confirmDelete, showText                        bool
	Status, Link, Password, ReceivePassword, Deletion, expiration, maxCount string
	newKind                                                                 int
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
		p.Status = i18n.T("send.panel.err_callbacks_missing")
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
	p.confirmRemovePassword = false
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
				p.Status = vaultwarden.ErrorMessage(r.Err)
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
		p.Status = vaultwarden.ErrorMessage(e)
		return
	}
	rows, e := p.session.Sends(p.vault)
	if e != nil {
		p.Status = vaultwarden.ErrorMessage(e)
		return
	}
	p.clearViews()
	p.Rows = rows
	p.Status = i18n.T("send.panel.status_offline")
}
func (p *Panel) New(kind int) {
	if p.Closed || p.Busy || p.session == nil {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = vaultwarden.ErrorMessage(e)
		return
	}
	d, e := p.session.NewSend(p.vault, kind)
	if e != nil {
		p.Status = vaultwarden.ErrorMessage(e)
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
		p.Status = vaultwarden.ErrorMessage(e)
		return
	}
	if e := p.form(); e != nil {
		p.Status = i18n.T("send.editor.err_invalid_dates")
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
		return Result{Draft: next, Err: e, changed: e == nil, message: i18n.T("send.editor.status_saved")}
	})
}
func (p *Panel) change(remove bool) {
	if p.Closed || p.Busy || p.Uncertain || p.Draft == nil || (remove && !p.confirmDelete) {
		return
	}
	if e := p.Host.Check(); e != nil {
		p.Status = vaultwarden.ErrorMessage(e)
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
		return Result{Err: e, changed: e == nil, message: i18n.T("send.editor.status_submitted")}
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
		return Result{Err: e, message: i18n.T("send.file.status_saved")}
	})
}
func (p *Panel) View(c *ui.Context) {
	ui.Column(c.Key("send-panel")).Gap(16).Children(func() {
		if p.Closed {
			kit.Notice(c, kit.ToneInfo, i18n.T("send.panel.status_closed"))
			return
		}
		disabled := p.Busy || p.Uncertain
		button := func(label string, kind kit.ButtonKind, off bool, f func()) {
			ui.Row(c).Children(func() {
				if kit.Button(c, label, "", kind, off).Clicked() {
					f()
				}
			})
		}
		ui.Row(c).Gap(8).Wrap().Children(func() {
			button(i18n.T("send.panel.refresh"), kit.ButtonSecondary, p.Busy || p.session == nil, p.Refresh)
			button(i18n.T("send.panel.offline_list"), kit.ButtonSecondary, p.Busy || p.session == nil, p.Offline)
			ui.Spacer(c)
			kit.Segmented(c.Key("send-new-kind"), &p.newKind, i18n.T("send.editor.text_type"), i18n.T("send.editor.file_type")).Width(160).Shrink(0).Disabled(p.Busy || p.session == nil)
			label := i18n.T("send.editor.new_text")
			if p.newKind == 1 {
				label = i18n.T("send.editor.new_file")
			}
			button(label, kit.ButtonPrimary, p.Busy || p.session == nil, func() { p.New(p.newKind) })
		})
		if p.Busy {
			kit.Notice(c, kit.ToneInfo, i18n.T("send.panel.status_processing"))
		}
		if p.Uncertain {
			kit.Notice(c, kit.ToneWarning, i18n.T("send.panel.status_uncertain"))
		}
		if p.Draft == nil && p.Receiver == nil {
			kit.Section(c, i18n.T("send.panel.list_title"), func() {
				if len(p.Rows) == 0 {
					kit.EmptyState(c, "inbox", i18n.T("send.panel.empty_title"), i18n.T("send.panel.empty_hint"))
				}
				for i, d := range p.Rows {
					index := i
					ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
						kit.Icon(c, "note", 20).TextColor(kit.Purple)
						ui.Column(c).Grow(1).MinWidth(0).Gap(4).Children(func() {
							ui.Text(c, d.Fields.Name).FontWeight(600).SingleLine()
							ui.Text(c, i18n.Tf("send.editor.access_count", d.AccessCount())).FontSize(12).TextColor(kit.Muted)
						})
						if d.Fields.Disabled {
							kit.Pill(c, i18n.T("send.panel.disabled"), kit.Panel, kit.Muted)
						} else {
							kit.Pill(c, i18n.T("send.panel.enabled"), kit.Selected, kit.Purple)
						}
						button(i18n.T("send.panel.open"), kit.ButtonQuiet, p.Busy, func() { p.openRow(index) })
					})
				}
			})
		}
		if p.Draft != nil {
			kit.Section(c, i18n.T("send.editor.content_title"), func() {
				sendInput(c, &p.Fields.Name, i18n.T("common.name")).Disabled(disabled)
				if p.Fields.Type == 0 {
					kit.Field(c, i18n.T("send.editor.shared_text"), "", func() {
						kit.Input(ui.TextArea(c, &p.Fields.Text).Label(i18n.T("send.editor.shared_text"))).Height(110).Disabled(disabled)
					})
					kit.Checkbox(c, &p.Fields.Hidden, i18n.T("send.editor.hidden_text"), disabled)
				} else {
					kit.Notice(c, kit.ToneInfo, i18n.T("send.file.edit_hint"))
					if p.Fields.FileName != "" {
						ui.Text(c, p.Fields.FileName)
					}
				}
				kit.Field(c, i18n.T("send.editor.private_notes"), "", func() {
					kit.Input(ui.TextArea(c, &p.Fields.Notes).Label(i18n.T("send.editor.private_notes"))).Height(70).Disabled(disabled)
				})
			})
			kit.Section(c, i18n.T("send.editor.access_title"), func() {
				sendInput(c, &p.Deletion, i18n.T("send.editor.deletion_date"), i18n.T("send.editor.deletion_date_hint")).Disabled(disabled)
				sendInput(c, &p.expiration, i18n.T("send.editor.expiration_date"), i18n.T("send.editor.expiration_date_hint")).Disabled(disabled)
				sendInput(c, &p.maxCount, i18n.T("send.editor.max_access_count"), i18n.T("send.editor.max_access_count_hint")).Disabled(disabled)
				sendInput(c, &p.Password, i18n.T("send.editor.password"), i18n.T("send.editor.password_hint")).Password().Disabled(disabled)
				kit.Checkbox(c, &p.Fields.Disabled, i18n.T("send.editor.disabled"), disabled)
				kit.Checkbox(c, &p.Fields.HideEmail, i18n.T("send.editor.hide_email"), disabled)
				kit.Notice(c, kit.ToneInfo, i18n.T("send.editor.email_verification_hint"))
			})
			kit.ActionBar(c, func() {
				ui.Spacer(c)
				button(i18n.T("send.editor.save"), kit.ButtonPrimary, disabled, p.Save)
			})
			if p.Draft.ID() != "" {
				ui.Text(c, i18n.Tf("send.editor.access_count", p.Draft.AccessCount()))
				button(i18n.T("send.editor.copy_link"), kit.ButtonQuiet, disabled || p.Host.Copy == nil, func() {
					if e := p.Host.Check(); e != nil {
						p.Status = vaultwarden.ErrorMessage(e)
						return
					}
					link, e := p.Draft.ShareLink()
					if e == nil {
						e = p.Host.Copy(link)
					}
					if e != nil {
						p.Status = vaultwarden.ErrorMessage(e)
					} else {
						p.Status = i18n.T("send.editor.status_link_copied")
					}
				})
				if p.Draft.HasPassword() {
					button(i18n.T("send.editor.remove_password"), kit.ButtonDanger, disabled, func() { p.confirmRemovePassword = true })
				}
				if p.confirmRemovePassword {
					kit.ConfirmDialog(c, "send-remove-password", i18n.T("send.editor.remove_password"), i18n.T("send.editor.remove_access_hint"), i18n.T("common.confirm"), i18n.T("common.cancel"), disabled,
						func() { p.change(false); p.confirmRemovePassword = false }, func() {
							if !p.Busy {
								p.confirmRemovePassword = false
							}
						})
				}
				if !p.confirmDelete {
					button(i18n.T("send.editor.delete"), kit.ButtonDanger, disabled, func() { p.confirmDelete = true })
				} else {
					kit.ConfirmDialog(c, "send-delete", i18n.T("send.editor.delete"), i18n.T("send.editor.confirm_delete_hint"), i18n.T("send.editor.confirm_delete"), i18n.T("send.editor.cancel_delete"), disabled,
						func() { p.change(true) }, func() {
							if !p.Busy {
								p.confirmDelete = false
							}
						})
				}
			}
		}
		kit.Section(c, i18n.T("send.receive.title"), func() {
			sendInput(c, &p.Link, i18n.T("send.receive.link")).Password().Disabled(p.Busy)
			sendInput(c, &p.ReceivePassword, i18n.T("send.receive.password")).Password().Disabled(p.Busy)
			ui.Row(c).Children(func() {
				button(i18n.T("send.receive.open_link"), kit.ButtonSecondary, p.Busy || p.Link == "", p.Receive)
			})
			if p.Receiver != nil {
				ui.Text(c, p.Fields.Name)
				if p.Fields.CreatorIdentifier != "" {
					ui.Text(c, i18n.Tf("send.receive.sender", p.Fields.CreatorIdentifier))
				}
				if p.Fields.Type == 0 {
					if p.Fields.Hidden && !p.showText {
						button(i18n.T("send.receive.show_text"), kit.ButtonQuiet, false, func() { p.showText = true })
					} else {
						ui.Text(c, p.Fields.Text).MaxLines(30)
					}
				} else {
					ui.Text(c, p.Fields.FileName)
					button(i18n.T("send.receive.save_file"), kit.ButtonPrimary, p.Busy, p.saveReceived)
				}
			}
		})
		kit.ActionBar(c, func() {
			ui.Text(c, p.Status).FontSize(12).TextColor(kit.Muted).Grow(1).MinWidth(0)
			button(i18n.T("send.panel.close"), kit.ButtonSecondary, false, p.Close)
		})
	})
}

func sendInput(c *ui.Context, value *string, label string, hints ...string) ui.Element {
	var input ui.Element
	hint := ""
	if len(hints) != 0 {
		hint = hints[0]
	}
	kit.Field(c, label, hint, func() { input = kit.Input(ui.TextInput(c, value).Label(label)) })
	return input
}
