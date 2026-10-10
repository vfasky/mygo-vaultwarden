// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// orgEventsPanel runs entirely through injected session-bound dependencies. The
// host chooses an organization/member/cipher from its authenticated business
// lists, then closes this panel on lock, sync or scope change.
type orgEventsPanel struct {
	query                      vaultwarden.OrganizationEventQuery
	startDate, endDate, status string
	events                     []vaultwarden.OrganizationEvent
	next                       *string
	running, closed            bool
	generation                 uint64
	cancel                     context.CancelFunc
	fetch                      func(context.Context, vaultwarden.OrganizationEventQuery) (vaultwarden.OrganizationEventPage, error)
	dispatch                   func(func())
	busy                       func(bool)
}

func newOrgEventsPanel(query vaultwarden.OrganizationEventQuery, fetch func(context.Context, vaultwarden.OrganizationEventQuery) (vaultwarden.OrganizationEventPage, error), dispatch func(func())) *orgEventsPanel {
	return &orgEventsPanel{query: query, startDate: query.Start.Format(time.RFC3339), endDate: query.End.Format(time.RFC3339), fetch: fetch, dispatch: dispatch}
}
func (p *orgEventsPanel) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.closed = true
	p.generation++
	p.events = nil
	p.next = nil
	p.status = ""
}
func (p *orgEventsPanel) load(next bool) {
	if p.closed || p.running || p.fetch == nil || p.dispatch == nil {
		return
	}
	query := p.query
	if next {
		if p.next == nil {
			return
		}
		query.ContinuationToken = *p.next
	} else {
		var err error
		query.Start, err = time.Parse(time.RFC3339, p.startDate)
		if err != nil {
			p.status = "请输入包含时区的开始日期，例如 2026-06-01T00:00:00Z"
			return
		}
		query.End, err = time.Parse(time.RFC3339, p.endDate)
		if err != nil || query.Start.After(query.End) {
			p.status = "结束时间必须不早于开始时间"
			return
		}
		query.ContinuationToken = ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	if p.busy != nil {
		p.busy(true)
	}
	p.status = "正在读取审计事件…"
	generation := p.generation
	fetch, dispatch := p.fetch, p.dispatch
	go func() {
		page, err := fetch(ctx, query)
		cancel()
		dispatch(func() {
			if p.busy != nil {
				p.busy(false)
			}
			if p.closed || p.generation != generation {
				return
			}
			p.running = false
			p.cancel = nil
			if err != nil {
				p.status = "读取失败：" + err.Error()
				return
			}
			if !next {
				p.events = nil
			}
			p.events = append(p.events, page.Data...)
			p.next = page.ContinuationToken
			p.query = query
			p.status = fmt.Sprintf("已加载 %d 条事件；空列表也可能表示服务器未启用审计。", len(p.events))
		})
	}()
}
func (p *orgEventsPanel) View(c *ui.Context) {
	if p.closed {
		return
	}
	ui.Text(c, "组织审计事件").FontSize(22)
	ui.TextInput(c, &p.startDate).Label("开始时间（含时区）").Disabled(p.running)
	ui.TextInput(c, &p.endDate).Label("结束时间（含时区）").Disabled(p.running)
	if action(c, "读取事件", "", true, p.running || p.fetch == nil || p.dispatch == nil).Key("org-events-load").Clicked() {
		p.load(false)
	}
	for i, event := range p.events {
		// Unknown event type numbers stay visible instead of being mislabeled.
		ui.Text(c, fmt.Sprintf("%d. %s · 事件 %d", i+1, event.Date, event.Type))
		if event.ActingUserID != nil {
			ui.Text(c, "操作账号："+*event.ActingUserID)
		}
		if event.OrganizationUserID != nil {
			ui.Text(c, "组织成员："+*event.OrganizationUserID)
		}
		if event.CipherID != nil {
			ui.Text(c, "条目："+*event.CipherID)
		}
	}
	if action(c, "加载下一页", "", false, p.running || p.next == nil).Key("org-events-next").Clicked() {
		p.load(true)
	}
	if p.running && action(c, "取消读取", "", false, false).Key("org-events-cancel").Clicked() {
		if p.cancel != nil {
			p.cancel()
		}
	}
	if p.status != "" {
		ui.Text(c, p.status)
	}
}
