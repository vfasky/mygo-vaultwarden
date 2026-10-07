// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestOrgEventsPanelPagingAndCancellation(t *testing.T) {
	queue := make(chan func(), 1)
	requests := make(chan vaultwarden.OrganizationEventQuery, 2)
	query := vaultwarden.OrganizationEventQuery{OrganizationID: "org-1", Start: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)}
	token := "2026-06-02T00:00:00Z"
	p := newOrgEventsPanel(query, func(ctx context.Context, q vaultwarden.OrganizationEventQuery) (vaultwarden.OrganizationEventPage, error) {
		requests <- q
		if q.ContinuationToken != "" {
			<-ctx.Done()
			return vaultwarden.OrganizationEventPage{}, vaultwarden.ErrCancelled
		}
		return vaultwarden.OrganizationEventPage{Data: []vaultwarden.OrganizationEvent{{Type: 9999, Date: token}}, ContinuationToken: &token}, nil
	}, func(f func()) { queue <- f })
	p.load(false)
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("no result")
	}
	if len(p.events) != 1 || p.next == nil || p.running {
		t.Fatal("page lost")
	}
	p.load(true)
	first := <-requests
	second := <-requests
	if first.ContinuationToken != "" || second.ContinuationToken != token || second.Start != first.Start || second.End != first.End {
		t.Fatal("page range changed")
	}
	p.Close()
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("no cancellation")
	}
	if len(p.events) != 0 || p.next != nil || p.status != "" {
		t.Fatal("late callback exposed data")
	}
}
