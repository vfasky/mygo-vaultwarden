// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInvitationUnknownWriteAndLockNeverReplayConsent(t *testing.T) {
	for _, lock := range []bool{false, true} {
		t.Run(map[bool]string{false: "server-failure", true: "lock-during-write"}[lock], func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/accounts/profile":
					writePendingInvitationProfile(w)
				case strings.HasSuffix(r.URL.Path, "/policies/token"):
					_, _ = w.Write([]byte(`{"data":[]}`))
				case strings.HasSuffix(r.URL.Path, "/accept"):
					writes.Add(1)
					close(entered)
					if lock {
						<-release
						return
					}
					w.WriteHeader(http.StatusServiceUnavailable)
				default:
					t.Error("unexpected path", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			defer close(release)
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			link := server.URL + "/#/accept-organization/?" + url.Values{"organizationId": {"new-org"}, "organizationUserId": {"new-member"}, "email": {s.email}, "token": {"fixture"}}.Encode()
			draft, err := s.PrepareInvitationAcceptance(ctx, v, link, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer draft.Close()
			result := make(chan error, 1)
			go func() { result <- s.AcceptPreparedInvitation(ctx, v, draft, false, "", nil) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if lock {
				s.Close()
			}
			err = <-result
			var unknown *MutationUncertainError
			if !errors.As(err, &unknown) {
				t.Fatal("write not classified unknown", err)
			}
			if err = s.AcceptPreparedInvitation(ctx, v, draft, false, "", nil); err != ErrExpired {
				t.Fatal("replayed uncertain consent", err)
			}
			if writes.Load() != 1 {
				t.Fatal("blind retry")
			}
		})
	}
}
