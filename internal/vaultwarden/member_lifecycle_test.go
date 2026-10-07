// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestMemberManagementCheckpointAndSelfRoleIsolationFailClosed(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); writeMembers(w, memberRows()) }))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = acceptedGroupsVault(t, s, ownerVault(t, v))
	s.checkpointPending = true
	storageFailure := errors.New("storage failed")
	if _, err := s.OrganizationMembers(context.Background(), v, "org-1", func(SessionCheckpoint) error { return storageFailure }); !errors.Is(err, storageFailure) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("checkpoint failure made HTTP")
	}
	s.checkpointPending = false
	installFixtureSnapshot(t, s, v, "revision-1")
	directory := &MemberDirectory{scope: v.Scope, organizationID: "org-1", revision: s.authorizationRevision, rows: memberRows()}
	draft := &MemberRoleDraft{Role: 2, directory: directory, member: memberRows()[0]}
	if err := s.SaveMemberRole(context.Background(), v, draft, nil, nil, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if err := s.SaveMemberRole(context.Background(), v, draft, nil, func(SessionCheckpoint) error { return errors.New("disk") }, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("self downgrade before durable isolation")
	}
}
func TestMemberMutationCloseAfterDispatchIsUncertainAndNeverRetried(t *testing.T) {
	dispatched, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeMembers(w, memberRows())
			return
		}
		writes.Add(1)
		close(dispatched)
		<-release
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	v = acceptedOwnerVault(t, s, v)
	directory, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- s.ChangeOrganizationMember(context.Background(), v, directory, "member-2", "remove", nil, nil)
	}()
	<-dispatched
	s.Close()
	close(release)
	err = <-result
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || writes.Load() != 1 {
		t.Fatal(err, writes.Load())
	}
}
