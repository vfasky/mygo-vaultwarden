// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"context"
	"errors"
	"testing"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestExportDialogExplicitDirectoryGrant(t *testing.T) {
	path, err := chooseExportPath(context.Background(), mygo.SaveDialogOptions{},
		func(mygo.SaveDialogOptions) (string, error) { return "/first/fixture.json", nil },
		func(opts mygo.OpenDialogOptions) ([]string, error) {
			if !opts.Directory || opts.Multiple || opts.DefaultPath != "/first" {
				t.Fatal("missing directory grant request", opts)
			}
			return []string{"/selected"}, nil
		})
	if err != nil || path != "/selected/fixture.json" {
		t.Fatal(path, err)
	}
}

func TestExportDialogCancelAndFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		selected []string
		failure  error
		cancel   bool
		want     error
	}{
		{name: "cancel", want: vaultwarden.ErrCancelled},
		{name: "error", failure: errors.New("panel failed"), want: vaultwarden.ErrPermission},
		{name: "invalid", selected: []string{"relative"}, want: vaultwarden.ErrValidation},
		{name: "lock", selected: []string{"/selected"}, cancel: true, want: vaultwarden.ErrCancelled},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path, err := chooseExportPath(ctx, mygo.SaveDialogOptions{}, func(mygo.SaveDialogOptions) (string, error) { return "/first/new", nil }, func(mygo.OpenDialogOptions) ([]string, error) {
				if test.cancel {
					cancel()
				}
				return test.selected, test.failure
			})
			if path != "" || !errors.Is(err, test.want) {
				t.Fatal(path, err)
			}
		})
	}
}

func TestExportDialogDoesNotAskForDirectoryAfterSaveCancellation(t *testing.T) {
	_, err := chooseExportPath(context.Background(), mygo.SaveDialogOptions{}, func(mygo.SaveDialogOptions) (string, error) { return "", nil }, func(mygo.OpenDialogOptions) ([]string, error) { t.Fatal("unexpected directory panel"); return nil, nil })
	if !errors.Is(err, vaultwarden.ErrCancelled) {
		t.Fatal(err)
	}
}
