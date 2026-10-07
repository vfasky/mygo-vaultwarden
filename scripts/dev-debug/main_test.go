// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func put(t *testing.T, root, name, text string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintInputsAndGeneratedOutputs(t *testing.T) {
	root := t.TempDir()
	sum := func() [32]byte {
		t.Helper()
		s, err := fingerprint(root)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	previous := sum()
	for _, name := range []string{"ui.go", "internal/vault/client.go", "go.mod", "resources/logo.png", "macos/Bridge/SnapshotBridge.swift", "macos/App/AppIcon.icns", "macos/App/App.entitlements", "scripts/build-macos.sh", ".local/signing.env"} {
		put(t, root, name, "changed")
		next := sum()
		if next == previous {
			t.Fatalf("did not watch %s", name)
		}
		previous = next
	}
	for _, name := range []string{"build/debug/app.go", "macos/.build/output.swift", "macos/project.xcodeproj/xcuserdata/state.plist", ".mygo/dev/app.go", "README.md", "scripts/dev-debug/main.go"} {
		put(t, root, name, "generated")
		if sum() != previous {
			t.Fatalf("watched generated/unrelated file %s", name)
		}
	}
	if err := os.Remove(filepath.Join(root, "ui.go")); err != nil {
		t.Fatal(err)
	}
	if sum() == previous {
		t.Fatal("missed deletion")
	}
}

// Exercise restart/cleanup against a real subprocess, without accessing a vault.
func TestWatcherProcess(t *testing.T) {
	if os.Getenv("VAULTWARDEN_WATCH_TEST") != "1" {
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

type messages chan string

func (m messages) Write(p []byte) (int, error) {
	m <- string(p)
	return len(p), nil
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for watcher")
		var zero T
		return zero
	}
}

func readyPID(t *testing.T, logs messages) int {
	t.Helper()
	for {
		line := receive(t, (<-chan string)(logs))
		if _, suffix, ok := strings.Cut(line, "PID="); ok {
			pid, err := strconv.Atoi(strings.SplitN(suffix, "；", 2)[0])
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
	}
}

func TestWatchRetainsAppOnFailureAndBuildsLatestBeforeRestart(t *testing.T) {
	root := t.TempDir()
	put(t, root, "ui.go", "first")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	appPath := filepath.Join(root, "app")
	quotedBinary := "'" + strings.ReplaceAll(binary, "'", "'\\''") + "'"
	put(t, root, "app", "#!/bin/sh\nVAULTWARDEN_WATCH_TEST=1 exec "+quotedBinary+" -test.run=^TestWatcherProcess$\n")
	if err := os.Chmod(appPath, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 10)
	complete := make(chan error)
	installed := make(chan struct{}, 10)
	logs := make(messages, 100)
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, root, appPath, os.Stdout, log.New(logs, "", 0), func(ctx context.Context) error {
			started <- struct{}{}
			select {
			case err := <-complete:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		}, func(_ context.Context, launch bool) error {
			if launch {
				return fmt.Errorf("installer must not launch independently")
			}
			installed <- struct{}{}
			return nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("watcher exited unexpectedly: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("watcher did not settle")
		}
	})
	receive(t, (<-chan struct{})(started))
	complete <- nil
	receive(t, (<-chan struct{})(installed))
	firstPID := readyPID(t, logs)

	put(t, root, "ui.go", "compile error")
	receive(t, (<-chan struct{})(started))
	complete <- errors.New("deliberate compile failure")
	for !strings.Contains(receive(t, (<-chan string)(logs)), "构建失败") {
	}
	if err := syscall.Kill(firstPID, 0); err != nil {
		t.Fatal("compile failure stopped running app", err)
	}
	select {
	case <-installed:
		t.Fatal("installed a failed build")
	default:
	}

	put(t, root, "ui.go", "fixed")
	receive(t, (<-chan struct{})(started))
	put(t, root, "ui.go", "newer edit during build")
	complete <- nil
	receive(t, (<-chan struct{})(started)) // queued build for the newest edit
	if err := syscall.Kill(firstPID, 0); err != nil {
		t.Fatal("stale build stopped running app", err)
	}
	select {
	case <-installed:
		t.Fatal("installed a stale build")
	default:
	}
	complete <- nil
	receive(t, (<-chan struct{})(installed))
	secondPID := readyPID(t, logs)
	if secondPID == firstPID || syscall.Kill(firstPID, 0) == nil {
		t.Fatal("old app still running after reload")
	}

	// Cancel during a subsequent build: both build and owned app must settle.
	put(t, root, "ui.go", "cancel while building")
	receive(t, (<-chan struct{})(started))
	cancel()
	err = receive(t, (<-chan error)(done))
	done <- err // leave the settled result for Cleanup
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation result: %v", err)
	}
	if syscall.Kill(secondPID, 0) == nil {
		t.Fatal("owned app survived watcher cancellation")
	}
}
