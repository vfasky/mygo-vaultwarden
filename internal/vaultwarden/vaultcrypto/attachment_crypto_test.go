// SPDX-License-Identifier: GPL-3.0-only
package vaultcrypto

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

func attachmentTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("open-file unlink guarantees exercised on Darwin/Linux")
	}
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func assertNoAttachmentFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool directory not empty: %v, %v", entries, err)
	}
}

func TestAttachmentSpoolUnlinkedAndClose(t *testing.T) {
	dir := attachmentTempDir(t)
	spool, err := newAttachmentSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	assertNoAttachmentFiles(t, dir)
	name := spool.File.Name()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("spool remains accessible by path: %v", err)
	}
	if _, err := spool.File.WriteString("public test content"); err != nil {
		t.Fatal(err)
	}
	if err := spool.Rewind(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(spool.File)
	if err != nil || string(got) != "public test content" {
		t.Fatalf("descriptor content: %q, %v", got, err)
	}
	// Closing the original descriptor must not delete a replacement pathname.
	if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	fd := spool.File
	spool.Close()
	spool.Close()
	if _, err := fd.Stat(); err == nil {
		t.Fatal("descriptor remains open")
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "replacement" {
		t.Fatalf("Close touched a replacement path: %q, %v", data, err)
	}
}

type attachmentObservedReader struct {
	r       io.Reader
	observe func()
}

func (r attachmentObservedReader) Read(p []byte) (int, error) {
	r.observe()
	return r.r.Read(p)
}

func TestAttachmentAnonymousRoundTripAndFailures(t *testing.T) {
	dir := attachmentTempDir(t)
	key := bytes.Repeat([]byte{42}, 64)
	content := bytes.Repeat([]byte("public fixture"), AttachmentBufferSize/5)
	observe := func() { assertNoAttachmentFiles(t, dir) }
	encrypted, err := EncryptAttachment(context.Background(), attachmentObservedReader{bytes.NewReader(content), observe}, int64(len(content)), key)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()
	ciphertext, err := io.ReadAll(encrypted.File)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptAttachment(context.Background(), attachmentObservedReader{bytes.NewReader(ciphertext), observe}, encrypted.Size, key)
	if err != nil {
		t.Fatal(err)
	}
	defer plaintext.Close()
	observe()
	got, err := io.ReadAll(plaintext.File)
	if err != nil || !bytes.Equal(got, content) || plaintext.Size != int64(len(content)) {
		t.Fatalf("round trip failed: %v", err)
	}
	badMAC := bytes.Clone(ciphertext)
	badMAC[17] ^= 1
	for _, tc := range []struct {
		name   string
		data   []byte
		cancel bool
		want   error
	}{
		{"bad MAC", badMAC, false, vaulterr.ErrEncryption},
		{"truncated", ciphertext[:len(ciphertext)-1], false, vaulterr.ErrEncryption},
		{"cancel after header", ciphertext, true, vaulterr.ErrCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			source := attachmentObservedReader{bytes.NewReader(tc.data), func() {
				observe()
				reads++
				if tc.cancel && reads == 2 {
					cancel()
				}
			}}
			spool, err := DecryptAttachment(ctx, source, encrypted.Size, key)
			if spool != nil {
				spool.Close()
				t.Fatal("failure exposed plaintext")
			}
			if err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			observe()
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spool, err := EncryptAttachment(ctx, attachmentObservedReader{bytes.NewReader(content), func() { observe(); cancel() }}, int64(len(content)), key)
	if spool != nil {
		spool.Close()
		t.Fatal("cancelled encryption returned spool")
	}
	if err != vaulterr.ErrCancelled {
		t.Fatalf("cancelled encryption: %v", err)
	}
	observe()
}

func TestAttachmentSpoolAbruptExit(t *testing.T) {
	if os.Getenv("MYGO_ATTACHMENT_CRASH_TEST") == "1" {
		spool, err := newAttachmentSpool()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spool.File.WriteString("public crash fixture"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Deliberately bypass Close and all deferred cleanup.
	}
	dir := attachmentTempDir(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestAttachmentSpoolAbruptExit$")
	cmd.Env = append(os.Environ(), "MYGO_ATTACHMENT_CRASH_TEST=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %s, %v", output, err)
	}
	assertNoAttachmentFiles(t, dir)
}

func TestAttachmentSpoolCreateFailure(t *testing.T) {
	dir := attachmentTempDir(t)
	t.Setenv("TMPDIR", filepath.Join(dir, "missing"))
	spool, err := newAttachmentSpool()
	if spool != nil || err != vaulterr.ErrEncryption {
		t.Fatalf("create failure: %v, %v", spool, err)
	}
}
