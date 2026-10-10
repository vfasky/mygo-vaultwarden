// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testKeys(t *testing.T) (*updates, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &updates{PublicKey: base64.StdEncoding.EncodeToString(pub), GitHub: "owner/repo", TagPrefix: "v"}, key
}

func fakeApp(t *testing.T) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "MyGo Vaultwarden.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "main"), []byte("executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("MacOS/main", filepath.Join(app, "Contents", "current")); err != nil {
		t.Fatal(err)
	}
	return app
}

func TestSignedArchiveAndManifest(t *testing.T) {
	u, key := testKeys(t)
	app, out := fakeApp(t), t.TempDir()
	files, err := generate(app, out, "0.1.0", "darwin-universal", "Release notes", u, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(files[1])
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	signature, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), digest[:], signature) {
		t.Fatal("invalid signature")
	}
	if m.Version != "0.1.0" || m.Notes != "Release notes" || m.Size != int64(len(archive)) || m.URL != "https://github.com/owner/repo/releases/download/v0.1.0/mygo-vaultwarden-0.1.0-darwin-universal.tar.gz" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	if _, err := time.Parse(time.RFC3339, m.Date); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 6 {
		t.Fatalf("unexpected manifest fields: %v", fields)
	}
	extracted := t.TempDir()
	extractCompatible(t, archive, extracted)
	roots, err := os.ReadDir(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0].Name() != filepath.Base(app) || !roots[0].IsDir() {
		t.Fatalf("unexpected roots: %v", roots)
	}
	executable := filepath.Join(extracted, filepath.Base(app), "Contents", "MacOS", "main")
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("lost executable permission: %v", info.Mode())
	}
	data, err = os.ReadFile(filepath.Join(extracted, filepath.Base(app), "Contents", "current"))
	if err != nil || string(data) != "executable" {
		t.Fatalf("symlink roundtrip: %q %v", data, err)
	}
	if _, err := generate(app, out, "0.1.0", "darwin-universal", "notes", u, key); err == nil {
		t.Fatal("overwrote existing release")
	}
}

// This test reader enforces MyGo ExtractArchive's path/type/mode rules and
// reconstructs the bundle, independently of the archive writer.
func extractCompatible(t *testing.T, data []byte, dir string) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := path.Clean(h.Name)
		if !fs.ValidPath(name) || name == "." || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Fatalf("invalid header: %+v", h)
		}
		destination := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if !strings.HasSuffix(h.Name, "/") {
				t.Fatal("missing directory slash")
			}
			err = os.MkdirAll(destination, 0o755)
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(destination), 0o755); err == nil {
				var file *os.File
				file, err = os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.FileMode(h.Mode).Perm()|0o200)
				if err == nil {
					_, err = io.Copy(file, tr)
					closeErr := file.Close()
					if err == nil {
						err = closeErr
					}
				}
			}
		case tar.TypeSymlink:
			if path.IsAbs(h.Linkname) || !fs.ValidPath(path.Join(path.Dir(name), h.Linkname)) {
				t.Fatal("escaping symlink")
			}
			if err = os.MkdirAll(filepath.Dir(destination), 0o755); err == nil {
				err = os.Symlink(h.Linkname, destination)
			}
		default:
			t.Fatalf("unsupported type: %d", h.Typeflag)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnsafeSymlinks(t *testing.T) {
	for _, link := range []string{"/etc/passwd", "../../outside", "../outside"} {
		t.Run(link, func(t *testing.T) {
			app := fakeApp(t)
			if err := os.Symlink(link, filepath.Join(app, "bad")); err != nil {
				t.Fatal(err)
			}
			if err := writeArchive(io.Discard, app); err == nil {
				t.Fatal("accepted escaping link")
			}
		})
	}
}

func TestArchiveRejectsUnsupportedAndUnsafeOutput(t *testing.T) {
	u, key := testKeys(t)
	app := fakeApp(t)
	inside := filepath.Join(app, "new-output")
	if _, err := generate(app, inside, "0.1.0", "darwin-arm64", "notes", u, key); err == nil {
		t.Fatal("accepted output inside bundle")
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		t.Fatal("invalid output modified bundle")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(app, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(app, filepath.Join(alias, "new-output"), "0.1.0", "darwin-arm64", "notes", u, key); err == nil {
		t.Fatal("accepted output through bundle symlink")
	}
	if err := syscall.Mkfifo(filepath.Join(app, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, err := generate(app, out, "0.1.0", "darwin-arm64", "notes", u, key); err == nil {
		t.Fatal("accepted FIFO")
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed archive left output: %v %v", entries, err)
	}
}

func TestReleaseNotes(t *testing.T) {
	for _, heading := range []string{"0.1.0", "v0.1.0", "[0.1.0] - 2026-01-01", "[0.1.0](https://example.com)"} {
		notes, err := releaseNotes("# Changes\r\n## 0.2.0\r\nNew\r\n## "+heading+"\r\n\r\n- Notes\r\n### Details\r\nText\r\n## 0.0.1\r\nOld", "0.1.0")
		if err != nil || notes != "- Notes\n### Details\nText" {
			t.Fatalf("%s: %q %v", heading, notes, err)
		}
	}
	for _, text := range []string{"## 0.1.1\nOther", "## 0.1.0\n\n## 0.0.1\nOld"} {
		if _, err := releaseNotes(text, "0.1.0"); err == nil {
			t.Fatal("accepted absent notes")
		}
	}
}

func TestConfigAndURLs(t *testing.T) {
	u, _ := testKeys(t)
	name := filepath.Join(t.TempDir(), "mygo.json")
	writeConfig := func(text string) {
		t.Helper()
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyEnv := func(string) (string, bool) { return "", false }
	writeConfig(`{"name":"App"}`)
	if c, err := loadConfig(name, emptyEnv); err != nil || c != nil {
		t.Fatalf("unconfigured: %+v %v", c, err)
	}
	writeConfig(`{"updates":{}}`)
	if _, err := loadConfig(name, emptyEnv); err == nil {
		t.Fatal("accepted empty configured updates")
	}
	writeConfig(`{"updates":{"publicKey":"` + u.PublicKey + `","github":"owner/repo"}}`)
	c, err := loadConfig(name, emptyEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.fileURL("update-darwin-arm64.json", "", true) != "https://github.com/owner/repo/releases/latest/download/update-darwin-arm64.json" {
		t.Fatal("latest URL")
	}
	overrides := map[string]string{"MYGO_UPDATE_GITHUB": "", "MYGO_UPDATE_URL": "https://example.com/downloads/", "MYGO_UPDATE_TAG_PREFIX": "app/"}
	c, err = loadConfig(name, func(k string) (string, bool) { v, ok := overrides[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if c.fileURL("archive name.tar.gz", "0.1.0", false) != "https://example.com/downloads/archive%20name.tar.gz" {
		t.Fatal("custom URL")
	}
	c.URL, c.GitHub = "", "owner/repo"
	if c.fileURL("update-darwin-arm64.json", "", true) != "https://github.com/owner/repo/releases/download/app%2F{version}/update-darwin-arm64.json" {
		t.Fatal("tagged feed")
	}
	if c.fileURL("a.tar.gz", "0.1.0", false) != "https://github.com/owner/repo/releases/download/app%2F0.1.0/a.tar.gz" {
		t.Fatal("tagged archive")
	}
	for _, change := range []func(*updates){
		func(u *updates) { u.PublicKey = "bad" }, func(u *updates) { u.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		func(u *updates) { u.URL = "https://example.com" }, func(u *updates) { u.GitHub = "" },
		func(u *updates) { u.GitHub = "/repo" }, func(u *updates) { u.GitHub = "owner/" }, func(u *updates) { u.GitHub = "owner/repo/extra" },
		func(u *updates) { u.GitHub = ""; u.URL = "http://example.com" }, func(u *updates) { u.GitHub = ""; u.URL = "https:///missing" },
		func(u *updates) { u.GitHub = ""; u.URL = "https://example.com?query=1" },
	} {
		invalid := *u
		change(&invalid)
		if err := invalid.validate(); err == nil {
			t.Fatalf("accepted invalid config: %+v", invalid)
		}
	}
}

func TestSigningKey(t *testing.T) {
	u, key := testKeys(t)
	t.Setenv("MYGO_UPDATER_PRIVATE_KEY", base64.StdEncoding.EncodeToString(key))
	got, err := u.signingKey("mygo.json")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("key: %v", err)
	}
	_, other := testKeys(t)
	t.Setenv("MYGO_UPDATER_PRIVATE_KEY", base64.StdEncoding.EncodeToString(other))
	if _, err := u.signingKey("mygo.json"); err == nil {
		t.Fatal("accepted mismatched key")
	}
	damaged := append([]byte(nil), key...)
	damaged[0] ^= 1
	t.Setenv("MYGO_UPDATER_PRIVATE_KEY", base64.StdEncoding.EncodeToString(damaged))
	if _, err := u.signingKey("mygo.json"); err == nil {
		t.Fatal("accepted inconsistent seed")
	}
	t.Setenv("MYGO_UPDATER_PRIVATE_KEY", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "private.key"), []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	u.PrivateKey = "private.key"
	if _, err := u.signingKey(filepath.Join(dir, "mygo.json")); err != nil {
		t.Fatal(err)
	}
}

func TestDetectTarget(t *testing.T) {
	// Minimal 64-bit Mach-O headers: magic, CPU, subtype, executable, no loads.
	thin := func(cpu uint32) []byte {
		var b bytes.Buffer
		for _, value := range []uint32{0xfeedfacf, cpu, 0, 2, 0, 0, 0, 0} {
			if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
				t.Fatal(err)
			}
		}
		return b.Bytes()
	}
	arm, amd := thin(0x100000c), thin(0x1000007)
	var fat bytes.Buffer
	for _, value := range []uint32{0xcafebabe, 2, 0x100000c, 0, 48, 32, 0, 0x1000007, 0, 80, 32, 0} {
		if err := binary.Write(&fat, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	fat.Write(arm)
	fat.Write(amd)
	for _, test := range []struct {
		data []byte
		want string
	}{{arm, "darwin-arm64"}, {amd, "darwin-amd64"}, {fat.Bytes(), "darwin-universal"}, {thin(7), ""}, {[]byte("not macho"), ""}} {
		name := filepath.Join(t.TempDir(), "main")
		if err := os.WriteFile(name, test.data, 0o755); err != nil {
			t.Fatal(err)
		}
		got, err := detectTarget(name)
		if got != test.want || (err == nil) != (test.want != "") {
			t.Fatalf("got %q %v, want %q", got, err, test.want)
		}
	}
}
