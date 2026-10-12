// SPDX-License-Identifier: GPL-3.0-only
package websiteicons

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func iconPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	img.SetNRGBA(2, 3, color.NRGBA{R: 230, G: 30, B: 70, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func waitIcon(t *testing.T, c *Cache, raw string) {
	t.Helper()
	done := make(chan struct{}, 1)
	if c.Lookup(raw, func() { done <- struct{}{} }) != nil {
		return
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("icon load timed out")
	}
}

func TestHost(t *testing.T) {
	for raw, want := range map[string]string{
		"https://GitHub.com/login?secret=hidden#fragment": "github.com",
		"https://例子.com:8443/path":                        "xn--fsqu00a.com",
		"http://www.example.org./":                        "www.example.org",
		"https://192.168.8.40":                            "", "http://127.1": "", "http://[::1]": "",
		"https://localhost": "", "https://vault.local": "", "https://router.lan": "",
		"https://demo.invalid": "", "https://private.internal": "",
		"https://user:password@example.org": "", "androidapp://com.example.app": "",
		"javascript:alert(1)": "", "example.org": "", "https://a..com": "",
		"https://-a.com": "", "https://foo_bar.com": "", "": "",
	} {
		t.Run(raw, func(t *testing.T) {
			if got := Host(raw); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestFetchDedupPersistenceAndAccountIsolation(t *testing.T) {
	data := iconPNG(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.RequestURI() != "/vault/icons/github.com/icon.png" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" {
			t.Errorf("unexpected request: %s", r.URL.RequestURI())
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	directory := t.TempDir()
	c := New(server.URL+"/vault", "account-one", directory)
	defer c.Close()
	raw := "https://github.com/secret/path?token=never-send"
	waitIcon(t, c, raw)
	if c.Lookup(raw, nil) == nil {
		t.Fatal("missing fetched bitmap")
	}
	for i := 0; i < 10; i++ {
		c.Lookup("https://github.com/another/path", nil)
	}
	if requests.Load() != 1 {
		t.Fatal("request was not deduplicated")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("cache files: %v %v", files, err)
	}
	info, _ := files[0].Info()
	if info.Mode().Perm() != 0600 || strings.Contains(files[0].Name(), "github") {
		t.Fatal("cache mode or filename")
	}
	cached, _ := os.ReadFile(filepath.Join(directory, files[0].Name()))
	if !bytes.HasPrefix(cached, []byte("\x89PNG")) || bytes.Contains(cached, []byte("secret")) {
		t.Fatal("cache is not image-only PNG")
	}
	c.Close()
	reopened := New(server.URL+"/vault", "account-one", directory)
	defer reopened.Close()
	waitIcon(t, reopened, raw)
	if reopened.Lookup(raw, nil) == nil || requests.Load() != 1 {
		t.Fatal("disk cache not reused")
	}
	other := New(server.URL+"/vault", "account-two", directory)
	defer other.Close()
	waitIcon(t, other, raw)
	if requests.Load() != 2 {
		t.Fatal("account caches were shared")
	}
}

func TestFailureBackoffRedirectAndCorruptCache(t *testing.T) {
	data := iconPNG(t)
	var requests, redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); _, _ = w.Write(data) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/icons/redirect.org/icon.png":
			http.Redirect(w, r, destination.URL, http.StatusFound)
		case "/icons/corrupt.org/icon.png":
			_, _ = w.Write(data)
		case "/icons/large.org/icon.png":
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, maxBytes+1))
		default:
			_, _ = w.Write([]byte("<html>not an icon</html>"))
		}
	}))
	defer server.Close()
	c := New(server.URL, "account", t.TempDir())
	defer c.Close()
	for _, host := range []string{"redirect.org", "html.org", "large.org"} {
		raw := "https://" + host
		waitIcon(t, c, raw)
		if c.Lookup(raw, nil) != nil {
			t.Fatal("invalid response displayed")
		}
	}
	if requests.Load() != 3 || redirected.Load() != 0 {
		t.Fatal("failure repeated or redirect followed")
	}
	if err := os.WriteFile(c.path("corrupt.org"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	waitIcon(t, c, "https://corrupt.org")
	if c.Lookup("https://corrupt.org", nil) == nil {
		t.Fatal("corrupt cache did not recover")
	}
}

func TestExpiredCacheRefetched(t *testing.T) {
	data := iconPNG(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(data) }))
	defer server.Close()
	c := New(server.URL, "account", t.TempDir())
	defer c.Close()
	path := c.path("github.com")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-cacheTTL - time.Hour)
	if err := os.Chtimes(path, expired, expired); err != nil {
		t.Fatal(err)
	}
	waitIcon(t, c, "https://github.com")
	if requests.Load() != 1 || c.Lookup("https://github.com", nil) == nil {
		t.Fatal("expired cache not replaced")
	}
}

func TestCloseCancelsAndBoundsConcurrentRequests(t *testing.T) {
	started := make(chan struct{}, 4)
	stopped := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		stopped <- struct{}{}
	}))
	defer server.Close()
	c := New(server.URL, "account", t.TempDir())
	defer c.Close()
	var callbacks atomic.Int32
	for _, raw := range []string{"https://one.org", "https://two.org", "https://three.org", "https://four.org", "https://five.org"} {
		c.Lookup(raw, func() { callbacks.Add(1) })
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("request did not start")
		}
	}
	c.mu.Lock()
	if len(c.entries) != 4 {
		t.Error("more than four loads queued")
	}
	c.mu.Unlock()
	c.Close()
	for i := 0; i < 4; i++ {
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatal("request not cancelled")
		}
	}
	if c.Lookup("https://six.org", nil) != nil || callbacks.Load() != 0 {
		t.Fatal("closed cache published a result")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 0 {
		t.Fatal("closed cache retained images")
	}
}

func TestDecodePNGAndICO(t *testing.T) {
	pngData := iconPNG(t)
	wrap := func(frame []byte) []byte {
		ico := make([]byte, 22)
		copy(ico, []byte{0, 0, 1, 0, 1, 0, 32, 32})
		binary.LittleEndian.PutUint32(ico[14:18], uint32(len(frame)))
		binary.LittleEndian.PutUint32(ico[18:22], 22)
		return append(ico, frame...)
	}
	for _, data := range [][]byte{pngData, wrap(pngData)} {
		img, err := decode(data)
		if err != nil || img.Bounds().Dx() != 32 {
			t.Fatalf("decode: %v", err)
		}
	}
	// One opaque and one transparent pixel, bottom-up 32-bit DIB plus AND mask.
	dib := make([]byte, 40+8+4)
	binary.LittleEndian.PutUint32(dib[:4], 40)
	binary.LittleEndian.PutUint32(dib[4:8], 2)
	binary.LittleEndian.PutUint32(dib[8:12], 2)
	binary.LittleEndian.PutUint16(dib[12:14], 1)
	binary.LittleEndian.PutUint16(dib[14:16], 32)
	copy(dib[40:48], []byte{30, 20, 10, 255, 80, 70, 60, 255})
	dib[48] = 0x40
	img, err := decode(wrap(dib))
	if err != nil {
		t.Fatal(err)
	}
	if got := color.NRGBAModel.Convert(img.At(0, 0)).(color.NRGBA); got != (color.NRGBA{R: 10, G: 20, B: 30, A: 255}) {
		t.Fatal(got)
	}
	if _, _, _, a := img.At(1, 0).RGBA(); a != 0 {
		t.Fatal("ICO mask lost")
	}
	for _, bad := range [][]byte{nil, []byte("html"), {0, 0, 1, 0, 255, 255}, wrap([]byte("bad frame")), bytes.Repeat([]byte{0}, maxBytes+1)} {
		if _, err := decode(bad); err == nil {
			t.Fatal("malformed image accepted")
		}
	}
	var large bytes.Buffer
	_ = png.Encode(&large, image.NewNRGBA(image.Rect(0, 0, 2048, 1)))
	if _, err := decode(large.Bytes()); err == nil {
		t.Fatal("excessive dimensions accepted")
	}
	large.Reset()
	_ = png.Encode(&large, image.NewNRGBA(image.Rect(0, 0, 256, 128)))
	img, err = decode(large.Bytes())
	if err != nil || img.Bounds().Dx() != 128 || img.Bounds().Dy() != 64 {
		t.Fatal("image not proportionally bounded")
	}
}
