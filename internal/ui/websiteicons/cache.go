// SPDX-License-Identifier: GPL-3.0-only
// Package websiteicons loads display-only icons from the configured vault server.
package websiteicons

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"golang.org/x/image/draw"
	"golang.org/x/net/idna"
)

const (
	maxBytes   = 1 << 20
	maxEntries = 512
	cacheTTL   = 7 * 24 * time.Hour
	failureTTL = time.Hour
)

type entry struct {
	bitmap  *ui.Bitmap
	expires time.Time
	pending bool
}

// Cache is scoped to one server/account and one unlocked UI lifetime. Disk
// entries contain only normalized PNGs; filenames hash the scope and hostname.
// No vault token, cookies, full website URL or credential is sent or persisted.
type Cache struct {
	mu                       sync.Mutex
	entries                  map[string]entry
	server, scope, directory string
	client                   *http.Client
	ctx                      context.Context
	cancel                   context.CancelFunc
	slots                    chan struct{}
	closed                   bool
}

func New(server, account, directory string) *Cache {
	canonical, err := vaultwarden.CanonicalServer(server)
	if err != nil || account == "" {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 4
	transport.ResponseHeaderTimeout = 5 * time.Second
	return &Cache{
		server: canonical, scope: canonical + "\x00" + account, directory: directory,
		entries: make(map[string]entry), ctx: ctx, cancel: cancel, slots: make(chan struct{}, 4),
		client: &http.Client{Transport: transport, Timeout: 8 * time.Second,
			// A server configured with an external icon redirect falls back locally;
			// never disclose vault domains to an additional origin implicitly.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Host accepts public HTTP(S) domain names only, never userinfo, local names or
// IP literals. Only the hostname is forwarded to the vault's icon endpoint.
func Host(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	host, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")))
	if err != nil || len(host) > 253 || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".lan", ".home", ".invalid", ".test", ".example"} {
		if strings.HasSuffix(host, suffix) {
			return ""
		}
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	// Reject legacy numeric IPv4 forms as well as dotted IP literals.
	last := host[strings.LastIndexByte(host, '.')+1:]
	if strings.Trim(last, "0123456789") == "" {
		return ""
	}
	return host
}

// Lookup never blocks the UI on disk/network. Only visible rows call it;
// requests are deduplicated and at most four loads run concurrently.
func (c *Cache) Lookup(raw string, invalidate func()) *ui.Bitmap {
	if c == nil {
		return nil
	}
	host := Host(raw)
	if host == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if e, ok := c.entries[host]; ok && (e.pending || time.Now().Before(e.expires)) {
		return e.bitmap
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return nil
	}
	if len(c.entries) >= maxEntries {
		var oldest string
		var expiry time.Time
		for key, e := range c.entries {
			if !e.pending && (oldest == "" || e.expires.Before(expiry)) {
				oldest, expiry = key, e.expires
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[host] = entry{pending: true}
	go func() {
		bitmap := c.load(host)
		ttl := cacheTTL
		if bitmap == nil {
			ttl = failureTTL
		}
		c.mu.Lock()
		active := !c.closed
		if active {
			c.entries[host] = entry{bitmap: bitmap, expires: time.Now().Add(ttl)}
		}
		<-c.slots
		c.mu.Unlock()
		if active && invalidate != nil {
			invalidate()
		}
	}()
	return nil
}

func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	clear(c.entries)
	c.cancel()
	c.mu.Unlock()
	c.client.CloseIdleConnections()
}

func (c *Cache) path(host string) string {
	return filepath.Join(c.directory, fmt.Sprintf("%x.png", sha256.Sum256([]byte(c.scope+"\x00"+host))))
}

func (c *Cache) load(host string) *ui.Bitmap {
	if c.directory != "" {
		path := c.path(host)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Size() <= maxBytes && time.Since(info.ModTime()) < cacheTTL {
			if data, err := os.ReadFile(path); err == nil {
				if img, err := decode(data); err == nil {
					return ui.NewBitmap(img)
				}
			}
		}
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.server+"/icons/"+host+"/icon.png", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "image/png,image/x-icon,image/webp,image/*;q=0.8")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxBytes {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil
	}
	img, err := decode(data)
	if err != nil {
		return nil
	}
	// Save the decoded, bounded image rather than arbitrary server bytes.
	var normalized bytes.Buffer
	if png.Encode(&normalized, img) == nil && c.directory != "" && c.ctx.Err() == nil {
		c.save(host, normalized.Bytes())
	}
	return ui.NewBitmap(img)
}

func decode(data []byte) (image.Image, error) {
	if len(data) > maxBytes {
		return nil, fmt.Errorf("icon too large")
	}
	var img image.Image
	var err error
	if len(data) >= 6 && bytes.Equal(data[:4], []byte{0, 0, 1, 0}) {
		img, err = decodeICO(data)
	} else {
		var config image.Config
		config, _, err = image.DecodeConfig(bytes.NewReader(data))
		if err == nil && (config.Width < 1 || config.Height < 1 || config.Width > 1024 || config.Height > 1024) {
			err = fmt.Errorf("icon dimensions too large")
		}
		if err == nil {
			img, _, err = image.Decode(bytes.NewReader(data))
		}
	}
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w > 128 || h > 128 {
		scale := 128.0 / float64(max(w, h))
		dst := image.NewNRGBA(image.Rect(0, 0, max(1, int(float64(w)*scale)), max(1, int(float64(h)*scale))))
		draw.CatmullRom.Scale(dst, dst.Bounds(), img, bounds, draw.Src, nil)
		img = dst
	}
	return img, nil
}

func (c *Cache) save(host string, data []byte) {
	if os.MkdirAll(c.directory, 0700) != nil {
		return
	}
	f, err := os.CreateTemp(c.directory, ".icon-*")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil || c.ctx.Err() != nil {
		return
	}
	if os.Rename(f.Name(), c.path(host)) != nil {
		return
	}
	// Bound persistent storage across accounts as well as the in-memory cache.
	files, _ := os.ReadDir(c.directory)
	type cached struct {
		name     string
		modified time.Time
	}
	var rows []cached
	for _, file := range files {
		if len(file.Name()) != 68 || !strings.HasSuffix(file.Name(), ".png") {
			continue
		}
		if info, err := file.Info(); err == nil && info.Mode().IsRegular() {
			rows = append(rows, cached{file.Name(), info.ModTime()})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].modified.After(rows[j].modified) })
	for i, row := range rows {
		if i >= maxEntries*2 || time.Since(row.modified) >= cacheTTL {
			_ = os.Remove(filepath.Join(c.directory, row.name))
		}
	}
}
