// SPDX-License-Identifier: GPL-3.0-only

// Package i18n localizes user-visible text in Simplified Chinese and
// English. Text is looked up by a semantic key such as "app.sidebar.items";
// each catalog file in this package defines the Chinese and English text of
// the keys of one area side by side. The language follows the system's
// preferred languages and is selected at startup before other packages
// initialize. MessageError stores only a key and translates when displayed,
// keeping sentinel identity independent of the active language.
//
//	ui.Text(c, i18n.T("common.save"))
//	status = i18n.Tf("app.sync.done", n)
//	err = i18n.Error("file.backup.err_unsafe_access")
//
// Keys name text, never program state: compare, persist and send stable
// identifiers, and translate them only where they are shown.
package i18n

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// Lang is a supported user interface language.
type Lang string

const (
	Chinese Lang = "zh-Hans"
	English Lang = "en"
)

// EnvLanguage overrides the system language with "zh" or "en".
const EnvLanguage = "MYGO_VAULTWARDEN_LANG"

var current atomic.Value // Lang

func init() { current.Store(detect()) }

func detect() Lang {
	if l, ok := parse(os.Getenv(EnvLanguage)); ok {
		return l
	}
	// Tests assert the Chinese text unless they choose a language.
	if testing.Testing() {
		return Chinese
	}
	return Match(preferredLanguages())
}

// Match returns the first supported language in a list of BCP 47 tags in
// order of preference, such as NSLocale.preferredLanguages, and English when
// none is supported.
func Match(tags []string) Lang {
	for _, tag := range tags {
		if l, ok := parse(tag); ok {
			return l
		}
	}
	return English
}

func parse(tag string) (Lang, bool) {
	tag = strings.ToLower(strings.TrimSpace(tag))
	switch {
	case tag == "zh" || strings.HasPrefix(tag, "zh-") || strings.HasPrefix(tag, "zh_"):
		return Chinese, true
	case tag == "en" || strings.HasPrefix(tag, "en-") || strings.HasPrefix(tag, "en_"):
		return English, true
	}
	return "", false
}

// Current returns the active language.
func Current() Lang { return current.Load().(Lang) }

// Set changes the active language. Text built before the change, including
// package-level values, keeps its language; use it in tests and at startup.
func Set(l Lang) {
	if l != Chinese && l != English {
		panic("i18n: unsupported language " + string(l))
	}
	current.Store(l)
}

// T returns the text of key in the active language. An unknown key is
// returned as is, so it shows up in the interface instead of failing; the
// catalog test rejects unknown keys.
func T(key string) string {
	if m, ok := messages[key]; ok {
		if Current() == English {
			return m.en
		}
		return m.zh
	}
	return key
}

// Tf formats the text of key with args as fmt.Sprintf does. Use %[n]v
// verbs where the languages order the arguments differently.
func Tf(key string, args ...any) string {
	return fmt.Sprintf(T(key), args...)
}

// text is one message in both languages.
type text struct{ zh, en string }

var (
	messages = map[string]text{}
	areas    = map[string]bool{}
	keyRe    = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+(_[a-z0-9]+)*)+$`)
)

// register adds the messages of an area, such as "app" or "org.member";
// every key must start with the area and a dot. Each catalog file registers
// its areas from init.
func register(area string, entries map[string]text) {
	if areas[area] {
		panic("i18n: area " + area + " registered twice")
	}
	areas[area] = true
	for key, m := range entries {
		if !keyRe.MatchString(key) || !strings.HasPrefix(key, area+".") {
			panic("i18n: key " + key + " is malformed or outside area " + area)
		}
		if _, dup := messages[key]; dup {
			panic("i18n: key " + key + " defined twice")
		}
		messages[key] = m
	}
}
