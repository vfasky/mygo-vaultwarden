// SPDX-License-Identifier: GPL-3.0-only

// Package i18n localizes user-visible text. Source strings are written in
// Simplified Chinese and double as catalog keys; English catalogs in this
// package map them to translations. The language follows the system's
// preferred languages and is fixed at startup, before any other package
// initializes, so package-level text such as sentinel errors is localized
// too.
//
//	ui.Text(c, i18n.T("保存"))
//	status = i18n.Tf("已同步 %d 个项目", n)
//	err = fmt.Errorf(i18n.T("读取失败：%w"), err)
//
// Text that is also program state (compared, persisted or sent to a server)
// keeps its Chinese value: mark the literal with Key and translate it only
// where it is shown, with T(value).
package i18n

import (
	"fmt"
	"os"
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
	// Tests assert the Chinese source text unless they choose a language.
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

// T returns the translation of a Chinese source string in the active
// language, or the source string itself when it has none.
func T(source string) string {
	if Current() == English {
		if t, ok := english[source]; ok {
			return t
		}
	}
	return source
}

// Tf translates format and formats it with args as fmt.Sprintf does.
func Tf(format string, args ...any) string {
	return fmt.Sprintf(T(format), args...)
}

// Key marks a Chinese literal that is program state rather than text, so it
// is kept as is. Translate it with T where it is displayed.
func Key(source string) string { return source }

var (
	english   = map[string]string{}
	catalogs  = map[string]map[string]string{}
	conflicts []string
)

// register adds an English catalog; each catalog file registers one from
// init. A source string translated differently by two catalogs is reported
// by the catalog test and keeps its first translation.
func register(name string, entries map[string]string) {
	if _, dup := catalogs[name]; dup {
		panic("i18n: catalog " + name + " registered twice")
	}
	catalogs[name] = entries
	for source, translation := range entries {
		if prior, ok := english[source]; ok {
			if prior != translation {
				conflicts = append(conflicts, fmt.Sprintf("%q: %q vs %q (%s)", source, prior, translation, name))
			}
			continue
		}
		english[source] = translation
	}
}
