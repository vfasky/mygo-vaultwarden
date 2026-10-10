// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package i18n

import (
	"runtime"
	"sync"

	"github.com/ebitengine/purego"
)

const kCFStringEncodingUTF8 = 0x08000100

// CoreFoundation is called directly: the language is read during package
// initialization, before the MyGo application runs, and the preference is
// AppKit's own per-app AppleLanguages, which System Settings > General >
// Language & Region > Applications also writes.
var cf struct {
	once sync.Once
	ok   bool

	copyPreferred  func() uintptr
	count          func(uintptr) int
	valueAt        func(uintptr, int) uintptr
	cString        func(uintptr, []byte, int, uint32) bool
	release        func(uintptr)
	typeID         func(uintptr) uintptr
	arrayTypeID    func() uintptr
	stringTypeID   func() uintptr
	createString   func(uintptr, string, uint32) uintptr
	createArray    func(uintptr, *uintptr, int, uintptr) uintptr
	arrayCallbacks uintptr
	setAppValue    func(uintptr, uintptr, uintptr)
	copyAppValue   func(uintptr, uintptr) uintptr
	copyValue      func(uintptr, uintptr, uintptr, uintptr) uintptr
	synchronize    func(uintptr) bool
}

func loadCF() bool {
	cf.once.Do(func() {
		lib, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			return
		}
		callbacks, err := purego.Dlsym(lib, "kCFTypeArrayCallBacks")
		if err != nil {
			return
		}
		cf.arrayCallbacks = callbacks
		purego.RegisterLibFunc(&cf.copyPreferred, lib, "CFLocaleCopyPreferredLanguages")
		purego.RegisterLibFunc(&cf.count, lib, "CFArrayGetCount")
		purego.RegisterLibFunc(&cf.valueAt, lib, "CFArrayGetValueAtIndex")
		purego.RegisterLibFunc(&cf.cString, lib, "CFStringGetCString")
		purego.RegisterLibFunc(&cf.release, lib, "CFRelease")
		purego.RegisterLibFunc(&cf.typeID, lib, "CFGetTypeID")
		purego.RegisterLibFunc(&cf.arrayTypeID, lib, "CFArrayGetTypeID")
		purego.RegisterLibFunc(&cf.stringTypeID, lib, "CFStringGetTypeID")
		purego.RegisterLibFunc(&cf.createString, lib, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&cf.createArray, lib, "CFArrayCreate")
		purego.RegisterLibFunc(&cf.setAppValue, lib, "CFPreferencesSetAppValue")
		purego.RegisterLibFunc(&cf.copyAppValue, lib, "CFPreferencesCopyAppValue")
		purego.RegisterLibFunc(&cf.copyValue, lib, "CFPreferencesCopyValue")
		purego.RegisterLibFunc(&cf.synchronize, lib, "CFPreferencesAppSynchronize")
		cf.ok = true
	})
	return cf.ok
}

// cfString returns a new CFString; the caller releases it. The
// kCFPreferences* constants are CFStrings of their own names.
func cfString(s string) uintptr { return cf.createString(0, s, kCFStringEncodingUTF8) }

// tags reads a CFArray of CFStrings and releases it.
func tags(array uintptr) []string {
	if array == 0 {
		return nil
	}
	defer cf.release(array)
	if cf.typeID(array) != cf.arrayTypeID() {
		return nil
	}
	var out []string
	buffer := make([]byte, 64)
	for i, n := 0, cf.count(array); i < n; i++ {
		value := cf.valueAt(array, i)
		if cf.typeID(value) != cf.stringTypeID() || !cf.cString(value, buffer, len(buffer), kCFStringEncodingUTF8) {
			continue
		}
		for end, b := range buffer {
			if b == 0 {
				out = append(out, string(buffer[:end]))
				break
			}
		}
	}
	return out
}

// preferredLanguages reads CFLocaleCopyPreferredLanguages, the list System
// Settings orders, including a language chosen for this app alone.
func preferredLanguages() []string {
	if !loadCF() {
		return nil
	}
	return tags(cf.copyPreferred())
}

// withPreferenceKeys calls fn with the AppleLanguages key and this app's
// preference domain.
func withPreferenceKeys(fn func(key, app uintptr)) bool {
	if !loadCF() {
		return false
	}
	key, app := cfString("AppleLanguages"), cfString("kCFPreferencesCurrentApplication")
	defer cf.release(key)
	defer cf.release(app)
	fn(key, app)
	return true
}

// savedLanguages returns this app's own AppleLanguages, without the
// system-wide list.
func savedLanguages() []string {
	var out []string
	withPreferenceKeys(func(key, app uintptr) {
		user, host := cfString("kCFPreferencesCurrentUser"), cfString("kCFPreferencesAnyHost")
		defer cf.release(user)
		defer cf.release(host)
		out = tags(cf.copyValue(key, app, user, host))
	})
	return out
}

// saveLanguages stores this app's AppleLanguages, or removes it for nil so
// the app follows the system again, and returns the languages now in effect.
func saveLanguages(languages []string) []string {
	var effective []string
	withPreferenceKeys(func(key, app uintptr) {
		if len(languages) == 0 {
			cf.setAppValue(key, 0, app)
		} else {
			values := make([]uintptr, len(languages))
			for i, l := range languages {
				values[i] = cfString(l)
			}
			array := cf.createArray(0, &values[0], len(values), cf.arrayCallbacks)
			runtime.KeepAlive(values)
			for _, v := range values {
				cf.release(v)
			}
			cf.setAppValue(key, array, app)
			cf.release(array)
		}
		cf.synchronize(app)
		// The app domain falls back to the system-wide list once its own
		// value is removed; CFLocale may still cache the old one.
		effective = tags(cf.copyAppValue(key, app))
	})
	return effective
}
