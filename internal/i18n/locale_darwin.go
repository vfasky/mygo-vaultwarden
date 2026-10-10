// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package i18n

import (
	"github.com/ebitengine/purego"
)

const kCFStringEncodingUTF8 = 0x08000100

// preferredLanguages reads CFLocaleCopyPreferredLanguages, the list System
// Settings orders, including a language chosen for this app alone. It runs
// during package initialization, so it uses CoreFoundation directly instead
// of the MyGo application, which is not running yet.
func preferredLanguages() []string {
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil
	}
	var (
		copyPreferred func() uintptr
		count         func(uintptr) int
		valueAt       func(uintptr, int) uintptr
		cString       func(uintptr, []byte, int, uint32) bool
		release       func(uintptr)
	)
	purego.RegisterLibFunc(&copyPreferred, cf, "CFLocaleCopyPreferredLanguages")
	purego.RegisterLibFunc(&count, cf, "CFArrayGetCount")
	purego.RegisterLibFunc(&valueAt, cf, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&cString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&release, cf, "CFRelease")
	languages := copyPreferred()
	if languages == 0 {
		return nil
	}
	defer release(languages)
	var tags []string
	buffer := make([]byte, 64)
	for i, n := 0, count(languages); i < n; i++ {
		if cString(valueAt(languages, i), buffer, len(buffer), kCFStringEncodingUTF8) {
			for end, b := range buffer {
				if b == 0 {
					tags = append(tags, string(buffer[:end]))
					break
				}
			}
		}
	}
	return tags
}
