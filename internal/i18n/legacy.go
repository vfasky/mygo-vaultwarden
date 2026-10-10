// SPDX-License-Identifier: GPL-3.0-only

package i18n

// TODO(i18n): delete this file and the en_*.go catalogs once every call
// site uses a semantic key. Until then, T(chinese) still finds the English
// of text whose source string was its key.

var (
	legacyEnglish   = map[string]string{}
	legacyCatalogs  = map[string]map[string]string{}
	legacyConflicts []string
)

func legacyT(source string) string {
	if Current() == English {
		if t, ok := legacyEnglish[source]; ok {
			return t
		}
	}
	return source
}

func registerLegacy(name string, entries map[string]string) {
	legacyCatalogs[name] = entries
	for source, translation := range entries {
		if prior, ok := legacyEnglish[source]; ok && prior != translation {
			legacyConflicts = append(legacyConflicts, source)
			continue
		}
		legacyEnglish[source] = translation
	}
}

// Key marks a Chinese literal that is program state. Deprecated: replace
// the state with a stable identifier and translate it with T where shown.
func Key(source string) string { return source }

// Tc translates a Chinese source string in a context. Deprecated: use a
// semantic key per context instead.
func Tc(context, source string) string {
	if Current() == English {
		if t, ok := legacyEnglish[context+"\x04"+source]; ok {
			return t
		}
	}
	return legacyT(source)
}
