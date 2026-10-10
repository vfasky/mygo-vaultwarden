// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin

package i18n

import (
	"os"
	"strings"
)

// preferredLanguages reads the POSIX locale variables in priority order.
func preferredLanguages() []string {
	var tags []string
	for _, name := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		for _, value := range strings.Split(os.Getenv(name), ":") {
			if value = strings.SplitN(value, ".", 2)[0]; value != "" && value != "C" && value != "POSIX" {
				tags = append(tags, value)
			}
		}
	}
	return tags
}

// Elsewhere the choice lasts until the app quits.
var chosenLanguages []string

func savedLanguages() []string { return chosenLanguages }

func saveLanguages(languages []string) []string {
	chosenLanguages = languages
	if len(languages) > 0 {
		return languages
	}
	return preferredLanguages()
}
