// SPDX-License-Identifier: GPL-3.0-only

// Command mygo-vaultwarden is the macOS Vaultwarden client entry point. The
// build scripts compile this root package; all application code lives under
// internal/.
package main

import "github.com/vfasky/mygo-vaultwarden/internal/app"

func main() {
	app.Run()
}
