#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
go_bin="$(bash scripts/resolve-go.sh)"
# Imports excludes TestImports/XTestImports. Fixture packages may depend on one
# another, but no production package may import a fixture.
"$go_bin" list -tags headless -f '{{.ImportPath}} {{join .Imports " "}}' ./... |
  awk '
    $1 !~ /\/internal\/testfixture(\/|$)/ {
      for (i = 2; i <= NF; i++) {
        if ($i ~ /\/internal\/testfixture(\/|$)/) {
          print "production fixture dependency: " $1 " -> " $i > "/dev/stderr"
          failed = 1
        }
      }
    }
    END { exit failed }
  '
