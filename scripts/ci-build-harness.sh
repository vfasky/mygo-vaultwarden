#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TMPDIR:?TMPDIR must point to an isolated scratch directory}"
output="${1:-$TMPDIR/libSnapshotBridgeHarness.dylib}"
xcrun swiftc -emit-library -O -swift-version 5 -D SNAPSHOT_BRIDGE_TESTING \
  -module-name SnapshotBridgeHarness -module-cache-path "$TMPDIR/ci-swift-modules" \
  macos/Shared/*.swift macos/Bridge/*.swift macos/UpdateHelper/UpdateHelperProtocol.swift macos/Tests/BridgeHarness.swift \
  -o "$output"
printf '%s\n' "$output"
