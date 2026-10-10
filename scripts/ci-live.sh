#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Exit 77 means NOT RUN. Callers must report it as a skip, never a live pass.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${MYGO_LIVE_CI:-}" != 1 ]]; then
  echo 'SKIP: set MYGO_LIVE_CI=1 to permit owned Docker fixtures' >&2
  exit 77
fi
if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo 'SKIP: Docker engine unavailable; no live test ran' >&2
  exit 77
fi
export GO_BIN="$(bash scripts/resolve-go.sh)"
# Never inherit a supplied server, CLI login, or release-only filter. Every
# selected entry creates a unique loopback container and checks ownership on cleanup.
unset MYGO_VW_TEST_URL MYGO_RECOVERY_TEST_URL MYGO_BW_CLI MYGO_PERSONAL_RELEASE_ONLY
export MYGO_PERSONAL_RELEASE_TEST=1 MYGO_VW_FINISHING_TEST=1
export MYGO_ROTATION_CIPHER_TEST=1 MYGO_RECOVERY_SMTP_TEST=1 MYGO_VW_SMTP_TEST=1
: "${TMPDIR:?TMPDIR must point to an isolated scratch directory}"
log="${1:-$TMPDIR/live-tests.jsonl}"
"$GO_BIN" test -tags headless -count=1 -timeout=25m -json ./internal/vaultwarden \
  -run '^TestLive(PersonalRelease|VaultFinishing|RotationCipherResources|RecoveryLifecycle|SMTPInvitations)$' | tee "$log"
# Go reports success when all selected tests skip or no test matches. Require
# each named top-level test to actually pass before reporting live success.
for name in PersonalRelease VaultFinishing RotationCipherResources RecoveryLifecycle SMTPInvitations; do
  if ! grep -E '"Action":"pass".*"Test":"TestLive'"$name"'"' "$log" >/dev/null; then
    echo "FAIL: TestLive$name did not produce a pass event (skip is not pass)" >&2
    exit 1
  fi
done
