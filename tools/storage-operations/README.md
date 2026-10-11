# Snapshot operation protocol

`operations.json` is the single source for the 33 snapshot request operation wire
names and their transfer/publish policies. It generates the distinct Go
`localstore.Operation` type and Swift `StorageOperation` enum. Do not edit the
generated files by hand.

From the repository root:

```sh
go run ./tools/storage-operations
go run ./tools/storage-operations -check
go test ./internal/localstore
swiftc macos/Bridge/StorageOperation.generated.swift tools/storage-operations/OperationProtocolTest.swift -o "$TMPDIR/operation-protocol-test"
"$TMPDIR/operation-protocol-test"
```

The Go package test also checks generated-file drift. Swift dispatch is exhaustive,
so a new schema operation requires an explicit native handler before compilation
succeeds. Unknown operation decoding fails before native storage access. The Go
transport continues forwarding unknown names through the existing transfer failure
path, preserving its error behavior.

`publishes` preserves `credentials: []` for nil credentials on exactly the seven
existing snapshot publication operations. Other operations retain `null`.
`control` selects the direct C ABI; all other declared operations allow bounded
transfer. Transport frame `__transfer_v1` and runtime-secret operations (`activate`,
`revoke`, `authorizeDisplay`, `copy`) belong to separate protocols and are not
snapshot request operations.

The two `macos/Shared` recovery APIs currently receive `.rawValue` at their existing
String boundaries; the bridge validates and exhaustively dispatches the enum first.
