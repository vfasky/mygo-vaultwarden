# Authentication bridge tests

Run from the repository root on macOS with the existing Swift toolchain:

```sh
swift test --package-path macos/Authentication --scratch-path "$TMPDIR/mygo-auth-swift-build"
swiftc -typecheck macos/Authentication/VaultAuthentication.swift
```

SwiftPM builds the production bridge and automatically discovers XCTest tests;
there is no `XCTMain` entry point. Direct `swiftc` invocation of the old test
executable did not supply XCTest's module paths. That invocation failure did
not mean XCTest was unavailable in this toolchain.

The two original byte tests and the complete assertion/registration DTO tests
run without Touch ID. The system authorization callback uses the same pure
`encodeVaultCredential` function. Tests verify base64url IDs, all raw response
bytes (including unchanged clientDataJSON), response branch keys, and required
object-valued `extensions`. The platform requests no extensions, so `{}` is
its actual result; no AppID success is fabricated. The required-field assertion
decoder reflects Vaultwarden 1.37.4's `PublicKeyCredentialCopy` requirement and
rejects missing/null/array/bool extensions. It is a serialization contract test,
not execution of the Rust server's decoder or signature verification.

Only `VaultAuthentication.swift` belongs in the app source target. The WebAuthn
bridge requires macOS 13+ for controller cancellation (registration exclusions
require 14+); the browser bridge remains macOS 12+. Integration must gate the
WebAuthn entry point accordingly. Do not add
this package manifest or `Tests/` to the app target. Signed associated domains,
AASA, dynamic RP support, URL scheme/loopback and Go callback registration belong
to integration card #14. Real platform credentials, system authentication UI,
hardware signatures and live provider7 login still require platform validation.
