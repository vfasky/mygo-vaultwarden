// swift-tools-version: 5.9
import PackageDescription

// Standalone pure tests; production sources are also built by xcode-build-bridge.sh.
let package = Package(
    name: "VaultAuthentication",
    platforms: [.macOS(.v12)],
    targets: [
        .target(name: "VaultAuthentication", path: ".", exclude: ["Tests", "README.md"], sources: ["VaultAuthentication.swift", "AuthenticationBridge.swift"]),
        .testTarget(name: "VaultAuthenticationTests", dependencies: ["VaultAuthentication"], path: "Tests")
    ]
)
