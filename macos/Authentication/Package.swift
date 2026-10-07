// swift-tools-version: 5.9
import PackageDescription

// Standalone tests only; the app's package and source registration are unchanged.
let package = Package(
    name: "VaultAuthentication",
    platforms: [.macOS(.v12)],
    targets: [
        .target(name: "VaultAuthentication", path: ".", exclude: ["Tests", "README.md"], sources: ["VaultAuthentication.swift"]),
        .testTarget(name: "VaultAuthenticationTests", dependencies: ["VaultAuthentication"], path: "Tests")
    ]
)
