// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CredentialModel",
    platforms: [.macOS(.v14)],
    products: [.library(name: "CredentialModel", targets: ["CredentialModel"])],
    targets: [
        .target(name: "CredentialModel", path: "Shared"),
        .testTarget(name: "CredentialModelTests", dependencies: ["CredentialModel"], path: "Tests")
    ]
)
