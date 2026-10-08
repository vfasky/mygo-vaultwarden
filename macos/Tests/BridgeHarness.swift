// SPDX-License-Identifier: GPL-3.0-only
// Compiled only into the explicitly test-configured bridge dylib. No App Group,
// Keychain or system identity-store access is allowed in this harness.
#if SNAPSHOT_BRIDGE_TESTING
import Foundation
import LocalAuthentication

private final class BridgeMemoryKeys: SnapshotKeyStore {
    var values: [String: Data] = [:]
    func create(id: String, key: Data) throws { values[id] = key }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data {
        guard allowUI, let key = values[id] else { throw SnapshotError.authenticationRequired }
        return key
    }
    func recoveryKey(create: Bool) throws -> Data {
        if let key = values[targetRecoveryKeyID] { return key }
        guard create else { throw SnapshotError.unavailable }
        let key = Data(repeating: 93, count: 32) // isolated deterministic metadata-only fixture
        values[targetRecoveryKeyID] = key
        return key
    }
    func delete(id: String) throws { values[id] = nil }
}
private let bridgeKeys = BridgeMemoryKeys()
func snapshotBridgeTestStore() throws -> SnapshotStore {
    guard let path = ProcessInfo.processInfo.environment["SNAPSHOT_TEST_DIRECTORY"], !path.isEmpty else { throw SnapshotError.configuration }
    return try SnapshotStore(directory: URL(fileURLWithPath: path, isDirectory: true), keys: bridgeKeys)
}
#endif
