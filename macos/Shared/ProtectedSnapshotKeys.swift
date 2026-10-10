// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security
import LocalAuthentication

protocol SnapshotKeyStore {
    func create(id: String, key: Data) throws
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data
    func delete(id: String) throws
    func recoveryKey(create: Bool) throws -> Data
}

final class ProtectedSnapshotKeys: SnapshotKeyStore {
    private let accessGroup: String
    private let service = "yz.sh.mygo-vaultwarden.snapshot-v1"
    init(accessGroup: String) { self.accessGroup = accessGroup }

    private func query(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id,
         kSecAttrAccessGroup as String: accessGroup,
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrSynchronizable as String: false]
    }
    func create(id: String, key: Data) throws {
        guard key.count == 32 else { throw SnapshotError.invalidInput }
        var error: Unmanaged<CFError>?
        // The OS controls actual key retrieval. There is no unprotected fallback copy.
        guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                        .userPresence, &error) else {
            throw SnapshotError.configuration
        }
        var attributes = query(id)
        attributes[kSecAttrAccessControl as String] = acl
        attributes[kSecValueData as String] = key
        attributes[kSecAttrLabel as String] = L10n.t("snapshot.key_label")
        let result = SecItemAdd(attributes as CFDictionary, nil)
        guard result == errSecSuccess else { throw SnapshotError.keychain(result) }
    }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data {
        context.interactionNotAllowed = !allowUI
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = L10n.t("auth.unlock_snapshot_reason")
        var request = query(id)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        request[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == 32 else { throw SnapshotError.corrupt }
            return data
        case errSecUserCanceled: throw SnapshotError.cancelled
        case errSecInteractionNotAllowed, errSecAuthFailed: throw SnapshotError.authenticationRequired
        case errSecItemNotFound: throw SnapshotError.unavailable
        default: throw SnapshotError.keychain(status)
        }
    }
    // Separate metadata service, with no vault wrapping capability. Survives
    // logout to retain unresolved target barriers; never used by snapshot reads.
    func recoveryKey(create: Bool) throws -> Data {
        var request = query(targetRecoveryKeyID)
        request[kSecAttrService as String] = "yz.sh.mygo-vaultwarden.target-recovery-v1"
        if create {
            var attributes = request
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            var key = Data(count: 32)
            guard key.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw SnapshotError.configuration }
            defer { key.resetBytes(in: 0..<key.count) }
            attributes[kSecValueData as String] = key
            let result = SecItemAdd(attributes as CFDictionary, nil)
            guard result == errSecSuccess || result == errSecDuplicateItem else { throw SnapshotError.keychain(result) }
        }
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext()
        context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        var value: CFTypeRef?
        let result = SecItemCopyMatching(request as CFDictionary, &value)
        guard result == errSecSuccess, let data = value as? Data, data.count == 32 else { throw SnapshotError.keychain(result) }
        return data
    }
    func delete(id: String) throws {
        let context = LAContext()
        context.interactionNotAllowed = true
        var request = query(id)
        request[kSecUseAuthenticationContext as String] = context
        let result = SecItemDelete(request as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else { throw SnapshotError.keychain(result) }
    }
}

struct SnapshotConfiguration {
    let group: String
    let keychainGroup: String
    let directory: URL
    static func current() throws -> SnapshotConfiguration {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "SnapshotAppGroup") as? String,
              let keychain = Bundle.main.object(forInfoDictionaryKey: "SnapshotKeychainGroup") as? String,
              !group.isEmpty, !keychain.isEmpty, !group.contains("$"), !keychain.contains("$"),
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw SnapshotError.configuration
        }
        return SnapshotConfiguration(group: group, keychainGroup: keychain,
                                     directory: container.appendingPathComponent("SnapshotV1", isDirectory: true))
    }
}
