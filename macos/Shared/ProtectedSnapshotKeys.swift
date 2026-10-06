// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security
import LocalAuthentication

protocol SnapshotKeyStore {
    func create(id: String, key: Data) throws
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data
    func delete(id: String) throws
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
        attributes[kSecAttrLabel as String] = "MyGo Vaultwarden 自动填充快照密钥"
        let result = SecItemAdd(attributes as CFDictionary, nil)
        guard result == errSecSuccess else { throw SnapshotError.keychain(result) }
    }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data {
        context.interactionNotAllowed = !allowUI
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = "解锁 MyGo Vaultwarden 的本机自动填充快照"
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
