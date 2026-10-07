// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

struct SnapshotScope: Codable, Equatable {
    let server: String
    let account: String
    // Reserved legacy scope: real Vaultwarden publications must never use it.
    static let demo = SnapshotScope(server: "https://demo.invalid", account: "public-demo-account")
    var valid: Bool {
        guard !account.isEmpty, account.utf8.count <= 256, let url = URLComponents(string: server), let host = url.host,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else { return false }
        return url.scheme == "https" || (url.scheme == "http" && ["localhost", "127.0.0.1", "[::1]", "::1"].contains(host))
    }
}

struct SnapshotHeader: Codable, Equatable {
    let format: Int
    let id: String
    let keyID: String
    let scope: SnapshotScope
    let createdAt: Date
    let count: Int
}

struct PasswordUnlockKDF: Codable, Equatable {
    let kdf: Int
    let kdfIterations: Int
    let kdfMemory: Int
    let kdfParallelism: Int
    let salt: String?

    var valid: Bool {
        switch kdf {
        case 0: return (5000...2000000).contains(kdfIterations)
        case 1: return (2...10).contains(kdfIterations) && (16...256).contains(kdfMemory) && (1...16).contains(kdfParallelism)
        default: return false
        }
    }
}

struct PasswordUnlockConfig: Codable, Equatable {
    let email: String
    let kdf: PasswordUnlockKDF
    var valid: Bool {
        !email.isEmpty && email.utf8.count <= 1024 && kdf.valid &&
        (kdf.salt == nil || kdf.salt == "" || kdf.salt == email)
    }
}

// Transient bridge input; only the authenticated envelope is persisted.
struct PasswordUnlockMaterial: Decodable {
    let config: PasswordUnlockConfig
    var key: Data
}

struct PasswordWrappedSnapshotKey: Codable {
    let config: PasswordUnlockConfig
    let sealed: Data
}

private struct PasswordUnlockAAD: Encodable {
    let header: SnapshotHeader
    let config: PasswordUnlockConfig
}

struct EncryptedSnapshot: Codable {
    let header: SnapshotHeader
    let sealed: Data
    var passwordUnlock: PasswordWrappedSnapshotKey? = nil
}

struct VaultData: Codable, Equatable {
    let version: Int
    let scope: SnapshotScope
    let sync: Data
    var quarantinedOrganizations: [String]? = nil

    func excludingQuarantined(_ credentials: [VaultCredential]) throws -> [VaultCredential] {
        guard let ids = quarantinedOrganizations, !ids.isEmpty else { return credentials }
        try validate(scope: scope)
        let object = try JSONSerialization.jsonObject(with: sync) as! [String: Any]
        let ciphers = object["ciphers"] as! [[String: Any]]
        let forbidden = Set(ciphers.filter { ids.contains($0["organizationId"] as? String ?? "") }.compactMap { $0["id"] as? String })
        return credentials.filter { !forbidden.contains($0.id) }
    }

    func validate(scope expected: SnapshotScope) throws {
        guard version == 1, scope == expected, !sync.isEmpty, sync.count <= 32 * 1024 * 1024,
              let object = try JSONSerialization.jsonObject(with: sync) as? [String: Any],
              let profile = object["profile"] as? [String: Any], profile["id"] as? String == scope.account,
              let ciphers = object["ciphers"] as? [[String: Any]], ciphers.count <= 100000 else { throw SnapshotError.invalidInput }
        if let isolated = quarantinedOrganizations {
            guard isolated.count <= 1024, Set(isolated).count == isolated.count,
                  isolated.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 && $0.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }) }) else { throw SnapshotError.invalidInput }
        }
        var ids = Set<String>()
        for cipher in ciphers {
            guard let id = cipher["id"] as? String, !id.isEmpty, id.utf8.count <= 128,
                  id.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }),
                  ids.insert(id).inserted else { throw SnapshotError.invalidInput }
        }
    }
}

struct SnapshotPayload: Codable {
    let scope: SnapshotScope
    let credentials: [VaultCredential]
    var session: Data? = nil
    // Absent on legacy Login-only snapshots; a successful sync migrates them.
    var vault: VaultData? = nil
}

struct SnapshotState: Codable {
    static let initialRevision = "empty-v1"
    var format = 1
    var revision = initialRevision
    var snapshot: EncryptedSnapshot?
    var retiredKeys: [String] = []
    var indexedToken: String?
    var signedOut = true
    var indexToken: String { snapshot?.header.id ?? revision }
    var indexPending: Bool { indexedToken != indexToken }

    func validate() throws {
        guard format == 1, !revision.isEmpty, retiredKeys.count < 512,
              Set(retiredKeys).count == retiredKeys.count else { throw SnapshotError.corrupt }
        if snapshot == nil && !signedOut { throw SnapshotError.corrupt }
        if let snapshot {
            guard !signedOut, snapshot.header.format == 1,
                  UUID(uuidString: snapshot.header.id) != nil,
                  UUID(uuidString: snapshot.header.keyID) != nil,
                  !retiredKeys.contains(snapshot.header.keyID),
                  snapshot.header.scope.valid,
                  snapshot.header.count >= 0, snapshot.header.count <= 10000 else { throw SnapshotError.corrupt }
            if let wrapper = snapshot.passwordUnlock {
                guard wrapper.config.valid, wrapper.sealed.count == 60 else { throw SnapshotError.corrupt }
            }
        }
        guard retiredKeys.allSatisfy({ UUID(uuidString: $0) != nil }) else { throw SnapshotError.corrupt }
    }
}

struct SnapshotLease {
    let revision: String
    let header: SnapshotHeader
    let expiresAt: TimeInterval
    let credentials: [VaultCredential]
    // Only authenticated main-app unlocks opt in; AutoFill leases omit it.
    var session: Data? = nil
    var vault: VaultData? = nil
}

enum SnapshotError: Error, Equatable {
    case unavailable, corrupt, stale, expired, wrongScope, busy, invalidInput
    case keychain(Int32), authenticationRequired, cancelled, configuration, invalidPassword, passwordUnlockUnavailable

    var code: String {
        switch self {
        case .unavailable: return "no_snapshot"
        case .corrupt: return "corrupt_snapshot"
        case .stale: return "stale_revision"
        case .expired: return "expired_lease"
        case .wrongScope: return "wrong_scope"
        case .busy: return "storage_busy"
        case .invalidInput: return "invalid_input"
        case .keychain: return "keychain_error"
        case .authenticationRequired: return "authentication_required"
        case .cancelled: return "authentication_cancelled"
        case .configuration: return "configuration_error"
        case .invalidPassword: return "invalid_password"
        case .passwordUnlockUnavailable: return "password_unlock_unavailable"
        }
    }
    var message: String {
        switch self {
        case .unavailable: return "没有可用快照，请先在主应用登录并同步密码库。"
        case .corrupt: return "快照损坏或格式不受支持，已拒绝解密。"
        case .stale: return "数据已被锁定、更新或撤销，请刷新后重试。"
        case .expired: return "认证已过期，请重新认证。"
        case .wrongScope: return "快照所属账号或服务器不匹配。"
        case .busy: return "另一个进程正在更新快照，请稍后重试。"
        case .invalidInput: return "请求或凭据格式不受支持。"
        case .keychain(let status): return "系统钥匙串操作失败（\(status)）。"
        case .authenticationRequired: return "需要通过 Touch ID 或系统允许的设备认证读取密钥。"
        case .cancelled: return "系统认证已取消，没有读取凭据。"
        case .configuration: return "共享容器或钥匙串权限未配置，请使用完整签名版本。"
        case .invalidPassword: return "主密码不正确，请重试。"
        case .passwordUnlockUnavailable: return "请重新登录一次，以启用主密码解锁；也可以使用 Touch ID 解锁。"
        }
    }
}

func snapshotJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    // Milliseconds avoid differing floating-point representations in authenticated headers.
    encoder.dateEncodingStrategy = .millisecondsSince1970
    return try encoder.encode(value)
}

func snapshotDecode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .millisecondsSince1970
    return try decoder.decode(type, from: data)
}

func validateCredentials(_ credentials: [VaultCredential]) throws {
    guard credentials.count <= 10000, Set(credentials.map(\.id)).count == credentials.count,
          credentials.allSatisfy({
              !$0.id.isEmpty && $0.id.utf8.count <= 256 && !$0.id.contains(":") &&
              $0.title.utf8.count <= 4096 && $0.username.utf8.count <= 4096 && $0.password.utf8.count <= 65536 &&
              ($0.uris.map { $0.count <= 128 && $0.allSatisfy(\.valid) } ?? (!$0.hosts.isEmpty && $0.hosts.allSatisfy({ ["localhost", "127.0.0.1"].contains($0) })))
          }) else { throw SnapshotError.invalidInput }
}

func sealSnapshot(credentials: [VaultCredential], scope: SnapshotScope, keyID: String, key: Data,
                  passwordUnlock: PasswordUnlockMaterial? = nil, session: Data? = nil, vault: VaultData? = nil) throws -> EncryptedSnapshot {
    try validateCredentials(credentials)
    try validateSessionData(session)
    try vault?.validate(scope: scope)
    guard key.count == 32 else { throw SnapshotError.corrupt }
    // Round the timestamp before using the header as authenticated data.
    let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
    let header = SnapshotHeader(format: 1, id: UUID().uuidString, keyID: keyID, scope: scope, createdAt: now, count: credentials.count)
    let plaintext = try snapshotJSON(SnapshotPayload(scope: scope, credentials: credentials, session: session, vault: vault))
    let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), authenticating: snapshotJSON(header))
    guard let combined = box.combined else { throw SnapshotError.corrupt }
    var snapshot = EncryptedSnapshot(header: header, sealed: combined)
    if let material = passwordUnlock {
        guard material.config.valid, material.key.count == 32 else { throw SnapshotError.invalidInput }
        let aad = try snapshotJSON(PasswordUnlockAAD(header: header, config: material.config))
        let wrapped = try AES.GCM.seal(key, using: SymmetricKey(data: material.key), authenticating: aad)
        guard let sealed = wrapped.combined else { throw SnapshotError.corrupt }
        snapshot.passwordUnlock = PasswordWrappedSnapshotKey(config: material.config, sealed: sealed)
    }
    return snapshot
}

func unwrapSnapshotKey(_ snapshot: EncryptedSnapshot, unlockKey: Data) throws -> Data {
    guard let wrapper = snapshot.passwordUnlock else { throw SnapshotError.passwordUnlockUnavailable }
    guard unlockKey.count == 32, wrapper.config.valid else { throw SnapshotError.invalidInput }
    do {
        let aad = try snapshotJSON(PasswordUnlockAAD(header: snapshot.header, config: wrapper.config))
        let box = try AES.GCM.SealedBox(combined: wrapper.sealed)
        return try AES.GCM.open(box, using: SymmetricKey(data: unlockKey), authenticating: aad)
    } catch { throw SnapshotError.invalidPassword }
}

func validateSessionData(_ session: Data?) throws {
    if let session {
        guard !session.isEmpty, session.count <= 64 * 1024 else { throw SnapshotError.invalidInput }
    }
}

func replacingSnapshotSession(_ snapshot: EncryptedSnapshot, key: Data, session: Data) throws -> EncryptedSnapshot {
    try validateSessionData(session)
    var payload = try openSnapshotPayload(snapshot, key: key, scope: snapshot.header.scope)
    payload.session = session
    let box = try AES.GCM.seal(snapshotJSON(payload), using: SymmetricKey(data: key), authenticating: snapshotJSON(snapshot.header))
    guard let combined = box.combined else { throw SnapshotError.corrupt }
    // Retain candidate identity, timestamp and password wrapper; use a fresh nonce.
    return EncryptedSnapshot(header: snapshot.header, sealed: combined, passwordUnlock: snapshot.passwordUnlock)
}

func openSnapshot(_ snapshot: EncryptedSnapshot, key: Data, scope: SnapshotScope) throws -> [VaultCredential] {
    try openSnapshotPayload(snapshot, key: key, scope: scope).credentials
}

func openSnapshotPayload(_ snapshot: EncryptedSnapshot, key: Data, scope: SnapshotScope) throws -> SnapshotPayload {
    guard snapshot.header.scope == scope else { throw SnapshotError.wrongScope }
    guard key.count == 32 else { throw SnapshotError.corrupt }
    do {
        let box = try AES.GCM.SealedBox(combined: snapshot.sealed)
        let data = try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: snapshotJSON(snapshot.header))
        let payload = try snapshotDecode(SnapshotPayload.self, from: data)
        guard payload.scope == scope, payload.credentials.count == snapshot.header.count else { throw SnapshotError.corrupt }
        try validateCredentials(payload.credentials)
        try validateSessionData(payload.session)
        try payload.vault?.validate(scope: scope)
        if let vault = payload.vault {
            guard try vault.excludingQuarantined(payload.credentials).count == payload.credentials.count else { throw SnapshotError.corrupt }
        }
        return payload
    } catch { throw SnapshotError.corrupt }
}
