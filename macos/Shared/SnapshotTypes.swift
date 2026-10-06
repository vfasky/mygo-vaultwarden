// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

struct SnapshotScope: Codable, Equatable {
    let server: String
    let account: String
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

struct EncryptedSnapshot: Codable {
    let header: SnapshotHeader
    let sealed: Data
}

struct SnapshotPayload: Codable {
    let scope: SnapshotScope
    let credentials: [DemoCredential]
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
        }
        guard retiredKeys.allSatisfy({ UUID(uuidString: $0) != nil }) else { throw SnapshotError.corrupt }
    }
}

struct SnapshotLease {
    let revision: String
    let header: SnapshotHeader
    let expiresAt: TimeInterval
    let credentials: [DemoCredential]
}

enum SnapshotError: Error, Equatable {
    case unavailable, corrupt, stale, expired, wrongScope, busy, invalidInput
    case keychain(Int32), authenticationRequired, cancelled, configuration

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
        }
    }
    var message: String {
        switch self {
        case .unavailable: return "没有可用快照，请先在主应用发布演示凭据。"
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

func validateCredentials(_ credentials: [DemoCredential]) throws {
    guard credentials.count <= 10000, Set(credentials.map(\.id)).count == credentials.count,
          credentials.allSatisfy({
              !$0.id.isEmpty && $0.id.utf8.count <= 256 && !$0.id.contains(":") &&
              $0.title.utf8.count <= 4096 && $0.username.utf8.count <= 4096 && $0.password.utf8.count <= 65536 &&
              ($0.uris.map { $0.count <= 128 && $0.allSatisfy(\.valid) } ?? (!$0.hosts.isEmpty && $0.hosts.allSatisfy({ ["localhost", "127.0.0.1"].contains($0) })))
          }) else { throw SnapshotError.invalidInput }
}

func sealSnapshot(credentials: [DemoCredential], scope: SnapshotScope, keyID: String, key: Data) throws -> EncryptedSnapshot {
    try validateCredentials(credentials)
    guard key.count == 32 else { throw SnapshotError.corrupt }
    // Round the timestamp before using the header as authenticated data.
    let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
    let header = SnapshotHeader(format: 1, id: UUID().uuidString, keyID: keyID, scope: scope, createdAt: now, count: credentials.count)
    let plaintext = try snapshotJSON(SnapshotPayload(scope: scope, credentials: credentials))
    let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), authenticating: snapshotJSON(header))
    guard let combined = box.combined else { throw SnapshotError.corrupt }
    return EncryptedSnapshot(header: header, sealed: combined)
}

func openSnapshot(_ snapshot: EncryptedSnapshot, key: Data, scope: SnapshotScope) throws -> [DemoCredential] {
    guard snapshot.header.scope == scope else { throw SnapshotError.wrongScope }
    guard key.count == 32 else { throw SnapshotError.corrupt }
    do {
        let box = try AES.GCM.SealedBox(combined: snapshot.sealed)
        let data = try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: snapshotJSON(snapshot.header))
        let payload = try snapshotDecode(SnapshotPayload.self, from: data)
        guard payload.scope == scope, payload.credentials.count == snapshot.header.count else { throw SnapshotError.corrupt }
        try validateCredentials(payload.credentials)
        return payload.credentials
    } catch { throw SnapshotError.corrupt }
}
