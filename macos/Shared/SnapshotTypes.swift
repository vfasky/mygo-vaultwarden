// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

// Kept in this shared source so SwiftPM, the bridge, and AutoFill use the same catalog.
enum L10n {
    enum Language: Equatable { case chinese, english }

    // Fixed on first use; matches internal/i18n's BCP 47 parsing and fallback.
    static let language = select(preferredLanguages: Locale.preferredLanguages,
                                 override: ProcessInfo.processInfo.environment["MYGO_VAULTWARDEN_LANG"])

    static func select(preferredLanguages: [String], override: String? = nil) -> Language {
        func parse(_ value: String) -> Language? {
            let tag = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if tag == "zh" || tag.hasPrefix("zh-") || tag.hasPrefix("zh_") { return .chinese }
            if tag == "en" || tag.hasPrefix("en-") || tag.hasPrefix("en_") { return .english }
            return nil
        }
        if let override, let language = parse(override) { return language }
        return preferredLanguages.compactMap(parse).first ?? .english
    }

    static func t(_ key: String, language: Language = language) -> String {
        guard let message = messages[key] else { return key }
        return language == .english ? message.en : message.zh
    }

    static let messages: [String: (zh: String, en: String)] = [
        "autofill.err_snapshot_changed": (zh: "快照已更改或锁定，请重新认证。", en: "The snapshot has changed or been locked. Authenticate again."),
        "autofill.err_system_locked": (zh: "系统已锁定，请重新认证。", en: "This Mac has been locked. Authenticate again."),
        "autofill.no_snapshot": (zh: "没有加密快照。请先在主应用登录并同步。", en: "No encrypted snapshot. Log in and sync in the main app first."),
        "autofill.finish_configuration": (zh: "完成设置并清理旧候选", en: "Finish & clear old suggestions"),
        "autofill.snapshot_description": (zh: "本机加密快照 · %d 条。读取密钥需要系统认证。", en: "Local encrypted snapshot. Items: %d. System authentication is required to read the key."),
        "autofill.authenticate_update": (zh: "认证并更新自动填充候选", en: "Authenticate & update AutoFill"),
        "autofill.authenticate_fill": (zh: "认证并填充", en: "Authenticate & fill"),
        "autofill.search_hint": (zh: "搜索标题或用户名，回车筛选", en: "Search title or username; press Return"),
        "autofill.no_matching_credentials": (zh: "没有与此网站匹配的凭据。", en: "No credentials match this website."),
        "autofill.previous_page": (zh: "上一页", en: "Previous"),
        "autofill.next_page": (zh: "下一页", en: "Next"),
        "autofill.authenticate_view": (zh: "认证并查看凭据", en: "Authenticate & view"),
        "autofill.cancel": (zh: "取消", en: "Cancel"),
        "auth.status_waiting": (zh: "等待系统认证…", en: "Waiting for system authentication…"),
        "autofill.select_credential_hint": (zh: "选择凭据后将再次认证并填充。", en: "Select a credential to authenticate again and fill."),
        "auth.err_expired": (zh: "认证已过期，请重新认证。", en: "Authentication has expired. Authenticate again."),
        "autofill.err_update_incomplete": (zh: "候选更新未完成，请检查系统开关并重试。", en: "Suggestions were not updated. Check the AutoFill setting in System Settings and try again."),
        "bridge.account_switch.status_pending": (zh: "新账号已提交；确认切换前保留原账号加密副本与密钥。", en: "The new account has been saved. The previous account's encrypted copy and key are kept until you confirm the switch."),
        "bridge.account_switch.status_authenticated": (zh: "已认证本机账号切换记录。", en: "The account switch record on this Mac has been authenticated."),
        "bridge.account_switch.status_recovery_pending": (zh: "切换已确认，目标账号仍需专用恢复核验。", en: "The switch is confirmed. The target account still requires dedicated recovery verification."),
        "bridge.account_switch.status_confirmed": (zh: "本机账号切换已确认。", en: "The account switch on this Mac is confirmed."),
        "bridge.status_snapshot_saved": (zh: "快照已保存。", en: "Snapshot saved."),
        "bridge.status_organization_quarantined": (zh: "该组织的本机访问已隔离。", en: "Access to this organization on this Mac has been quarantined."),
        "bridge.status_credentials_updated": (zh: "登录凭据已安全更新。", en: "Login credentials updated securely."),
        "bridge.status_vault_unlocked": (zh: "密码库已解锁。", en: "Vault unlocked."),
        "bridge.status_snapshot_unlocked": (zh: "离线快照已解锁。", en: "Offline snapshot unlocked."),
        "bridge.status_storage_completed": (zh: "存储操作已完成。", en: "Storage operation completed."),
        "bridge.status_index_pending": (zh: "系统候选尚未确认同步。", en: " System suggestions have not yet been confirmed as synced."),
        "bridge.status_cleanup_pending": (zh: "旧密钥清理待重试。", en: " Old key cleanup needs to be retried."),
        "bridge.err_unrecognized_request": (zh: "无法识别请求。", en: "Unrecognized request."),
        "snapshot.key_label": (zh: "MyGo Vaultwarden 自动填充快照密钥", en: "MyGo Vaultwarden AutoFill snapshot key"),
        "auth.unlock_snapshot_reason": (zh: "解锁 MyGo Vaultwarden 的本机自动填充快照", en: "unlock the MyGo Vaultwarden AutoFill snapshot on this Mac"),
        "snapshot.account_switch.err_storage_limit": (zh: "保留旧新账号恢复副本会超过本机加密存储上限；原账号数据保留，请先备份并明确管理旧缓存。", en: "Keeping recovery copies for both accounts would exceed the encrypted storage limit on this Mac. The previous account's data is preserved. Back it up and manage the old cache before proceeding."),
        "snapshot.account_switch.err_protected": (zh: "原本机账号有未决恢复、策略或组织隔离；请先在原账号处理后再切换。", en: "The previous account on this Mac has pending recovery, policy changes, or organization quarantine. Resolve these in that account before switching."),
        "snapshot.err_account_recovery_required": (zh: "此目标仍有账号轮换恢复记录，请先完成专用账号恢复核验。", en: "This target still has an account key rotation recovery record. Complete the dedicated account recovery verification first."),
        "snapshot.err_unavailable": (zh: "没有可用快照，请先在主应用登录并同步密码库。", en: "No snapshot is available. Log in and sync your vault in the main app first."),
        "snapshot.err_corrupt": (zh: "快照损坏或格式不受支持，已拒绝解密。", en: "The snapshot is damaged or its format is unsupported. Decryption was refused."),
        "snapshot.err_stale": (zh: "数据已被锁定、更新或撤销，请刷新后重试。", en: "The data has been locked, updated, or revoked. Refresh and try again."),
        "snapshot.err_wrong_scope": (zh: "快照所属账号或服务器不匹配。", en: "The snapshot's account or server does not match."),
        "snapshot.err_busy": (zh: "另一个进程正在更新快照，请稍后重试。", en: "Another process is updating the snapshot. Try again shortly."),
        "snapshot.err_invalid_input": (zh: "请求或凭据格式不受支持。", en: "The request or credential format is unsupported."),
        "snapshot.err_keychain": (zh: "系统钥匙串操作失败（%d）。", en: "System Keychain operation failed (%d)."),
        "auth.err_required": (zh: "需要通过 Touch ID 或系统允许的设备认证读取密钥。", en: "Reading the key requires Touch ID or device authentication allowed by the system."),
        "auth.err_cancelled": (zh: "系统认证已取消，没有读取凭据。", en: "System authentication was canceled. No credentials were read."),
        "snapshot.err_configuration": (zh: "共享容器或钥匙串权限未配置，请使用完整签名版本。", en: "Shared container or Keychain permissions are not configured. Use the fully signed app."),
        "auth.err_invalid_password": (zh: "主密码不正确，请重试。", en: "Incorrect master password. Try again."),
        "auth.err_password_unlock_unavailable": (zh: "请重新登录一次，以启用主密码解锁；也可以使用 Touch ID 解锁。", en: "Log in again to enable master password unlock, or unlock with Touch ID.")
    ]
}


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
        case 1: return (2...10).contains(kdfIterations) && (16...1024).contains(kdfMemory) && (1...16).contains(kdfParallelism)
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

struct PendingPolicyMutation: Codable, Equatable {
    let organizationId: String
    let policyType: Int
    let mutationId: String
}

struct VaultData: Codable, Equatable {
    var version: Int
    let scope: SnapshotScope
    let sync: Data
    var pendingPolicyMutations: [PendingPolicyMutation]? = nil
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
        guard (version == 1 || version == 2), (version == 2) == !(pendingPolicyMutations ?? []).isEmpty, scope == expected, !sync.isEmpty, sync.count <= 32 * 1024 * 1024,
              let object = try JSONSerialization.jsonObject(with: sync) as? [String: Any],
              let profile = object["profile"] as? [String: Any], profile["id"] as? String == scope.account,
              let ciphers = object["ciphers"] as? [[String: Any]], ciphers.count <= 100000 else { throw SnapshotError.invalidInput }
        if let isolated = quarantinedOrganizations {
            guard isolated.count <= 1024, Set(isolated).count == isolated.count,
                  isolated.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 && $0.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }) }) else { throw SnapshotError.invalidInput }
        }
        if let pending = pendingPolicyMutations {
            let types = Set([0,1,2,3,5,6,7,8,14,15,16,20])
            func validID(_ id: String) -> Bool { !id.isEmpty && id.utf8.count <= 128 && id.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 } }
            guard pending.count <= 1024, Set(pending.map(\.organizationId)).count == pending.count, Set(pending.map(\.mutationId)).count == pending.count,
                  pending.allSatisfy({ validID($0.organizationId) && validID($0.mutationId) && types.contains($0.policyType) }) else { throw SnapshotError.invalidInput }
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
    var accountRecovery: AccountRecoveryJournal? = nil
    var safeCandidates: [VaultCredential] {
        if accountRecovery != nil { return [] }
        if scope == .demo { return credentials }
        return vault?.policyCandidates(credentials) ?? []
    }
}

struct SnapshotState: Codable {
    static let initialRevision = "empty-v1"
    var format = 1
    var revision = initialRevision
    var snapshot: EncryptedSnapshot?
    var retiredKeys: [String] = []
    var indexedToken: String?
    var signedOut = true
    var targetRecovery: TargetRecoveryEnvelope? = nil
    var accountSwitch: AccountSwitchEnvelope? = nil
    var accountSwitchPending: Bool { accountSwitch?.pending ?? false }
    var indexToken: String { format >= 2 ? revision : (snapshot?.header.id ?? revision) }
    var indexPending: Bool { indexedToken != indexToken }

    func validate() throws {
        guard (format == 1 && targetRecovery == nil && accountSwitch == nil) ||
              (format == 2 && targetRecovery?.version == 1 && accountSwitch == nil) ||
              (format == 3 && accountSwitch?.version == 1 && (targetRecovery == nil || targetRecovery?.version == 1)) else { throw SnapshotError.corrupt }
        guard !revision.isEmpty, retiredKeys.count < 512,
              Set(retiredKeys).count == retiredKeys.count else { throw SnapshotError.corrupt }
        if snapshot == nil && !signedOut { throw SnapshotError.corrupt }
        if let snapshot {
            guard !signedOut, [1, 2].contains(snapshot.header.format),
                  UUID(uuidString: snapshot.header.id) != nil,
                  UUID(uuidString: snapshot.header.keyID) != nil,
                  !retiredKeys.contains(snapshot.header.keyID),
                  snapshot.header.scope.valid,
                  snapshot.header.count >= 0, snapshot.header.count <= 10000,
                  snapshot.sealed.count <= SnapshotTransfer.maximumBytes + 28 else { throw SnapshotError.corrupt }
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
    var recoveryOnly = false
}

enum SnapshotError: Error, Equatable {
    case accountRecoveryRequired, protectedAccountSwitch, accountSwitchTooLarge
    case unavailable, corrupt, stale, expired, wrongScope, busy, invalidInput
    case keychain(Int32), authenticationRequired, cancelled, configuration, invalidPassword, passwordUnlockUnavailable

    var code: String {
        switch self {
        case .accountSwitchTooLarge: return "account_switch_too_large"
        case .protectedAccountSwitch: return "account_switch_protected"
        case .accountRecoveryRequired: return "account_recovery_pending"
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
        case .accountSwitchTooLarge: return L10n.t("snapshot.account_switch.err_storage_limit")
        case .protectedAccountSwitch: return L10n.t("snapshot.account_switch.err_protected")
        case .accountRecoveryRequired: return L10n.t("snapshot.err_account_recovery_required")
        case .unavailable: return L10n.t("snapshot.err_unavailable")
        case .corrupt: return L10n.t("snapshot.err_corrupt")
        case .stale: return L10n.t("snapshot.err_stale")
        case .expired: return L10n.t("auth.err_expired")
        case .wrongScope: return L10n.t("snapshot.err_wrong_scope")
        case .busy: return L10n.t("snapshot.err_busy")
        case .invalidInput: return L10n.t("snapshot.err_invalid_input")
        case .keychain(let status): return String(format: L10n.t("snapshot.err_keychain"), status)
        case .authenticationRequired: return L10n.t("auth.err_required")
        case .cancelled: return L10n.t("auth.err_cancelled")
        case .configuration: return L10n.t("snapshot.err_configuration")
        case .invalidPassword: return L10n.t("auth.err_invalid_password")
        case .passwordUnlockUnavailable: return L10n.t("auth.err_password_unlock_unavailable")
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
                  passwordUnlock: PasswordUnlockMaterial? = nil, session: Data? = nil, vault: VaultData? = nil,
                  accountRecovery: AccountRecoveryJournal? = nil) throws -> EncryptedSnapshot {
    try validateCredentials(credentials)
    try validateSessionData(session)
    try vault?.validate(scope: scope)
    guard key.count == 32 else { throw SnapshotError.corrupt }
    // Round the timestamp before using the header as authenticated data.
    let now = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
    let header = SnapshotHeader(format: accountRecovery == nil ? 1 : 2, id: UUID().uuidString, keyID: keyID, scope: scope, createdAt: now, count: credentials.count)
    let plaintext = try snapshotJSON(SnapshotPayload(scope: scope, credentials: credentials, session: session, vault: vault, accountRecovery: accountRecovery))
    guard plaintext.count <= SnapshotTransfer.maximumBytes else { throw SnapshotError.invalidInput }
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
    guard payload.accountRecovery == nil else { throw SnapshotError.busy }
    payload.session = session
    let box = try AES.GCM.seal(snapshotJSON(payload), using: SymmetricKey(data: key), authenticating: snapshotJSON(snapshot.header))
    guard let combined = box.combined else { throw SnapshotError.corrupt }
    // Retain candidate identity, timestamp and password wrapper; use a fresh nonce.
    return EncryptedSnapshot(header: snapshot.header, sealed: combined, passwordUnlock: snapshot.passwordUnlock)
}

func openSnapshot(_ snapshot: EncryptedSnapshot, key: Data, scope: SnapshotScope) throws -> [VaultCredential] {
    let payload = try openSnapshotPayload(snapshot, key: key, scope: scope)
    return payload.safeCandidates
}

func openSnapshotPayload(_ snapshot: EncryptedSnapshot, key: Data, scope: SnapshotScope) throws -> SnapshotPayload {
    guard snapshot.header.scope == scope else { throw SnapshotError.wrongScope }
    guard key.count == 32 else { throw SnapshotError.corrupt }
    do {
        let box = try AES.GCM.SealedBox(combined: snapshot.sealed)
        let data = try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: snapshotJSON(snapshot.header))
        // Unknown envelope fields must never be silently discarded by a writer.
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: ["scope", "credentials", "session", "vault", "accountRecovery"]) else { throw SnapshotError.corrupt }
        if let vaultObject = object["vault"] as? [String: Any] {
            guard Set(vaultObject.keys).isSubset(of: ["version", "scope", "sync", "pendingPolicyMutations", "quarantinedOrganizations"]) else { throw SnapshotError.corrupt }
        }
        if let journalObject = object["accountRecovery"] as? [String: Any] {
            guard Set(journalObject.keys).isSubset(of: ["version", "binding", "record", "phase", "checkpoint"]),
                  let binding = journalObject["binding"] as? [String: Any],
                  Set(binding.keys) == Set(["operationId", "oldRevision", "epoch", "recordHash"]) else { throw SnapshotError.corrupt }
        }
        let payload = try snapshotDecode(SnapshotPayload.self, from: data)
        guard (snapshot.header.format == 2) == (payload.accountRecovery != nil) else { throw SnapshotError.corrupt }
        if let journal = payload.accountRecovery { try journal.validate(scope: scope) }
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
