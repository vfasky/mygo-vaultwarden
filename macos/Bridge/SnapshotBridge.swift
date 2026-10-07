// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import LocalAuthentication

private struct BridgeRequest: Decodable {
    let operation: String
    let expectedRevision: String?
    let credentials: [VaultCredential]?
    let scope: SnapshotScope?
    var passwordUnlock: PasswordUnlockMaterial?
    var unlockKey: Data?
    var session: Data?
    var vault: VaultData?
    var clearingPolicy: PendingPolicyMutation?
    var pendingPolicy: PendingPolicyMutation?
    var organizationID: String?
    var secret: String?
    let secretProtocol: Int?
    let secretNotAfter: Double?
}

private struct DisplayCredential: Encodable {
    let id: String
    let title: String
    let username: String
    let url: String
    init(_ item: VaultCredential) { id=item.id; title=item.title; username=item.username; url=item.url }
}

private struct BridgeStatus: Encodable {
    let revision: String
    let available: Bool
    let count: Int
    let indexPending: Bool
    let cleanupPending: Bool
    let snapshotID: String?
    let scope: SnapshotScope?
    let updatedAt: Date?
    let passwordUnlock: PasswordUnlockConfig?
    init(_ state: SnapshotState) {
        revision = state.revision
        available = state.snapshot != nil && !state.signedOut
        count = state.snapshot?.header.count ?? 0
        indexPending = state.indexPending
        cleanupPending = !state.retiredKeys.isEmpty
        snapshotID = state.snapshot?.header.id
        scope = state.snapshot?.header.scope
        updatedAt = state.snapshot?.header.createdAt
        passwordUnlock = state.snapshot?.passwordUnlock?.config
    }
}

private struct BridgeReply: Encodable {
    var ok: Bool
    var code: String
    var message: String
    var state: BridgeStatus?
    var items: [DisplayCredential]? = nil
    var truncated: Bool? = nil
    var deviceID: String? = nil
    var session: Data? = nil
    var vault: VaultData? = nil
}

private var secretClipboard: SensitiveClipboard?

// Copy is called synchronously from the Go UI thread. Worker callers enter the
// main queue before acquiring a snapshot file lease; never dispatch to the UI
// while holding a store lock. Cleanup uses the same ordering.
private func onClipboardThread<T>(_ body: () throws -> T) rethrows -> T {
    if Thread.isMainThread { return try body() }
    return try DispatchQueue.main.sync(execute: body)
}

private func clearSecretClipboard() {
    onClipboardThread { secretClipboard?.clear() }
}

private func execute(_ request: BridgeRequest) -> BridgeReply {
    var store: SnapshotStore?
    do {
        if request.operation == "clearSecretClipboard" {
            clearSecretClipboard()
            return BridgeReply(ok: true, code: "ok", message: "", state: nil)
        }
        let vault = try SnapshotStore.sharedContainer()
        store = vault
        func expected() throws -> String {
            guard let revision = request.expectedRevision else { throw SnapshotError.invalidInput }
            return revision
        }
        switch request.operation {
        case "authorizeSecretDisplay":
            guard request.secretProtocol == 1, let scope = request.scope,
                  let key = request.unlockKey, let notAfter = request.secretNotAfter else { throw SnapshotError.invalidInput }
            return try onClipboardThread {
                try vault.withSecretCopyAuthorization(scope: scope, expected: expected(), unlockKey: key, notAfter: notAfter) { _ in
                    BridgeReply(ok: true, code: "ok", message: "", state: nil)
                }
            }
        case "copySecret":
            guard request.secretProtocol == 1, let secret = request.secret,
                  !secret.isEmpty, secret.utf8.count <= 65536,
                  let scope = request.scope, let unlockKey = request.unlockKey,
                  let notAfter = request.secretNotAfter, notAfter.isFinite else { throw SnapshotError.invalidInput }
            return try onClipboardThread {
                return try vault.withSecretCopyAuthorization(scope: scope, expected: expected(), unlockKey: unlockKey, notAfter: notAfter) { remaining in
                    if secretClipboard == nil { secretClipboard = SensitiveClipboard(board: NativeSensitivePasteboard(.general)) }
                    guard let clipboard = secretClipboard else { throw SnapshotError.configuration }
                    let receipt = try clipboard.copy(secret)
                    DispatchQueue.main.asyncAfter(deadline: .now() + remaining) { clipboard.clear(ifOwned: receipt) }
                    return BridgeReply(ok: true, code: "ok", message: "", state: nil)
                }
            }
        case "status":
            let state = try vault.state()
            // Repair legacy/late candidates on a signed-out vault without authentication.
            if state.snapshot == nil && state.indexPending { SnapshotIndex.schedule(store: vault, lease: nil) }
        case "settings":
            let settings = UserDefaults.standard
            let deviceID = settings.string(forKey: "vaultwardenDeviceID") ?? UUID().uuidString
            settings.set(deviceID, forKey: "vaultwardenDeviceID")
            return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(try vault.state()), deviceID: deviceID)
        case "publishVault", "restoreOrganizationAccess", "restorePolicyAccess":
            guard let credentials = request.credentials, credentials.allSatisfy({ $0.uris != nil }),
                  let scope = request.scope, scope.valid, scope != .demo else { throw SnapshotError.invalidInput }
            if request.operation == "restorePolicyAccess" && request.clearingPolicy == nil { throw SnapshotError.invalidInput }
            if request.operation == "restoreOrganizationAccess" && request.organizationID == nil { throw SnapshotError.invalidInput }
            let lease = try vault.publish(credentials, scope: scope, expected: expected(), passwordUnlock: request.passwordUnlock, session: request.session, vault: request.vault, includeVault: true, restoringOrganization: request.operation != "publishVault" ? request.organizationID : nil, clearingPolicy: request.operation == "restorePolicyAccess" ? request.clearingPolicy : nil)
            SnapshotIndex.schedule(store: vault, lease: lease)
            // Do not return a later writer's revision as this session's write authority.
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: "快照已保存。", state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "quarantineOrganization":
            guard let scope = request.scope, let id = request.organizationID, let key = request.unlockKey, let session = request.session else { throw SnapshotError.invalidInput }
            defer { clearSecretClipboard() }
            let lease = try vault.quarantineOrganization(id, scope: scope, expected: expected(), unlockKey: key, session: session, pendingPolicy: request.pendingPolicy)
            SnapshotIndex.schedule(store: vault, lease: lease)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: "该组织的本机访问已隔离。", state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "saveSession":
            guard let scope = request.scope, let session = request.session, let key = request.unlockKey else { throw SnapshotError.invalidInput }
            let lease = try vault.saveSession(session, scope: scope, expected: expected(), unlockKey: key)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: "登录凭据已安全更新。", state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "lock":
            defer { clearSecretClipboard() }
            try vault.lock()
        case "logout":
            defer { clearSecretClipboard() }
            // Index clear is scheduled even when key cleanup returns an error after
            // the tombstone was committed. Callers still receive that cleanup failure.
            defer {
                if let state = try? vault.state(), state.snapshot == nil { SnapshotIndex.schedule(store: vault, lease: nil) }
            }
            try vault.logout(expected: expected())
        case "retryCleanup":
            try vault.retryCleanup()
        case "listPassword":
            guard let scope = request.scope, let unlockKey = request.unlockKey else { throw SnapshotError.invalidInput }
            let lease = try vault.unlockWithPassword(scope: scope, expected: expected(), unlockKey: unlockKey)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: "密码库已解锁。", state: BridgeStatus(try vault.files.read()),
                            items: lease.credentials.map(DisplayCredential.init), truncated: false, session: lease.session, vault: lease.vault)
            }
        case "reindex", "list":
            let context = LAContext()
            defer { context.invalidate() }
            guard let scope = try vault.state().snapshot?.header.scope else { throw SnapshotError.unavailable }
            let lease = try vault.unlock(scope: scope, context: context, allowUI: true, includeSession: request.operation == "list")
            if request.operation == "list" {
                guard lease.revision == request.expectedRevision else { throw SnapshotError.stale }
                return try vault.withCurrentLease(lease) {
                    BridgeReply(ok: true, code: "ok", message: "离线快照已解锁。", state: BridgeStatus(try vault.files.read()),
                                items: lease.credentials.map(DisplayCredential.init), truncated: false, session: lease.session, vault: lease.vault)
                }
            }
            if request.operation == "reindex" { SnapshotIndex.schedule(store: vault, lease: lease) }
        default: throw SnapshotError.invalidInput
        }
        let state = try vault.state()
        var message = "存储操作已完成。"
        if state.indexPending { message += "系统候选尚未确认同步。" }
        if !state.retiredKeys.isEmpty { message += "旧密钥清理待重试。" }
        return BridgeReply(ok: true, code: "ok", message: message, state: BridgeStatus(state))
    } catch {
        let issue = error as? SnapshotError ?? .configuration
        return BridgeReply(ok: false, code: issue.code, message: issue.message,
                           state: (try? store?.state()).map(BridgeStatus.init))
    }
}

// Synchronous C ABI. Go calls on a worker goroutine; no pointer escapes the call.
// Only authenticated list operations return the encrypted payload's saved session
// to the main app; status/index operations and AutoFill leases never return it.
// Vault entry passwords and the snapshot encryption key never leave this bridge.
@_cdecl("mygo_snapshot_execute")
public func mygoSnapshotExecute(_ request: UnsafePointer<UInt8>?, _ requestLength: Int,
                                _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard let request, let output, requestLength > 0, requestLength <= 4 * 1024 * 1024,
          capacity >= 1024, capacity <= 4 * 1024 * 1024 else { return -1 }
    return autoreleasepool {
        let reply: BridgeReply
        do {
            var parsed = try JSONDecoder().decode(BridgeRequest.self, from: Data(bytes: request, count: requestLength))
            defer {
                parsed.secret = nil
                if let count = parsed.passwordUnlock?.key.count { parsed.passwordUnlock?.key.resetBytes(in: 0..<count) }
                if let count = parsed.unlockKey?.count { parsed.unlockKey?.resetBytes(in: 0..<count) }
                if let count = parsed.session?.count { parsed.session?.resetBytes(in: 0..<count) }
            }
            reply = execute(parsed)
        } catch {
            reply = BridgeReply(ok: false, code: "invalid_input", message: "无法识别请求。", state: nil)
        }
        guard let data = try? snapshotJSON(reply), data.count <= capacity else { return -2 }
        data.copyBytes(to: output, count: data.count)
        return Int32(data.count)
    }
}
