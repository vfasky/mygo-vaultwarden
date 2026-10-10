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
    var recoveryBinding: AccountRecoveryBinding?
    var recoveryRecord: Data?
    var recoveryPhase: String?
    var recoveryResolution: AccountRecoveryResolution?
    var targetBinding: TargetRecoveryBinding?
    var targetSummary: Data?
    var targetPhase: String?
    var targetRuntime: RuntimeRecoveryAuthority?
    var targetLogin: TargetRecoveryResolution?
    var targetResolution: TargetRecoveryResolution?
    var switchBinding: AccountSwitchBinding?
    var switchOperationID: String?
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
    let targetRecoveryPresent: Bool
    let recoveryPending: Bool
    let accountSwitchPending: Bool
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
        targetRecoveryPresent = state.targetRecovery != nil
        recoveryPending = state.snapshot?.header.format == 2
        accountSwitchPending = state.accountSwitchPending
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
    var targetProtection: TargetRecoveryProtection? = nil
    var targetRecords: [TargetRecoveryRecord]? = nil
    var recovery: AccountRecoveryJournal? = nil
    var accountSwitch: AccountSwitchReceipt? = nil
}

private var secretClipboard: SensitiveClipboard?

private func bridgeStore() throws -> SnapshotStore {
#if SNAPSHOT_BRIDGE_TESTING
    return try snapshotBridgeTestStore()
#else
    return try SnapshotStore.sharedContainer()
#endif
}

private func scheduleBridgeIndex(store: SnapshotStore, lease: SnapshotLease?) {
#if !SNAPSHOT_BRIDGE_TESTING
    SnapshotIndex.schedule(store: store, lease: lease)
#endif
}

// Copy is called synchronously from the Go UI thread. Worker callers enter the
// main queue before acquiring a snapshot file lease; never dispatch to the UI
// while holding a store lock. Cleanup uses the same ordering.
private func onClipboardThread<T>(_ body: () throws -> T) rethrows -> T {
    if Thread.isMainThread { return try body() }
    return try DispatchQueue.main.sync(execute: body)
}

private func clearSecretClipboard() {
#if !SNAPSHOT_BRIDGE_TESTING
    onClipboardThread { secretClipboard?.clear() }
#endif
}

private func execute(_ request: BridgeRequest) -> BridgeReply {
    var store: SnapshotStore?
    do {
        if request.operation == "clearSecretClipboard" {
            clearSecretClipboard()
            return BridgeReply(ok: true, code: "ok", message: "", state: nil)
        }
        let vault = try bridgeStore()
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
        case "publishBoundAccount":
            guard let binding = request.switchBinding, request.scope == binding.target,
                  let credentials = request.credentials, let material = request.passwordUnlock,
                  let session = request.session, let data = request.vault else { throw SnapshotError.invalidInput }
            let lease = try vault.publishBoundAccount(credentials,binding:binding,expected:expected(),material:material,session:session,vault:data)
            scheduleBridgeIndex(store:vault,lease:nil)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok:true,code:"switch_pending",message:L10n.t("bridge.account_switch.status_pending"),state:BridgeStatus(try vault.files.read()),vault:lease.vault,
                            accountSwitch:AccountSwitchReceipt(binding:binding,newSnapshotID:lease.header.id,phase:"pending"))
            }
        case "inspectAccountSwitch":
            let result = try vault.inspectAccountSwitch(expected:expected(),operationID:request.switchOperationID)
            return BridgeReply(ok:true,code:"ok",message:L10n.t("bridge.account_switch.status_authenticated"),state:BridgeStatus(result.0),accountSwitch:result.1)
        case "confirmAccountSwitch":
            guard let operationID = request.switchOperationID else { throw SnapshotError.invalidInput }
            let result = try vault.confirmAccountSwitch(expected:expected(),operationID:operationID,unlockKey:request.unlockKey)
            try? vault.retryCleanup()
            if !result.0.recoveryOnly { scheduleBridgeIndex(store:vault,lease:result.0) }
            return try vault.withCurrentLease(result.0) {
                BridgeReply(ok:true,code:result.0.recoveryOnly ? "target_recovery_pending" : "ok",message:result.0.recoveryOnly ? L10n.t("bridge.account_switch.status_recovery_pending") : L10n.t("bridge.account_switch.status_confirmed"),state:BridgeStatus(try vault.files.read()),items:result.0.credentials.map(DisplayCredential.init),session:result.0.session,vault:result.0.vault,accountSwitch:result.1)
            }
        case "targetRecoveryBegin", "targetRecoveryQuery", "targetRecoveryPending", "targetRecoveryRuntimePending", "targetRecoveryResult", "targetRecoveryVerify":
            guard let scope = request.scope, request.unlockKey != nil || request.targetRuntime != nil else { throw SnapshotError.invalidInput }
            let key = request.unlockKey ?? Data()
            let (state, records) = try vault.targetRecovery(operation: request.operation, scope: scope,
                expected: expected(), unlockKey: key, binding: request.targetBinding, summary: request.targetSummary,
                phase: request.targetPhase, resolution: request.targetResolution, vault: request.vault,
                session: request.session, material: request.passwordUnlock, login: request.targetLogin, runtime: request.targetRuntime)
            // Clear clipboard only when this operation actually blocks the active target.
            if records.contains(where: { $0.requireTargetLogin && $0.binding.target == state.snapshot?.header.scope && $0.phase != "resolved" }) {
                clearSecretClipboard()
                scheduleBridgeIndex(store: vault, lease: nil)
            }
            return try vault.files.locked {
                guard try vault.files.read().revision == state.revision else { throw SnapshotError.stale }
                return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(state), targetRecords: records)
            }
        case "targetRecoveryInspectLocal":
            guard let binding = request.targetBinding, request.scope == binding.target else { throw SnapshotError.invalidInput }
            let (state, protection, journal) = try vault.inspectLocalTarget(binding: binding, expected: expected())
            return try vault.files.locked {
                guard try vault.files.read().revision == state.revision else { throw SnapshotError.stale }
                return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(state), targetProtection: protection,
                    targetRecords: try vault.files.targetRecords(state).filter { $0.binding == binding }, recovery: journal)
            }
        case "targetRecoveryResolveLocal":
            guard let proof = request.targetResolution, proof.binding == request.targetBinding,
                  proof.expectedRevision == (try expected()), let credentials = request.credentials,
                  let material = request.passwordUnlock, let session = request.session, let data = request.vault else { throw SnapshotError.invalidInput }
            let lease = try vault.resolveLocalTarget(proof: proof, credentials: credentials, material: material, session: session, vault: data)
            scheduleBridgeIndex(store: vault, lease: lease)
            return try vault.withCurrentLease(lease) {
                let state = try vault.files.read()
                return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(state), vault: lease.vault,
                    targetRecords: try vault.files.targetRecords(state).filter { $0.binding == proof.binding })
            }
        case "targetRecoveryResolve":
            guard let scope = request.scope, let proof = request.targetResolution, proof.target == scope, request.targetBinding == proof.binding,
                  let credentials = request.credentials else { throw SnapshotError.invalidInput }
            let lease = try vault.publish(credentials, scope: scope, expected: expected(), passwordUnlock: request.passwordUnlock,
                session: request.session, vault: request.vault, priorUnlockKey: request.unlockKey, includeVault: true, targetResolution: proof)
            scheduleBridgeIndex(store: vault, lease: lease)
            return try vault.withCurrentLease(lease) {
                let state = try vault.files.read()
                return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(state), vault: lease.vault,
                    targetRecords: try vault.files.targetRecords(state).filter { $0.binding == proof.binding })
            }
        case "accountRecoveryBegin", "accountRecoveryQuery", "accountRecoveryResult", "accountRecoveryCheckpoint", "accountRecoveryResolve":
            guard let scope = request.scope, let key = request.unlockKey else { throw SnapshotError.invalidInput }
            defer { clearSecretClipboard() }
            let (lease, journal) = try vault.accountRecovery(operation: request.operation, scope: scope,
                expected: expected(), unlockKey: key, binding: request.recoveryBinding, record: request.recoveryRecord,
                phase: request.recoveryPhase, resolution: request.recoveryResolution, credentials: request.credentials,
                material: request.passwordUnlock, session: request.session, vault: request.vault)
            if request.recoveryResolution?.mode == "delete" {
                scheduleBridgeIndex(store: vault, lease: nil)
                return try vault.files.locked {
                    let state = try vault.files.read()
                    guard state.revision == lease.revision, state.signedOut, state.snapshot == nil else { throw SnapshotError.stale }
                    return BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(state))
                }
            }
            scheduleBridgeIndex(store: vault, lease: lease)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: "", state: BridgeStatus(try vault.files.read()),
                    vault: lease.vault, recovery: journal)
            }
        case "status":
            let state = try vault.state()
            // Repair legacy/late candidates on a signed-out vault without authentication.
            if state.snapshot == nil && state.indexPending { scheduleBridgeIndex(store: vault, lease: nil) }
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
            scheduleBridgeIndex(store: vault, lease: lease)
            // Do not return a later writer's revision as this session's write authority.
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: L10n.t("bridge.status_snapshot_saved"), state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "quarantineOrganization":
            guard let scope = request.scope, let id = request.organizationID, let key = request.unlockKey, let session = request.session else { throw SnapshotError.invalidInput }
            defer { clearSecretClipboard() }
            let lease = try vault.quarantineOrganization(id, scope: scope, expected: expected(), unlockKey: key, session: session, pendingPolicy: request.pendingPolicy)
            scheduleBridgeIndex(store: vault, lease: lease)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: L10n.t("bridge.status_organization_quarantined"), state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "saveSession":
            guard let scope = request.scope, let session = request.session, let key = request.unlockKey else { throw SnapshotError.invalidInput }
            let lease = try vault.saveSession(session, scope: scope, expected: expected(), unlockKey: key)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: L10n.t("bridge.status_credentials_updated"), state: BridgeStatus(try vault.files.read()), vault: lease.vault)
            }
        case "lock":
            defer { clearSecretClipboard() }
            try vault.lock()
        case "logout":
            defer { clearSecretClipboard() }
            // Index clear is scheduled even when key cleanup returns an error after
            // the tombstone was committed. Callers still receive that cleanup failure.
            defer {
                if let state = try? vault.state(), state.snapshot == nil { scheduleBridgeIndex(store: vault, lease: nil) }
            }
            try vault.logout(expected: expected())
        case "retryCleanup":
            try vault.retryCleanup()
        case "listPassword":
            guard let scope = request.scope, let unlockKey = request.unlockKey else { throw SnapshotError.invalidInput }
            let lease = try vault.unlockWithPassword(scope: scope, expected: expected(), unlockKey: unlockKey)
            return try vault.withCurrentLease(lease) {
                BridgeReply(ok: true, code: "ok", message: L10n.t("bridge.status_vault_unlocked"), state: BridgeStatus(try vault.files.read()),
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
                    BridgeReply(ok: true, code: "ok", message: L10n.t("bridge.status_snapshot_unlocked"), state: BridgeStatus(try vault.files.read()),
                                items: lease.credentials.map(DisplayCredential.init), truncated: false, session: lease.session, vault: lease.vault)
                }
            }
            if request.operation == "reindex" { scheduleBridgeIndex(store: vault, lease: lease) }
        default: throw SnapshotError.invalidInput
        }
        let state = try vault.state()
        var message = L10n.t("bridge.status_storage_completed")
        if state.indexPending { message += L10n.t("bridge.status_index_pending") }
        if !state.retiredKeys.isEmpty { message += L10n.t("bridge.status_cleanup_pending") }
        return BridgeReply(ok: true, code: "ok", message: message, state: BridgeStatus(state))
    } catch {
        let issue = error as? SnapshotError ?? .configuration
        return BridgeReply(ok: false, code: issue.code, message: issue.message,
                           state: (try? store?.state()).map(BridgeStatus.init))
    }
}

private let snapshotTransfer = SnapshotTransfer()

private func executeTransfer(_ frame: SnapshotTransferFrame) throws -> SnapshotTransferReply {
    try snapshotTransfer.exchange(frame) { input in
        var parsed = try JSONDecoder().decode(BridgeRequest.self, from: input)
        defer {
            if let count = parsed.passwordUnlock?.key.count { parsed.passwordUnlock?.key.resetBytes(in: 0..<count) }
            if let count = parsed.unlockKey?.count { parsed.unlockKey?.resetBytes(in: 0..<count) }
            if let count = parsed.session?.count { parsed.session?.resetBytes(in: 0..<count) }
        }
        guard ["publishBoundAccount", "inspectAccountSwitch", "confirmAccountSwitch", "targetRecoveryInspectLocal", "targetRecoveryResolveLocal", "targetRecoveryBegin", "targetRecoveryQuery", "targetRecoveryPending", "targetRecoveryRuntimePending", "targetRecoveryResult", "targetRecoveryVerify", "targetRecoveryResolve", "accountRecoveryBegin", "accountRecoveryQuery", "accountRecoveryResult", "accountRecoveryCheckpoint", "accountRecoveryResolve", "publishVault", "restoreOrganizationAccess", "restorePolicyAccess", "quarantineOrganization", "saveSession", "listPassword", "list", "reindex"].contains(parsed.operation) else { throw SnapshotError.invalidInput }
        let expires = ProcessInfo.processInfo.systemUptime + 60
        let reply = execute(parsed)
        let encoded = try snapshotJSON(reply)
        if !reply.ok { return (encoded, { bytes, range in bytes.subdata(in: range) }) }
        guard let receipt = reply.state else { throw SnapshotError.stale }
        let store = try bridgeStore()
        if reply.accountSwitch != nil {
            return (encoded, { bytes, range in
                try store.files.locked {
                    guard ProcessInfo.processInfo.systemUptime < expires,
                          try store.files.read().revision == receipt.revision else { throw SnapshotError.stale }
                    return bytes.subdata(in: range)
                }
            })
        }
        if reply.targetRecords != nil {
            return (encoded, { bytes, range in
                try store.files.locked {
                    guard ProcessInfo.processInfo.systemUptime < expires,
                          try store.files.read().revision == receipt.revision else { throw SnapshotError.stale }
                    return bytes.subdata(in: range)
                }
            })
        }
        if parsed.operation == "accountRecoveryResolve", parsed.recoveryResolution?.mode == "delete" {
            return (encoded, { bytes, range in
                try store.files.locked {
                    let current = try store.files.read()
                    guard current.revision == receipt.revision, current.signedOut, current.snapshot == nil else { throw SnapshotError.stale }
                    return bytes.subdata(in: range)
                }
            })
        }
        guard receipt.available, let scope = receipt.scope else { throw SnapshotError.stale }
        let current = try store.state()
        guard current.revision == receipt.revision, let snapshot = current.snapshot,
              snapshot.header.id == receipt.snapshotID, snapshot.header.scope == scope else { throw SnapshotError.stale }
        let lease = SnapshotLease(revision: receipt.revision, header: snapshot.header, expiresAt: expires, credentials: [], recoveryOnly: reply.recovery != nil || reply.targetRecords != nil || parsed.operation == "accountRecoveryResolve")
        return (encoded, { bytes, range in
            try store.withCurrentLease(lease) { bytes.subdata(in: range) }
        })
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
        let input = Data(bytes: request, count: requestLength)
        if let frame = try? JSONDecoder().decode(SnapshotTransferFrame.self, from: input), frame.operation == "__transfer_v1" {
            let result: SnapshotTransferReply
            do { result = try executeTransfer(frame) }
            catch { result = SnapshotTransferReply(ok: false) }
            guard let data = try? snapshotJSON(result), data.count <= capacity else { return -2 }
            data.copyBytes(to: output, count: data.count)
            return Int32(data.count)
        }
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
            reply = BridgeReply(ok: false, code: "invalid_input", message: L10n.t("bridge.err_unrecognized_request"), state: nil)
        }
        guard let data = try? snapshotJSON(reply), data.count <= capacity else { return -2 }
        data.copyBytes(to: output, count: data.count)
        return Int32(data.count)
    }
}
