// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit
import AppKit

struct RuntimeSecretRequest: Codable {
    var operation: String
    let purpose: String
    let scope: SnapshotScope
    let generation: UInt64
    let deadlineUnixMS: Int64
    var leaseID: String? = nil
    var operationID: String? = nil
    var summaryHash: String? = nil
    var requestID: String? = nil
    var secret: String? = nil
}
struct RuntimeSecretReply: Codable {
    let ok: Bool
    let code: String
    var leaseID: String? = nil
    var generation: UInt64? = nil
    var deadlineUnixMS: Int64? = nil
}
struct RuntimeRecoveryAuthority: Codable {
    let scope: SnapshotScope
    let generation: UInt64
    let deadlineUnixMS: Int64
    let leaseID: String
    let operationID: String
    let summaryHash: String
}

// At most one secret lease and one recovery-purpose lease. Native checks local
// lifetime/binding only; the trusted Go controller supplies actual Session proof.
// Clipboard operations/expiry execute on main; recovery validation is read-only
// under this mutex and is safe in BeforeDispatch without hopping to main.
final class RuntimeSecretLeases {
    private struct Lease {
        let request: RuntimeSecretRequest
        let id: String
        let expires: TimeInterval
        var copies: [String: String] = [:]
    }
    private let mutex = NSLock()
    private let board: SensitivePasteboard
    private let wall: () -> Int64
    private let monotonic: () -> TimeInterval
    private var generation: UInt64 = 0
    private var scope: SnapshotScope?
    private var leases: [String: Lease] = [:]
    private var activated = Set<String>()
    private var clipboardOwner: (lease: String, owner: String, count: Int)?
    private var timer: DispatchWorkItem?
    init(board: SensitivePasteboard,
         wall: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
         monotonic: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.board = board; self.wall = wall; self.monotonic = monotonic
    }
    deinit { timer?.cancel() }
    private func clearOwned(_ lease: String? = nil) {
        guard let owner = clipboardOwner, lease == nil || owner.lease == lease else { return }
        clipboardOwner = nil
        if board.changeCount == owner.count, board.owner == owner.owner, board.changeCount == owner.count { board.clear() }
    }
    func expire() {
        mutex.lock(); defer { mutex.unlock() }
        expireLocked()
    }
    private func expireLocked() {
        for (purpose, lease) in leases where monotonic() >= lease.expires || wall() >= lease.request.deadlineUnixMS {
            clearOwned(lease.id); leases[purpose] = nil
        }
    }
    private func scheduleLocked() {
        timer?.cancel()
        guard let earliest = leases.values.map(\.expires).min() else { timer = nil; return }
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.mutex.lock(); defer { self.mutex.unlock() }
            self.expireLocked(); self.scheduleLocked()
        }
        timer = item
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0.001, earliest - monotonic()), execute: item)
    }
    private func matches(_ request: RuntimeSecretRequest, _ lease: Lease) -> Bool {
        request.scope == lease.request.scope && request.generation == lease.request.generation &&
        request.purpose == lease.request.purpose && request.deadlineUnixMS == lease.request.deadlineUnixMS &&
        request.operationID == lease.request.operationID && request.summaryHash == lease.request.summaryHash &&
        request.leaseID == lease.id
    }
    func execute(_ request: RuntimeSecretRequest) -> RuntimeSecretReply {
        mutex.lock(); defer { mutex.unlock() }
        expireLocked()
        func failed(_ code: String) -> RuntimeSecretReply { RuntimeSecretReply(ok: false, code: code) }
        guard request.scope.valid, request.generation > 0, ["secret", "recovery"].contains(request.purpose) else { return failed("invalid_input") }
        if request.operation == "activate" {
            let wallNow = wall()
            guard request.secret == nil, request.leaseID == nil, request.requestID == nil,
                  request.deadlineUnixMS > wallNow, request.deadlineUnixMS - wallNow <= 30000,
                  (request.purpose == "secret" && request.operationID == nil && request.summaryHash == nil) ||
                  (request.purpose == "recovery" && request.operationID?.count == 32 && targetHashValid(request.summaryHash ?? "")) else { return failed("invalid_input") }
            guard request.generation >= generation else { return failed("stale_generation") }
            if request.generation > generation {
                clearOwned(); leases.removeAll(); activated.removeAll()
                generation = request.generation; scope = request.scope
            }
            guard scope == request.scope else { return failed("wrong_scope") }
            if let lease = leases[request.purpose] {
                guard request.deadlineUnixMS == lease.request.deadlineUnixMS,
                      request.operationID == lease.request.operationID, request.summaryHash == lease.request.summaryHash else { return failed("binding_mismatch") }
                return RuntimeSecretReply(ok: true, code: "ok", leaseID: lease.id, generation: generation, deadlineUnixMS: lease.request.deadlineUnixMS)
            }
            guard !activated.contains(request.purpose) else { return failed("revoked") }
            let id = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() }
            leases[request.purpose] = Lease(request: request, id: id, expires: monotonic() + Double(request.deadlineUnixMS - wallNow) / 1000)
            activated.insert(request.purpose); scheduleLocked()
            return RuntimeSecretReply(ok: true, code: "ok", leaseID: id, generation: generation, deadlineUnixMS: request.deadlineUnixMS)
        }
        guard var lease = leases[request.purpose], matches(request, lease) else { return failed("invalid_lease") }
        switch request.operation {
        case "authorizeDisplay":
            guard request.purpose == "secret", request.secret == nil else { return failed("wrong_purpose") }
        case "copy":
            guard request.purpose == "secret", let secret = request.secret, !secret.isEmpty, secret.utf8.count <= 65536,
                  let id = request.requestID, UUID(uuidString: id) != nil else { return failed("invalid_input") }
            let hash = targetDigest(Data(secret.utf8))
            if let previous = lease.copies[id] {
                guard previous == hash else { return failed("binding_mismatch") }
            } else {
                guard lease.copies.count < 64 else { return failed("limit") }
                let owner = UUID().uuidString
                guard board.replace(secret: secret, owner: owner) else { return failed("clipboard_failed") }
                clipboardOwner = (lease.id, owner, board.changeCount)
                lease.copies[id] = hash; leases[request.purpose] = lease
            }
        case "revoke":
            guard request.secret == nil else { return failed("invalid_input") }
            clearOwned(lease.id); leases[request.purpose] = nil; scheduleLocked()
        default: return failed("invalid_input")
        }
        return RuntimeSecretReply(ok: true, code: "ok", leaseID: lease.id, generation: lease.request.generation, deadlineUnixMS: lease.request.deadlineUnixMS)
    }
    func authorizeRecovery(_ authority: RuntimeRecoveryAuthority) throws {
        mutex.lock(); defer { mutex.unlock() }
        guard let lease = leases["recovery"], lease.id == authority.leaseID,
              lease.request.scope == authority.scope, lease.request.generation == authority.generation,
              lease.request.deadlineUnixMS == authority.deadlineUnixMS,
              lease.request.operationID == authority.operationID, lease.request.summaryHash == authority.summaryHash,
              monotonic() < lease.expires, wall() < lease.request.deadlineUnixMS else { throw SnapshotError.expired }
    }
}

#if SNAPSHOT_BRIDGE_TESTING
private final class RuntimeBridgeMemoryPasteboard: SensitivePasteboard {
    var changeCount = 0
    var owner: String?
    func replace(secret: String, owner: String) -> Bool { changeCount += 1; self.owner = owner; return true }
    func clear() { changeCount += 1; owner = nil }
}
private let runtimeSecretLeases = RuntimeSecretLeases(board: RuntimeBridgeMemoryPasteboard())
#else
private final class RuntimeNativePasteboard: SensitivePasteboard {
    // Invalid recovery requests may arrive on a worker before any UI activation.
    // Do not even obtain the native pasteboard until a main-thread clipboard action.
    private lazy var native = NativeSensitivePasteboard(.general)
    var changeCount: Int { native.changeCount }
    var owner: String? { native.owner }
    func replace(secret: String, owner: String) -> Bool { native.replace(secret: secret, owner: owner) }
    func clear() { native.clear() }
}
private let runtimeSecretLeases = RuntimeSecretLeases(board: RuntimeNativePasteboard())
#endif
func authorizeRuntimeRecovery(_ authority: RuntimeRecoveryAuthority) throws { try runtimeSecretLeases.authorizeRecovery(authority) }

@_cdecl("mygo_runtime_secret_execute")
public func mygoRuntimeSecretExecute(_ request: UnsafePointer<UInt8>?, _ requestLength: Int,
                                    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard let request, let output, requestLength > 0, requestLength <= 96 * 1024, capacity >= 1024, capacity <= 96 * 1024 else { return -1 }
    return autoreleasepool {
        let reply: RuntimeSecretReply
#if !SNAPSHOT_BRIDGE_TESTING
        if !Thread.isMainThread {
            let data = try! JSONEncoder().encode(RuntimeSecretReply(ok: false, code: "wrong_thread"))
            guard data.count <= capacity else { return -2 }
            data.copyBytes(to: output, count: data.count); return Int32(data.count)
        }
#endif
        do {
            let input = Data(bytes: request, count: requestLength)
            _ = try targetStrictObject(input, keys: ["operation", "purpose", "scope", "generation", "deadlineUnixMS", "leaseID", "operationID", "summaryHash", "requestID", "secret"])
            var parsed = try JSONDecoder().decode(RuntimeSecretRequest.self, from: input)
            defer { parsed.secret = nil }
            reply = runtimeSecretLeases.execute(parsed)
        } catch { reply = RuntimeSecretReply(ok: false, code: "invalid_input") }
        guard let data = try? JSONEncoder().encode(reply), data.count <= capacity else { return -2 }
        data.copyBytes(to: output, count: data.count); return Int32(data.count)
    }
}
