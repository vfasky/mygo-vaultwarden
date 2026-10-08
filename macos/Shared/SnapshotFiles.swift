// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin
import CryptoKit

// A fresh fd per operation also serializes different store instances in one process.
final class SnapshotFileLock {
    private var fd: Int32
    init(url: URL, timeout: TimeInterval = 2) throws {
        fd = Darwin.open(url.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw SnapshotError.configuration }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            if errno == EINTR { continue }
            if errno != EWOULDBLOCK || ProcessInfo.processInfo.systemUptime >= deadline {
                Darwin.close(fd)
                fd = -1
                throw SnapshotError.busy
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }
    func release() {
        if fd >= 0 { flock(fd, LOCK_UN); Darwin.close(fd); fd = -1 }
    }
    deinit { release() }
}

final class SnapshotFiles {
    let directory: URL
    private let stateURL: URL
    let recoveryKeys: SnapshotKeyStore?
    // Isolated tests inject the uncertain-commit boundary; production leaves nil.
    var afterRenameForTesting: (() throws -> Void)? = nil
    init(directory: URL, recoveryKeys: SnapshotKeyStore? = nil) throws {
        self.recoveryKeys = recoveryKeys
        self.directory = directory
        self.stateURL = directory.appendingPathComponent("snapshot-v1.json")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        let values = try directory.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else { throw SnapshotError.configuration }
    }
    func locked<T>(_ body: () throws -> T) throws -> T {
        let lock = try SnapshotFileLock(url: directory.appendingPathComponent("state.lock"))
        defer { withExtendedLifetime(lock) {} }
        return try body()
    }
    // The caller holds state.lock. Missing is an empty vault; unreadable/corrupt is NOT.
    func read() throws -> SnapshotState {
        let fd = Darwin.open(stateURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return SnapshotState() }
            throw SnapshotError.corrupt
        }
        defer { Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size > 0, info.st_size <= 96 * 1024 * 1024 else { throw SnapshotError.corrupt }
        var data = Data(count: Int(info.st_size))
        try data.withUnsafeMutableBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw SnapshotError.corrupt }
                offset += n
            }
        }
        do {
            if let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let target = root["targetRecovery"] {
                _ = try targetStrictObject(JSONSerialization.data(withJSONObject: target), keys: ["version", "sealed"])
            }
            if let root = try JSONSerialization.jsonObject(with: data) as? [String: Any], let accountSwitch = root["accountSwitch"] {
                _ = try targetStrictObject(JSONSerialization.data(withJSONObject: accountSwitch), keys: ["version", "pending", "sealed"])
            }
            let state = try snapshotDecode(SnapshotState.self, from: data)
            try state.validate()
            _ = try targetRecords(state)
            _ = try accountSwitchRecord(state)
            return state
        } catch { throw SnapshotError.corrupt }
    }
    // Only ciphertext and non-secret control metadata reach disk, including temp files.
    func write(_ state: SnapshotState) throws {
        try state.validate()
        _ = try accountSwitchRecord(state)
        let data = try snapshotJSON(state)
        guard data.count <= 96 * 1024 * 1024 else { throw state.accountSwitchPending ? SnapshotError.accountSwitchTooLarge : SnapshotError.invalidInput }
        let temp = directory.appendingPathComponent(".snapshot-\(UUID().uuidString).tmp")
        let fd = Darwin.open(temp.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw SnapshotError.configuration }
        defer { Darwin.close(fd); try? FileManager.default.removeItem(at: temp) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw SnapshotError.configuration }
                offset += n
            }
        }
        guard fsync(fd) == 0, rename(temp.path, stateURL.path) == 0 else { throw SnapshotError.configuration }
        try afterRenameForTesting?()
        let directoryFD = Darwin.open(directory.path, O_RDONLY | O_CLOEXEC)
        guard directoryFD >= 0 else { throw SnapshotError.configuration }
        defer { Darwin.close(directoryFD) }
        // A failed post-rename fsync is an unknown commit, never a durable
        // success. Recovery callers query the same operation and do not POST.
        guard fsync(directoryFD) == 0 else { throw SnapshotError.configuration }
    }
}

// Process-local transport only: no filesystem handles, paths or plaintext spool.
// A handle is a bounded transport capability, never snapshot authorization.
struct SnapshotTransferFrame: Codable {
    var operation = "__transfer_v1"
    let action: String
    var handle: String? = nil
    var offset: Int? = nil
    var total: Int? = nil
    var digest: String? = nil
    var data: Data? = nil
}
struct SnapshotTransferReply: Codable {
    var ok = true
    var handle: String? = nil
    var total: Int? = nil
    var digest: String? = nil
    var data: Data? = nil
}

final class SnapshotTransfer {
    static let chunkBytes = 256 * 1024
    static let maximumBytes = 64 * 1024 * 1024
    private final class Entry {
        let handle = UUID().uuidString
        let expires: TimeInterval
        let total: Int
        let digest: String
        var bytes = Data()
        var offset = 0
        var executing = false
        var read: ((Data, Range<Int>) throws -> Data)?
        var timer: DispatchSourceTimer?
        init(total: Int, digest: String, expires: TimeInterval) {
            self.total = total; self.digest = digest; self.expires = expires
        }
        deinit {
            timer?.cancel()
            bytes.resetBytes(in: 0..<bytes.count)
        }
    }
    private let mutex = NSLock()
    private var entry: Entry?
    private var executions = 0
    private let clock: () -> TimeInterval
    init(clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) { self.clock = clock }
    func cancel(_ handle: String) {
        mutex.lock(); defer { mutex.unlock() }
        if entry?.handle == handle { entry = nil }
    }
    // The executor must authenticate using the original operation and provide a
    // reader that checks its exact lease under the snapshot's cross-process lock.
    func exchange(_ frame: SnapshotTransferFrame,
                  execute: (Data) throws -> (Data, (Data, Range<Int>) throws -> Data)) throws -> SnapshotTransferReply {
        mutex.lock()
        var held = true
        defer { if held { mutex.unlock() } }
        if let current = entry, clock() >= current.expires { entry = nil }
        if frame.action == "begin" {
            guard entry == nil, executions == 0 else { throw SnapshotError.busy }
            guard let total = frame.total, total > 0, total <= Self.maximumBytes,
                  let digest = frame.digest, digest.count == 64,
                  digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw SnapshotError.invalidInput }
            let next = Entry(total: total, digest: digest, expires: clock() + 60)
            entry = next
            let handle = next.handle
            let timer = DispatchSource.makeTimerSource(queue: .global())
            timer.schedule(deadline: .now() + 60)
            timer.setEventHandler { [weak self] in self?.cancel(handle) }
            next.timer = timer
            timer.resume()
            return SnapshotTransferReply(handle: handle)
        }
        guard let current = entry, current.handle == frame.handle else { throw SnapshotError.stale }
        do {
            switch frame.action {
            case "cancel": entry = nil; return SnapshotTransferReply()
            case "append":
                guard !current.executing, current.read == nil, (frame.offset ?? 0) == current.bytes.count,
                      let data = frame.data, !data.isEmpty, data.count <= Self.chunkBytes,
                      data.count <= current.total - current.bytes.count else { throw SnapshotError.invalidInput }
                current.bytes.append(data)
                return SnapshotTransferReply()
            case "finish":
                guard !current.executing, current.read == nil, current.bytes.count == current.total,
                      Self.hash(current.bytes) == current.digest else { throw SnapshotError.invalidInput }
                current.executing = true
                executions += 1
                // Authentication may display UI. Never hold the transport mutex
                // during it; cancellation and v1 lock/logout remain independent.
                mutex.unlock(); held = false
                let result: (Data, (Data, Range<Int>) throws -> Data)
                do { result = try execute(current.bytes) }
                catch {
                    mutex.lock(); held = true
                    executions -= 1
                    throw error
                }
                mutex.lock(); held = true
                executions -= 1
                guard entry === current, clock() < current.expires else { throw SnapshotError.expired }
                guard !result.0.isEmpty, result.0.count <= Self.maximumBytes else { throw SnapshotError.invalidInput }
                current.bytes.resetBytes(in: 0..<current.bytes.count)
                current.bytes = result.0
                current.read = result.1
                current.executing = false
                return SnapshotTransferReply(total: current.bytes.count, digest: Self.hash(current.bytes))
            case "read":
                guard !current.executing, let reader = current.read,
                      (frame.offset ?? 0) == current.offset, current.offset < current.bytes.count else { throw SnapshotError.invalidInput }
                let end = min(current.offset + Self.chunkBytes, current.bytes.count)
                let page = try reader(current.bytes, current.offset..<end)
                current.offset = end
                if end == current.bytes.count { entry = nil }
                return SnapshotTransferReply(data: page)
            default: throw SnapshotError.invalidInput
            }
        } catch {
            if entry === current { entry = nil }
            throw error
        }
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
