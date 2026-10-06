// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin

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
    init(directory: URL) throws {
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
              info.st_size > 0, info.st_size <= 16 * 1024 * 1024 else { throw SnapshotError.corrupt }
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
            let state = try snapshotDecode(SnapshotState.self, from: data)
            try state.validate()
            return state
        } catch { throw SnapshotError.corrupt }
    }
    // Only ciphertext and non-secret control metadata reach disk, including temp files.
    func write(_ state: SnapshotState) throws {
        try state.validate()
        let data = try snapshotJSON(state)
        guard data.count <= 16 * 1024 * 1024 else { throw SnapshotError.invalidInput }
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
        let directoryFD = Darwin.open(directory.path, O_RDONLY | O_CLOEXEC)
        if directoryFD >= 0 { _ = fsync(directoryFD); Darwin.close(directoryFD) }
    }
}
