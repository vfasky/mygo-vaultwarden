// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// The app's side of the update helper (macos/UpdateHelper).
enum UpdateHelperClient {
    private static let lock = NSLock()
    private static var connection: NSXPCConnection?

    static func current() -> NSXPCConnection {
        lock.lock(); defer { lock.unlock() }
        if let connection { return connection }
        let created = NSXPCConnection(serviceName: UpdateHelperService.name)
        created.remoteObjectInterface = NSXPCInterface(with: UpdateHelperProtocol.self)
        created.interruptionHandler = { hold() } // started again, while the bundle is likely unchanged
        created.invalidationHandler = {
            lock.lock(); defer { lock.unlock() }
            if connection === created { connection = nil }
        }
        created.resume()
        connection = created
        return created
    }

    static func hold() {
        (current().remoteObjectProxyWithErrorHandler { _ in } as? UpdateHelperProtocol)?.hold {}
    }
}

private final class UpdateHelperReply: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int32?
    let done = DispatchSemaphore(value: 0)

    func finish(_ result: Int32) {
        lock.lock(); defer { lock.unlock() }
        guard value == nil else { return }
        value = result
        done.signal()
    }
    var result: Int32? { lock.lock(); defer { lock.unlock() }; return value }
}

@_cdecl("mygo_update_helper_start")
public func mygoUpdateHelperStart() {
    UpdateHelperClient.hold()
}

// Returns an UpdateHelperResult, or -10 when the helper did not answer and
// -11 when it was unreachable.
@_cdecl("mygo_update_helper_repair")
public func mygoUpdateHelperRepair(_ timeoutMilliseconds: Int32) -> Int32 {
    let reply = UpdateHelperReply()
    let proxy = UpdateHelperClient.current().remoteObjectProxyWithErrorHandler { _ in reply.finish(-11) }
    guard let helper = proxy as? UpdateHelperProtocol else { return -11 }
    helper.repairInstalledApp { reply.finish($0) }
    _ = reply.done.wait(timeout: .now() + .milliseconds(Int(max(timeoutMilliseconds, 0))))
    return reply.result ?? -10
}
