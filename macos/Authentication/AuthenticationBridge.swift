// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import AuthenticationServices
import Security

// All ABI entries are short main-thread calls. No caller pointer is retained.
// take copies into caller-owned memory and consumes the request; release cancels
// and discards it. IDs are never reused, including after cancellation.
struct AuthenticationInput: Decodable {
    let kind: String
    var url: String?
    var rp: String?
    var challenge: Data?
    var userID: Data?
    var userName: String?
    var allowed: [Data]?
    var excluded: [Data]?
}

@MainActor
final class AuthenticationRequests {
    static let shared = AuthenticationRequests()
    static let limit = 16
    static let maxBytes = 131072
    final class Entry {
        var result: Data?
        var status: Int32 = 0
        var cancel: (() -> Void)?
        var observer: NSObjectProtocol?
        var timeout: Task<Void, Never>?
        deinit { if let observer { NotificationCenter.default.removeObserver(observer) }; timeout?.cancel() }
    }
    private var next: UInt64 = 0
    private var entries: [UInt64: Entry] = [:]
    func reserve(cancel: (() -> Void)? = nil) -> UInt64 {
        guard entries.count < Self.limit, next < UInt64.max else { return 0 }
        next += 1
        let entry = Entry(); entry.cancel = cancel
        entries[next] = entry
        return next
    }
    func finish(_ id: UInt64, _ data: Data?, status: Int32) {
        guard let e = entries[id], e.status == 0 else { return }
        e.status = status
        if let data, data.count <= Self.maxBytes { e.result = data }
        else if status == 1 { e.status = -4 }
        e.cancel = nil; e.timeout?.cancel(); e.timeout = nil
    }
    func release(_ id: UInt64) {
        let e = entries.removeValue(forKey: id)
        e?.cancel?()
    }
    func take(_ id: UInt64, into output: UnsafeMutablePointer<UInt8>, capacity: Int) -> Int32 {
        guard let e = entries[id] else { return -2 }
        guard e.status != 0 else { return 0 }
        defer { release(id) }
        guard e.status == 1, let data = e.result else { return e.status }
        guard capacity >= data.count else { return -4 }
        data.copyBytes(to: output, count: data.count)
        return Int32(data.count)
    }
    func start(window: NSWindow, input: AuthenticationInput) -> UInt64 {
        let id = reserve()
        guard id != 0, let e = entries[id] else { return 0 }
        e.observer = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { _ in
            MainActor.assumeIsolated { self.release(id) }
        }
        e.timeout = Task { @MainActor in
            do { try await Task.sleep(nanoseconds: 300_000_000_000) } catch { return }
            self.release(id)
        }
        if input.kind == "browser", let text = input.url, let url = URL(string: text),
           url.scheme == "https", url.host != nil, url.user == nil, url.password == nil {
            if #available(macOS 12.0, *) {
                let browser = VaultAuthenticationBrowser(window: window)
                e.cancel = { browser.cancel() }
                browser.start(url: url, callbackScheme: "bitwarden") { result in
                    switch result {
                    case .success(let url): self.finish(id, Data(url.absoluteString.utf8), status: 1)
                    case .failure: self.finish(id, nil, status: -3)
                    }
                }
            } else { finish(id, nil, status: -5) }
        } else if input.kind == "webauthn", let rp = input.rp, Self.signedRP(rp), let challenge = input.challenge {
            if #available(macOS 13.0, *) {
                if !(input.excluded ?? []).isEmpty {
                    guard #available(macOS 14.0, *) else { finish(id, nil, status: -5); return id }
                }
                let web = VaultWebAuthn(window: window)
                e.cancel = { web.cancel() }
                web.start(rp: rp, challenge: challenge, userID: input.userID, userName: input.userName,
                          allowed: input.allowed ?? [], excluded: input.excluded ?? []) { result in
                    switch result {
                    case .success(let data): self.finish(id, data, status: 1)
                    case .failure: self.finish(id, nil, status: -3)
                    }
                }
            } else { finish(id, nil, status: -5) }
        } else { finish(id, nil, status: -5) }
        return id
    }
    // Exact signed entries only. This is a prerequisite, not proof of AASA or
    // usable credentials; AuthenticationServices performs that verification.
    static func signedRP(_ rp: String) -> Bool {
        guard !rp.isEmpty, !rp.contains("*"), !rp.contains(":"), !rp.contains("/") else { return false }
        var code: SecCode?
        var info: CFDictionary?
        var staticCode: SecStaticCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any],
              let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let domains = entitlements["com.apple.developer.associated-domains"] as? [String] else { return false }
        return domains.contains("webcredentials:" + rp)
    }
}

@_cdecl("mygo_auth_start")
@MainActor
public func mygoAuthStart(_ handle: UInt, _ bytes: UnsafePointer<UInt8>?, _ length: Int) -> UInt64 {
    guard Thread.isMainThread, let bytes, length > 0, length <= AuthenticationRequests.maxBytes,
          let window = NSApp?.windows.first(where: { UInt(bitPattern: Unmanaged.passUnretained($0).toOpaque()) == handle }),
          let input = try? JSONDecoder().decode(AuthenticationInput.self, from: Data(bytes: bytes, count: length)) else { return 0 }
    // Compare against actual AppKit windows; never dereference the supplied integer.
    return AuthenticationRequests.shared.start(window: window, input: input)
}

@_cdecl("mygo_auth_take")
@MainActor
public func mygoAuthTake(_ id: UInt64, _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard Thread.isMainThread, let output, capacity > 0, capacity <= AuthenticationRequests.maxBytes else { return -4 }
    return AuthenticationRequests.shared.take(id, into: output, capacity: capacity)
}

@_cdecl("mygo_auth_release")
@MainActor
public func mygoAuthRelease(_ id: UInt64) {
    guard Thread.isMainThread else { return }
    AuthenticationRequests.shared.release(id)
}
