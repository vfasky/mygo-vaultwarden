// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security

enum InstalledApp {
    // .../MyGo Vaultwarden.app/Contents/XPCServices/UpdateHelper.xpc. After an
    // update replaced the bundle, the same path names the new app.
    static let url = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    // The team that signed this helper, which the app must share.
    static let requirement: String? = {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let team = (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String else { return nil }
        return "anchor apple generic and identifier \"\(UpdateHelperService.appIdentifier)\" and certificate leaf[subject.OU] = \"\(team)\""
    }()

    static func repair() -> UpdateHelperResult {
        guard url.pathExtension == "app" else { return .notApp }
        guard quarantined(url.path) else { return .unchanged }
        // Only the notarized app of this team loses its quarantine; anything
        // else keeps it and Gatekeeper decides as usual.
        guard let requirement, valid(url, requirement + " and notarized") else { return .untrusted }
        var complete = unquarantine(url.path)
        let files = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil, options: [], errorHandler: { _, _ in
            complete = false
            return true
        })
        while let file = files?.nextObject() as? URL {
            complete = unquarantine(file.path) && complete
        }
        return complete ? .repaired : .incomplete
    }

    private static func valid(_ url: URL, _ requirementText: String) -> Bool {
        var staticCode: SecStaticCode?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode,
              SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        return SecStaticCodeCheckValidity(staticCode, flags, requirement) == errSecSuccess
    }

    private static func quarantined(_ path: String) -> Bool {
        getxattr(path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    private static func unquarantine(_ path: String) -> Bool {
        removexattr(path, "com.apple.quarantine", XATTR_NOFOLLOW) == 0 || errno == ENOATTR
    }
}

final class UpdateHelper: NSObject, UpdateHelperProtocol {
    private let lock = NSLock()
    private var held: [() -> Void] = []

    func hold(_ reply: @escaping () -> Void) {
        lock.lock(); held.append(reply); lock.unlock()
    }

    func repairInstalledApp(_ reply: @escaping (Int32) -> Void) {
        reply(InstalledApp.repair().rawValue)
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let requirement = InstalledApp.requirement else { return false }
        connection.setCodeSigningRequirement(requirement)
        connection.exportedInterface = NSXPCInterface(with: UpdateHelperProtocol.self)
        connection.exportedObject = UpdateHelper()
        connection.resume()
        return true
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
