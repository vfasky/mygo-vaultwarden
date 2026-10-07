// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security
import LocalAuthentication

final class SnapshotStore {
    let files: SnapshotFiles
    private let keys: SnapshotKeyStore
    private let clock: () -> TimeInterval
    private let changed: () -> Void
    static let changeNotification = Notification.Name("yz.sh.mygo-vaultwarden.snapshotChanged")

    init(directory: URL, keys: SnapshotKeyStore,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         changed: @escaping () -> Void = {}) throws {
        files = try SnapshotFiles(directory: directory)
        self.keys = keys
        self.clock = clock
        self.changed = changed
    }
    static func sharedContainer() throws -> SnapshotStore {
        let config = try SnapshotConfiguration.current()
        return try SnapshotStore(directory: config.directory, keys: ProtectedSnapshotKeys(accessGroup: config.keychainGroup), changed: {
            DistributedNotificationCenter.default().postNotificationName(changeNotification, object: nil, userInfo: nil, deliverImmediately: true)
        })
    }
    func state() throws -> SnapshotState { try files.locked { try files.read() } }

    // Journal key IDs before creating them. Crashes cannot leave untracked secrets.
    // A new AES key is used for every replacement.
    func publish(_ credentials: [VaultCredential], scope: SnapshotScope, expected: String,
                 passwordUnlock: PasswordUnlockMaterial? = nil, session: Data? = nil, vault: VaultData? = nil,
                 priorUnlockKey: Data? = nil, includeVault: Bool = false, restoringOrganization: String? = nil, clearingPolicy: PendingPolicyMutation? = nil) throws -> SnapshotLease {
        try validateCredentials(credentials)
        try validateSessionData(session)
        try vault?.validate(scope: scope)
        if session != nil && passwordUnlock == nil { throw SnapshotError.invalidInput }
        guard scope.valid else { throw SnapshotError.wrongScope }
        if let material = passwordUnlock {
            guard material.config.valid, material.key.count == 32 else { throw SnapshotError.invalidInput }
        }
        defer { changed() }
        return try files.locked {
            var prior = try files.read()
            guard prior.revision == expected else { throw SnapshotError.stale }
            if let existing = prior.snapshot, existing.header.scope != scope { throw SnapshotError.wrongScope }
            var vault = vault
            if clearingPolicy != nil && prior.snapshot?.passwordUnlock == nil { throw SnapshotError.invalidInput }
            if let existing = prior.snapshot {
                // Authenticated prior isolation cannot be erased by an ordinary sync.
                // Legacy callers without password material may not replace a protected vault.
                if existing.passwordUnlock != nil {
                    guard let material = passwordUnlock else { throw SnapshotError.invalidInput }
                    var oldKey = try unwrapSnapshotKey(existing, unlockKey: priorUnlockKey ?? material.key)
                    defer { oldKey.resetBytes(in: 0..<oldKey.count) }
                    let old = try openSnapshotPayload(existing, key: oldKey, scope: scope)
                    if let clearingPolicy {
                        guard (restoringOrganization == nil || restoringOrganization == clearingPolicy.organizationId),
                              old.vault?.pendingPolicyMutations?.contains(clearingPolicy) == true else { throw SnapshotError.invalidInput }
                    }
                    if let pending = old.vault?.pendingPolicyMutations, !pending.isEmpty {
                        guard vault != nil else { throw SnapshotError.invalidInput }
                        var next = vault!.pendingPolicyMutations ?? []
                        for record in pending {
                            if record == clearingPolicy { continue }
                            if let existing = next.first(where: { $0.organizationId == record.organizationId }) {
                                guard existing == record else { throw SnapshotError.invalidInput }
                            } else { next.append(record) }
                        }
                        vault!.pendingPolicyMutations = next.filter { $0 != clearingPolicy }
                        vault!.version = (vault!.pendingPolicyMutations ?? []).isEmpty ? 1 : 2
                    }
                    if let id = restoringOrganization, !(old.vault?.quarantinedOrganizations ?? []).contains(id) { throw SnapshotError.invalidInput }
                    if let isolated = old.vault?.quarantinedOrganizations, !isolated.isEmpty {
                        guard vault != nil else { throw SnapshotError.invalidInput }
                        if let id = restoringOrganization {
                            guard isolated.contains(id), let fresh = vault,
                                  let object = try JSONSerialization.jsonObject(with: fresh.sync) as? [String: Any],
                                  let profile = object["profile"] as? [String: Any],
                                  let orgs = profile["organizations"] as? [[String: Any]],
                                  orgs.contains(where: { org in
                                      org["id"] as? String == id && org["status"] as? Int == 2 && org["enabled"] as? Bool == true &&
                                      org["userId"] as? String == scope.account && (org["organizationUserId"] as? String).map({ !$0.isEmpty && $0 != scope.account }) == true &&
                                      (org["key"] as? String).map({ !$0.isEmpty }) == true
                                  }) else { throw SnapshotError.invalidInput }
                        }
                        vault!.quarantinedOrganizations = Array(Set(isolated + (vault!.quarantinedOrganizations ?? []))).filter { $0 != restoringOrganization }.sorted()
                    }
                }
            }
            try vault?.validate(scope: scope)
            let credentials = scope == .demo ? (try vault?.excludingQuarantined(credentials) ?? credentials) : (vault?.policyCandidates(credentials) ?? [])
            try cleanupLocked(&prior)
            guard prior.retiredKeys.count < 500 else { throw SnapshotError.busy }
            let keyID = UUID().uuidString
            var key = Data(count: 32)
            let result = key.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            guard result == errSecSuccess else { throw SnapshotError.keychain(result) }
            defer { key.resetBytes(in: 0..<key.count) }
            var journal = prior
            journal.revision = UUID().uuidString
            journal.retiredKeys.append(keyID)
            try files.write(journal)
            do {
                try keys.create(id: keyID, key: key)
                let snapshot = try sealSnapshot(credentials: credentials, scope: scope, keyID: keyID, key: key, passwordUnlock: passwordUnlock, session: session, vault: vault)
                var next = journal
                next.snapshot = snapshot
                next.signedOut = false
                next.retiredKeys.removeAll { $0 == keyID }
                if let oldID = prior.snapshot?.header.keyID { next.retiredKeys.append(oldID) }
                try files.write(next)
                // Key cleanup failure does not hide a committed replacement.
                try? cleanupLocked(&next)
                return SnapshotLease(revision: next.revision, header: snapshot.header,
                                     expiresAt: clock() + 60, credentials: credentials, vault: includeVault ? vault : nil)
            } catch {
                try? cleanupLocked(&journal)
                throw error
            }
        }
    }

    // Write-ahead isolation: complete before sending leave/delete. It retains the
    // session and unrelated encrypted data and rotates the candidate identity.
    func quarantineOrganization(_ id: String, scope: SnapshotScope, expected: String, unlockKey: Data, session: Data, pendingPolicy: PendingPolicyMutation? = nil) throws -> SnapshotLease {
        try validateSessionData(session)
        defer { changed() }
        return try files.locked {
            var state = try files.read()
            guard state.revision == expected else { throw SnapshotError.stale }
            guard let snapshot = state.snapshot, !state.signedOut else { throw SnapshotError.unavailable }
            guard snapshot.header.scope == scope else { throw SnapshotError.wrongScope }
            var key = try unwrapSnapshotKey(snapshot, unlockKey: unlockKey)
            defer { key.resetBytes(in: 0..<key.count) }
            let payload = try openSnapshotPayload(snapshot, key: key, scope: scope)
            guard var vault = payload.vault, let config = snapshot.passwordUnlock?.config else { throw SnapshotError.invalidInput }
            let object = try JSONSerialization.jsonObject(with: vault.sync) as? [String: Any]
            let profile = object?["profile"] as? [String: Any]
            let organizations = profile?["organizations"] as? [[String: Any]] ?? []
            guard organizations.contains(where: { ($0["id"] as? String ?? $0["ID"] as? String) == id }),
                  !(vault.quarantinedOrganizations ?? []).contains(id) else { throw SnapshotError.invalidInput }
            if let pendingPolicy {
                guard pendingPolicy.organizationId == id, !(vault.pendingPolicyMutations ?? []).contains(where: { $0.organizationId == id }) else { throw SnapshotError.invalidInput }
                vault.pendingPolicyMutations = (vault.pendingPolicyMutations ?? []) + [pendingPolicy]
                vault.version = 2
            }
            vault.quarantinedOrganizations = ((vault.quarantinedOrganizations ?? []) + [id]).sorted()
            try vault.validate(scope: scope)
            let credentials = scope == .demo ? try vault.excludingQuarantined(payload.credentials) : vault.policyCandidates(payload.credentials)
            let replacement = try sealSnapshot(credentials: credentials, scope: scope, keyID: snapshot.header.keyID, key: key,
                passwordUnlock: PasswordUnlockMaterial(config: config, key: unlockKey), session: session, vault: vault)
            state.snapshot = replacement
            state.revision = UUID().uuidString
            try files.write(state)
            return SnapshotLease(revision: state.revision, header: replacement.header, expiresAt: clock() + 60, credentials: credentials, vault: vault)
        }
    }

    func unlock(scope: SnapshotScope, context: LAContext, allowUI: Bool, includeSession: Bool = false) throws -> SnapshotLease {
        let before = try state()
        guard let encrypted = before.snapshot, !before.signedOut else { throw SnapshotError.unavailable }
        guard encrypted.header.scope == scope else { throw SnapshotError.wrongScope }
        // Never hold the file lock while an authentication dialog is on screen.
        var key = try keys.read(id: encrypted.header.keyID, context: context, allowUI: allowUI)
        defer { key.resetBytes(in: 0..<key.count) }
        let payload = try openSnapshotPayload(encrypted, key: key, scope: scope)
        let lease = SnapshotLease(revision: before.revision, header: encrypted.header,
                                  expiresAt: clock() + 60, credentials: payload.safeCandidates, session: includeSession ? payload.session : nil,
                                  vault: includeSession ? payload.vault : nil)
        try withCurrentLease(lease) {}
        return lease
    }

    // Main-app password unlock can restore a saved session only after both
    // the snapshot lease and its server/account scope have been authenticated.
    func unlockWithPassword(scope: SnapshotScope, expected: String, unlockKey: Data) throws -> SnapshotLease {
        let before = try state()
        guard before.revision == expected else { throw SnapshotError.stale }
        guard let encrypted = before.snapshot, !before.signedOut else { throw SnapshotError.unavailable }
        guard encrypted.header.scope == scope else { throw SnapshotError.wrongScope }
        var key = try unwrapSnapshotKey(encrypted, unlockKey: unlockKey)
        defer { key.resetBytes(in: 0..<key.count) }
        let payload = try openSnapshotPayload(encrypted, key: key, scope: scope)
        let lease = SnapshotLease(revision: before.revision, header: encrypted.header,
                                  expiresAt: clock() + 60, credentials: payload.safeCandidates, session: payload.session, vault: payload.vault)
        try withCurrentLease(lease) {}
        return lease
    }

    // Persist refresh-token rotation before downloading a new vault. The same
    // CAS barrier as publication rejects writers revoked by lock/logout/switch.
    func saveSession(_ session: Data, scope: SnapshotScope, expected: String, unlockKey: Data) throws -> SnapshotLease {
        try validateSessionData(session)
        defer { changed() }
        return try files.locked {
            var state = try files.read()
            guard state.revision == expected else { throw SnapshotError.stale }
            guard let snapshot = state.snapshot, !state.signedOut else { throw SnapshotError.unavailable }
            guard snapshot.header.scope == scope else { throw SnapshotError.wrongScope }
            var key = try unwrapSnapshotKey(snapshot, unlockKey: unlockKey)
            defer { key.resetBytes(in: 0..<key.count) }
            let payload = try openSnapshotPayload(snapshot, key: key, scope: scope)
            state.snapshot = try replacingSnapshotSession(snapshot, key: key, session: session)
            state.revision = UUID().uuidString
            try files.write(state)
            return SnapshotLease(revision: state.revision, header: snapshot.header, expiresAt: clock() + 60, credentials: [], vault: payload.vault)
        }
    }

    // Linearization point: hold the same lock as revocation through submission
    // to Apple's extension context. Already submitted fills cannot be recalled.
    func withCurrentLease<T>(_ lease: SnapshotLease, _ body: () throws -> T) throws -> T {
        try files.locked {
            let current = try files.read()
            guard current.revision == lease.revision, !current.signedOut,
                  current.snapshot?.header.id == lease.header.id,
                  current.snapshot?.header.scope == lease.header.scope else { throw SnapshotError.stale }
            guard clock() < lease.expiresAt else { throw SnapshotError.expired }
            return try body()
        }
    }

    // Lock is unconditional: a screen-lock event must invalidate work even when
    // a UI mutation/authentication is in flight. Each subsequent fill authenticates anew.
    func lock() throws {
        defer { changed() }
        try files.locked {
            var state = try files.read()
            // Even an empty vault must advance its revision to cancel a pending login/publish.
            state.revision = UUID().uuidString
            try files.write(state)
        }
    }

    func logout(expected: String) throws {
        defer { changed() }
        try files.locked {
            var state = try files.read()
            guard state.revision == expected else { throw SnapshotError.stale }
            if let keyID = state.snapshot?.header.keyID { state.retiredKeys.append(keyID) }
            state.snapshot = nil
            state.signedOut = true
            state.revision = UUID().uuidString
            // Commit the tombstone first. Failed cleanup must never resurrect access.
            try files.write(state)
            try cleanupLocked(&state)
        }
    }

    func retryCleanup() throws {
        try files.locked {
            var state = try files.read()
            try cleanupLocked(&state)
        }
    }
    private func cleanupLocked(_ state: inout SnapshotState) throws {
        let pending = state.retiredKeys
        for id in pending {
            try keys.delete(id: id)
            state.retiredKeys.removeAll { $0 == id }
            try files.write(state)
        }
    }

    // Index callbacks may arrive after lock/logout/publish. They can acknowledge
    // only the exact snapshot generation they updated, never the current one blindly.
    func acknowledgeIndex(token: String) throws {
        try files.locked {
            var state = try files.read()
            guard state.indexToken == token else { throw SnapshotError.stale }
            state.indexedToken = token
            try files.write(state)
        }
    }
}
