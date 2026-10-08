// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import AuthenticationServices

// No passwords enter this object or the system identity store.
struct SnapshotIdentity {
    let service: String
    let username: String
    let recordID: String
}

protocol SnapshotIdentitySink {
    func replace(_ identities: [SnapshotIdentity], completion: @escaping (Bool) -> Void)
}

struct SystemSnapshotIdentitySink: SnapshotIdentitySink {
    func replace(_ identities: [SnapshotIdentity], completion: @escaping (Bool) -> Void) {
        let values: [any ASCredentialIdentity] = identities.map {
            ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: $0.service, type: .domain),
                                         user: $0.username, recordIdentifier: $0.recordID)
        }
        ASCredentialIdentityStore.shared.replaceCredentialIdentities(values) { success, _ in completion(success) }
    }
}

enum SnapshotIndex {
    static func recordID(snapshotID: String, credentialID: String) -> String { snapshotID + ":" + credentialID }
    static func credentialID(recordID: String, snapshotID: String) -> String? {
        let prefix = snapshotID + ":"
        guard recordID.hasPrefix(prefix) else { return nil }
        let id = String(recordID.dropFirst(prefix.count))
        return id.isEmpty || id.contains(":") ? nil : id
    }
    static func schedule(store: SnapshotStore, lease: SnapshotLease?,
                         sink: SnapshotIdentitySink = SystemSnapshotIdentitySink(),
                         completion: @escaping (Bool) -> Void = { _ in }) {
        let token: String
        let identities: [SnapshotIdentity]
        do {
            let state = try store.state()
            if let lease {
                guard state.snapshot?.header.id == lease.header.id else { throw SnapshotError.stale }
                try store.withCurrentLease(lease) {}
                token = state.indexToken
                identities = lease.credentials.flatMap { credential in
                    // QuickType gives an identity, not proof of the requesting URL.
                    // Host/exact rules must use the list callback's actual services.
                    let domains = credential.uris.map { rules in rules.filter(\.quickEligible).compactMap(\.baseDomain) } ?? credential.hosts
                    return Set(domains).map { SnapshotIdentity(service: $0, username: credential.username,
                                                            recordID: recordID(snapshotID: lease.header.id, credentialID: credential.id)) }
                }
            } else {
                if let snapshot = state.snapshot {
                    guard try store.files.isTargetBlocked(state, scope: snapshot.header.scope) else { throw SnapshotError.stale }
                }
                token = state.indexToken
                identities = []
            }
        } catch { completion(false); return }

        DispatchQueue.global(qos: .utility).async {
            do {
                // Separate from state.lock: revocation NEVER waits for the system
                // index service. Hold this lock until the real callback (not a timeout),
                // so a late replace cannot overtake a subsequent clear in another process.
                let lock = try SnapshotFileLock(url: store.files.directory.appendingPathComponent("index.lock"))
                guard try store.state().indexToken == token else { throw SnapshotError.stale }
                sink.replace(identities) { success in
                    var acknowledged = false
                    if success { acknowledged = (try? store.acknowledgeIndex(token: token)) != nil }
                    lock.release()
                    completion(acknowledged)
                }
            } catch { completion(false) }
        }
    }
}
