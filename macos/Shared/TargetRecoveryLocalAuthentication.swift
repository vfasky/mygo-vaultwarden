// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import LocalAuthentication

struct TargetRecoveryProtection: Codable, Equatable {
    let scope: SnapshotScope
    let pendingPolicyMutations: [PendingPolicyMutation]
    let quarantinedOrganizations: [String]
}
extension SnapshotStore {
    // Never called from BeforeDispatch. Local user presence proves access to the
    // existing encrypted target only; it proves no remote state and grants no lease.
    private func withAuthenticatedTargetKey<T>(binding: TargetRecoveryBinding, expected: String,
                                              body: (Data, SnapshotPayload) throws -> T) throws -> T {
        let before = try state()
        guard before.revision == expected, let snapshot = before.snapshot, snapshot.header.scope == binding.target,
              try files.targetRecords(before).contains(where: { $0.binding == binding && $0.phase != "resolved" }) else { throw SnapshotError.stale }
        var key = try keys.read(id: snapshot.header.keyID, context: LAContext(), allowUI: true)
        defer { key.resetBytes(in: 0..<key.count) }
        let payload = try openSnapshotPayload(snapshot, key: key, scope: binding.target)
        // Dialog/cancellation never holds the cross-process storage lock.
        let after = try state()
        guard after.revision == expected, after.snapshot?.header.id == snapshot.header.id else { throw SnapshotError.stale }
        return try body(key, payload)
    }
    func inspectLocalTarget(binding: TargetRecoveryBinding, expected: String) throws -> (SnapshotState, TargetRecoveryProtection, AccountRecoveryJournal?) {
        try withAuthenticatedTargetKey(binding: binding, expected: expected) { _, payload in
            try files.locked {
                let state = try files.read()
                guard state.revision == expected else { throw SnapshotError.stale }
                return (state, TargetRecoveryProtection(scope: binding.target, pendingPolicyMutations: payload.vault?.pendingPolicyMutations ?? [],
                    quarantinedOrganizations: payload.vault?.quarantinedOrganizations ?? []), payload.accountRecovery)
            }
        }
    }
    func resolveLocalTarget(proof: TargetRecoveryResolution, credentials: [VaultCredential], material: PasswordUnlockMaterial,
                            session: Data, vault: VaultData) throws -> SnapshotLease {
        try withAuthenticatedTargetKey(binding: proof.binding, expected: proof.expectedRevision) { key, payload in
            guard payload.accountRecovery == nil else { throw SnapshotError.accountRecoveryRequired }
            return try publish(credentials, scope: proof.target, expected: proof.expectedRevision,
                passwordUnlock: material, session: session, vault: vault, includeVault: true,
                targetResolution: proof, priorSnapshotKey: key)
        }
    }
}
