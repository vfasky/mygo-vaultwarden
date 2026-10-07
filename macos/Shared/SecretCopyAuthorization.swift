// SPDX-License-Identifier: GPL-3.0-only
import Foundation

extension SnapshotStore {
    // Call on the UI thread, before any file lock is held. The authenticated
    // lease linearizes copy with lock/logout/account replacement. Public state
    // and a matching revision alone are insufficient to enter the body.
    func withSecretCopyAuthorization<T>(scope: SnapshotScope, expected: String,
                                        unlockKey: Data, notAfter: Double,
                                        now: () -> TimeInterval = { Date().timeIntervalSince1970 },
                                        body: (TimeInterval) throws -> T) throws -> T {
        guard notAfter.isFinite else { throw SnapshotError.invalidInput }
        let lease = try unlockWithPassword(scope: scope, expected: expected, unlockKey: unlockKey)
        return try withCurrentLease(lease) {
            let remaining = notAfter / 1000 - now()
            guard remaining > 0, remaining <= 30 else { throw SnapshotError.stale }
            return try body(remaining)
        }
    }
}
