// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit

// AccountRecovery v1 is owned by Go. Retain its original bytes, including future
// fields, inside the authenticated envelope; never round-trip it through a DTO.
struct AccountRecoveryBinding: Codable, Equatable {
    let operationId: String
    let oldRevision: String
    let epoch: UInt64
    let recordHash: String
}
struct AccountRecoveryJournal: Codable {
    let version: Int
    let binding: AccountRecoveryBinding
    let record: Data
    var phase: String
    var checkpoint: Data? = nil

    func validate(scope: SnapshotScope) throws {
        guard version == 1, binding.epoch > 0, !binding.oldRevision.isEmpty,
              binding.operationId.count == 32,
              binding.operationId.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              binding.recordHash == recoveryDigest(record),
              ["prepared", "unknown", "confirmed", "not-dispatched"].contains(phase) else { throw SnapshotError.invalidInput }
        let original = try decodeRecord()
        guard original.version == 1, original.scope == scope,
              original.operationId == binding.operationId, original.oldRevision == binding.oldRevision,
              ["password", "kdf", "email", "security-stamp", "delete", "purge", "rotate-user-key"].contains(original.kind),
              original.oldUnlock.key.count == 32, original.oldUnlock.config.valid,
              !original.request.isEmpty, !original.oldVault.isEmpty else { throw SnapshotError.invalidInput }
        try validateSessionData(original.oldSession)
        try validateSessionData(checkpoint)
        if original.kind == "rotate-user-key" {
            guard original.newUserKey?.count == 64, !(original.newWrappedKey ?? "").isEmpty else { throw SnapshotError.invalidInput }
        }
    }
    func decodeRecord() throws -> AccountRecoveryRecord { try snapshotDecode(AccountRecoveryRecord.self, from: record) }
}
struct AccountRecoveryRecord: Decodable {
    let version: Int
    let operationId: String
    let scope: SnapshotScope
    let kind: String
    let oldRevision: String
    let oldSession: Data
    let oldUnlock: PasswordUnlockMaterial
    let oldVault: Data
    let newUserKey: Data?
    let newWrappedKey: String?
    let request: Data
}
struct AccountRecoveryResolution: Decodable {
    let binding: AccountRecoveryBinding
    let mode: String
    let userConfirmed: Bool
    let authorityVerified: Bool
    let resourcesVerified: Bool
    // Binds the trusted full-resource verification to the exact new VaultData.
    let vaultHash: String?
}
func recoveryDigest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
