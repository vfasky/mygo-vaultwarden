// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit
import LocalAuthentication

// This key protects operation metadata only. It never wraps a vault key.
let targetRecoveryKeyID = "C566F25C-946F-4454-9DC4-89A6C471BA08"
extension SnapshotKeyStore {
    func recoveryKey(create: Bool) throws -> Data {
        do { return try read(id: targetRecoveryKeyID, context: LAContext(), allowUI: false) }
        catch SnapshotError.unavailable where create {
            let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            try self.create(id: targetRecoveryKeyID, key: key)
            return key
        }
    }
}

struct TargetRecoveryBinding: Codable, Equatable {
    let operationId: String
    let actor: SnapshotScope
    let target: SnapshotScope
    let storageRevision: String
    let hostEpoch: UInt64
    let authorizationEpoch: UInt64
    let summaryHash: String
}
struct TargetRecoveryOriginalResult: Codable, Equatable {
    let version: Int
    let phase: String
}
struct TargetRecoveryExpectation: Codable, Equatable {
    let Version: Int
    let ResetPassword: Bool
    let ResetMFA: Bool
    let RemoveNonOwnerMemberships: Bool
    let ExpectedUserKeySHA256: String
    let ExpectedMasterWrapperSHA256: String
    func validate(kind: String) throws {
        guard Version == 1, targetHashValid(ExpectedUserKeySHA256),
              ResetPassword ? targetHashValid(ExpectedMasterWrapperSHA256) : ExpectedMasterWrapperSHA256.isEmpty else { throw SnapshotError.invalidInput }
        switch kind {
        case "administrator-recovery": guard (ResetPassword || ResetMFA) && !RemoveNonOwnerMemberships else { throw SnapshotError.invalidInput }
        case "emergency-takeover": guard ResetPassword && ResetMFA && RemoveNonOwnerMemberships else { throw SnapshotError.invalidInput }
        default: throw SnapshotError.invalidInput
        }
    }
}
struct TargetRecoveryRecord: Codable, Equatable {
    let binding: TargetRecoveryBinding
    let summary: Data
    var phase: String
    let requireTargetLogin: Bool
    let noLocalTarget: Bool
    var originalResult: TargetRecoveryOriginalResult? = nil
    var protection: TargetRecoveryProtection? = nil
    var verification: TargetRecoveryResolution? = nil
    var verifiedVaultHash: String? = nil
    var verifiedSessionHash: String? = nil
    var verifiedUnlockHash: String? = nil
}
struct TargetRecoveryEnvelope: Codable {
    let version: Int
    let sealed: Data
}
struct TargetRecoveryResolution: Codable, Equatable {
    var kind: String? = nil
    let binding: TargetRecoveryBinding
    let expectedRevision: String
    let target: SnapshotScope
    let vaultHash: String
    let sessionHash: String
    let unlockHash: String
    // Digests of the controller's actual verified authority/key/membership/MFA
    // evidence, and explicit confirmation bound to this operation. Not HTTP status.
    let authorityHash: String
    let keyHash: String
    let membershipHash: String
    let mfaHash: String
    let confirmationHash: String
    let authenticationEpoch: UInt64
}

private let targetAAD = Data("mygo.target-recovery.v1".utf8)
func targetDigest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func targetHashValid(_ hash: String) -> Bool { hash.count == 64 && hash.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
func targetStrictObject(_ data: Data, keys: Set<String>) throws -> [String: Any] {
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(value.keys).isSubset(of: keys) else { throw SnapshotError.invalidInput }
    return value
}

private func targetStrictScope(_ value: Any) throws {
    let object = try targetStrictObject(JSONSerialization.data(withJSONObject: value), keys: ["server", "account"])
    guard object.count == 2 else { throw SnapshotError.corrupt }
}
private func targetStrictBinding(_ value: Any) throws {
    let object = try targetStrictObject(JSONSerialization.data(withJSONObject: value), keys: ["operationId", "actor", "target", "storageRevision", "hostEpoch", "authorizationEpoch", "summaryHash"])
    guard let actor = object["actor"], let target = object["target"] else { throw SnapshotError.corrupt }
    try targetStrictScope(actor); try targetStrictScope(target)
}
extension TargetRecoveryRecord {
    func requireCurrentEvidence(_ proof: TargetRecoveryResolution) throws {
        let raw = try JSONSerialization.jsonObject(with: summary) as? [String: Any]
        guard raw?["Verification"] != nil else { throw SnapshotError.invalidInput }
        switch proof.kind {
        case "target-authenticated-nondispatch-v1":
            guard originalResult?.version == 1, originalResult?.phase == "not-dispatched" else { throw SnapshotError.invalidInput }
        case "target-confirmed-email-fallback-v1":
            guard originalResult?.version == 1, originalResult?.phase == "confirmed",
                  raw?["Kind"] as? String == "administrator-recovery",
                  let expected = raw?["Verification"] as? [String: Any], expected["ResetMFA"] as? Bool == true else { throw SnapshotError.invalidInput }
        case "target-observed-effects-v1":
            guard originalResult?.phase != "not-dispatched" else { throw SnapshotError.invalidInput }
        default: throw SnapshotError.invalidInput
        }
    }
    func validate() throws {
        let b = binding
        guard b.actor.valid, b.actor.server == b.target.server,
              b.target.account.isEmpty ? !requireTargetLogin : b.target.valid,
              b.operationId.count == 32, b.operationId.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !b.storageRevision.isEmpty, b.storageRevision.count <= 128, b.hostEpoch > 0, b.authorizationEpoch > 0,
              summary.count <= 32768, targetDigest(summary) == b.summaryHash,
              ["prepared", "confirmed", "unknown", "not-dispatched", "verified", "resolved"].contains(phase) else { throw SnapshotError.invalidInput }
        let raw = try targetStrictObject(summary, keys: ["OperationID", "Actor", "Target", "Kind", "ResourceID", "PreviousRevision", "AuthorizationEpoch", "OrganizationID", "MembershipID", "ConfirmedImpact", "TargetEmail", "CounterpartyID", "CounterpartyEmail", "EmergencyType", "WaitTimeDays", "RequireTargetLogin", "Verification"])
        guard raw["OperationID"] as? String == b.operationId,
              raw["AuthorizationEpoch"] as? UInt64 == b.authorizationEpoch,
              raw["RequireTargetLogin"] as? Bool == requireTargetLogin,
              let kind = raw["Kind"] as? String, !kind.isEmpty, kind.utf8.count <= 256,
              let revision = raw["PreviousRevision"] as? String, !revision.isEmpty, revision.count <= 128,
              let actor = raw["Actor"], let target = raw["Target"],
              try snapshotDecode(SnapshotScope.self, from: JSONSerialization.data(withJSONObject: actor)) == b.actor,
              try snapshotDecode(SnapshotScope.self, from: JSONSerialization.data(withJSONObject: target)) == b.target else { throw SnapshotError.invalidInput }
        try targetStrictScope(actor); try targetStrictScope(target)
        for value in raw.values { if let text = value as? String, text.utf8.count > 8192 { throw SnapshotError.invalidInput } }
        if let value = raw["Verification"] {
            guard requireTargetLogin, b.target.valid else { throw SnapshotError.invalidInput }
            let data = try JSONSerialization.data(withJSONObject: value)
            _ = try targetStrictObject(data, keys: ["Version", "ResetPassword", "ResetMFA", "RemoveNonOwnerMemberships", "ExpectedUserKeySHA256", "ExpectedMasterWrapperSHA256"])
            try snapshotDecode(TargetRecoveryExpectation.self, from: data).validate(kind: kind)
        }
        if let originalResult {
            guard raw["Verification"] != nil, originalResult.version == 1,
                  ["confirmed", "unknown", "not-dispatched"].contains(originalResult.phase),
                  phase == originalResult.phase || phase == "verified" || phase == "resolved" else { throw SnapshotError.invalidInput }
        }
        if let protection {
            guard protection.scope == b.target, protection.pendingPolicyMutations.count <= 1024,
                  protection.quarantinedOrganizations.count <= 1024,
                  Set(protection.pendingPolicyMutations.map(\.organizationId)).count == protection.pendingPolicyMutations.count,
                  Set(protection.quarantinedOrganizations).count == protection.quarantinedOrganizations.count else { throw SnapshotError.invalidInput }
        }
        if phase == "verified" || phase == "resolved" {
            if raw["Verification"] != nil { guard let verification else { throw SnapshotError.invalidInput }; try requireCurrentEvidence(verification) }
            guard let a = verifiedVaultHash, let b = verifiedSessionHash, let c = verifiedUnlockHash,
                  [a,b,c].allSatisfy(targetHashValid), let verification,
                  verification.binding == binding, verification.target == binding.target,
                  verification.vaultHash == a, verification.sessionHash == b, verification.unlockHash == c,
                  verification.authenticationEpoch > 0, !verification.expectedRevision.isEmpty,
                  [verification.authorityHash, verification.keyHash, verification.membershipHash, verification.mfaHash, verification.confirmationHash].allSatisfy(targetHashValid) else { throw SnapshotError.invalidInput }
        } else if verification != nil || verifiedVaultHash != nil || verifiedSessionHash != nil || verifiedUnlockHash != nil { throw SnapshotError.invalidInput }
    }
}

extension SnapshotFiles {
    func targetRecords(_ state: SnapshotState) throws -> [TargetRecoveryRecord] {
        guard let envelope = state.targetRecovery else { return [] }
        guard envelope.version == 1, envelope.sealed.count <= 4 * 1024 * 1024, let recoveryKeys else { throw SnapshotError.corrupt }
        var key = try recoveryKeys.recoveryKey(create: false)
        defer { key.resetBytes(in: 0..<key.count) }
        let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.sealed), using: SymmetricKey(data: key), authenticating: targetAAD)
        guard let array = try JSONSerialization.jsonObject(with: plain) as? [[String: Any]], array.count <= 1024 else { throw SnapshotError.corrupt }
        for object in array {
            _ = try targetStrictObject(JSONSerialization.data(withJSONObject: object), keys: ["binding", "summary", "phase", "requireTargetLogin", "noLocalTarget", "originalResult", "protection", "verification", "verifiedVaultHash", "verifiedSessionHash", "verifiedUnlockHash"])
            guard let binding = object["binding"] else { throw SnapshotError.corrupt }
            try targetStrictBinding(binding)
            if let original = object["originalResult"] {
                _ = try targetStrictObject(JSONSerialization.data(withJSONObject: original), keys: ["version", "phase"])
            }
            if let projection = object["protection"] {
                let p = try targetStrictObject(JSONSerialization.data(withJSONObject: projection), keys: ["scope", "pendingPolicyMutations", "quarantinedOrganizations"])
                guard let scope = p["scope"], let pending = p["pendingPolicyMutations"] as? [[String: Any]] else { throw SnapshotError.corrupt }
                try targetStrictScope(scope)
                for record in pending { _ = try targetStrictObject(JSONSerialization.data(withJSONObject: record), keys: ["organizationId", "policyType", "mutationId"]) }
            }
            if let verification = object["verification"] {
                let p = try targetStrictObject(JSONSerialization.data(withJSONObject: verification), keys: ["kind", "binding", "expectedRevision", "target", "vaultHash", "sessionHash", "unlockHash", "authorityHash", "keyHash", "membershipHash", "mfaHash", "confirmationHash", "authenticationEpoch"])
                guard let binding = p["binding"], let target = p["target"] else { throw SnapshotError.corrupt }
                try targetStrictBinding(binding); try targetStrictScope(target)
            }
        }
        let records = try snapshotDecode([TargetRecoveryRecord].self, from: plain)
        guard Set(records.map { $0.binding.operationId }).count == records.count else { throw SnapshotError.corrupt }
        for record in records { try record.validate() }
        return records
    }
    func sealTargetRecords(_ records: [TargetRecoveryRecord], into state: inout SnapshotState) throws {
        guard records.count <= 1024, let recoveryKeys else { throw SnapshotError.configuration }
        for record in records { try record.validate() }
        let data = try snapshotJSON(records)
        guard data.count <= 4 * 1024 * 1024 - 28 else { throw SnapshotError.invalidInput }
        var key = try recoveryKeys.recoveryKey(create: state.targetRecovery == nil)
        defer { key.resetBytes(in: 0..<key.count) }
        state.targetRecovery = TargetRecoveryEnvelope(version: 1, sealed: try AES.GCM.seal(data, using: SymmetricKey(data: key), authenticating: targetAAD).combined!)
        state.format = state.accountSwitch == nil ? 2 : 3
    }
    func isTargetBlocked(_ state: SnapshotState, scope: SnapshotScope) throws -> Bool {
        try targetRecords(state).contains(where: { $0.requireTargetLogin && $0.binding.target == scope && $0.phase != "resolved" })
    }
    func requireTargetAccess(_ state: SnapshotState, scope: SnapshotScope) throws {
        guard try accountSwitchRecord(state)?.phase != "pending" else { throw SnapshotError.busy }
        guard try !isTargetBlocked(state, scope: scope) else { throw SnapshotError.busy }
    }
    func prepareTargetPublication(_ state: inout SnapshotState, scope: SnapshotScope, vault: inout VaultData?, session: Data?, material: PasswordUnlockMaterial?, resolution: TargetRecoveryResolution?) throws {
        var records = try targetRecords(state)
        if let resolution {
            guard resolution.target == scope else { throw SnapshotError.wrongScope }
            guard let index = records.firstIndex(where: { $0.binding == resolution.binding }) else { throw SnapshotError.stale }
            try verifyTargetResolution(resolution, record: records[index], state: state, vault: vault, session: session, material: material)
            records[index].verification = resolution
            records[index].phase = "verified"
            records[index].verifiedVaultHash = resolution.vaultHash
            records[index].verifiedSessionHash = resolution.sessionHash
            records[index].verifiedUnlockHash = resolution.unlockHash
        }
        var updated = resolution != nil
        for i in records.indices where records[i].requireTargetLogin && records[i].binding.target == scope &&
            (records[i].phase != "resolved" || state.snapshot?.header.scope != scope) {
            let alreadyResolved = records[i].phase == "resolved"
            guard let freshVault = vault else { throw SnapshotError.invalidInput }
            if !alreadyResolved {
                guard let storedProof = records[i].verification else { throw SnapshotError.busy }
                try records[i].requireCurrentEvidence(storedProof)
                guard records[i].phase == "verified", let session, let material,
                      records[i].verifiedVaultHash == targetDigest(freshVault.sync), records[i].verifiedSessionHash == targetDigest(session),
                      records[i].verifiedUnlockHash == targetDigest(material.key) else { throw SnapshotError.busy }
            }
            if let protection = records[i].protection {
                var merged = freshVault
                merged.quarantinedOrganizations = Array(Set((merged.quarantinedOrganizations ?? []) + protection.quarantinedOrganizations)).sorted()
                var pending = merged.pendingPolicyMutations ?? []
                for old in protection.pendingPolicyMutations {
                    if let existing = pending.first(where: { $0.organizationId == old.organizationId }) {
                        guard existing == old else { throw SnapshotError.invalidInput }
                    } else { pending.append(old) }
                }
                merged.pendingPolicyMutations = pending; merged.version = pending.isEmpty ? 1 : 2
                try merged.validate(scope: scope); vault = merged
            }
            if !alreadyResolved { records[i].phase = "resolved"; updated = true }
        }
        if updated { try sealTargetRecords(records, into: &state) }
    }
    // A successful authenticated publication is the current protection source.
    // Explicit policy/org recovery can remove restrictions; retain that result
    // for subsequent logout/passwordless bootstrap instead of reviving history.
    func updateResolvedTargetProtection(_ state: inout SnapshotState, scope: SnapshotScope, vault: VaultData?) throws {
        guard let vault else { return }
        var records = try targetRecords(state)
        let projection = TargetRecoveryProtection(scope:scope,pendingPolicyMutations:vault.pendingPolicyMutations ?? [],quarantinedOrganizations:vault.quarantinedOrganizations ?? [])
        var changed = false
        for i in records.indices where records[i].binding.target == scope && records[i].phase == "resolved" {
            if records[i].protection != projection { records[i].protection = projection; changed = true }
        }
        if changed { try sealTargetRecords(records,into:&state) }
    }
    func verifyTargetLogin(_ proof: TargetRecoveryResolution, scope: SnapshotScope, state: SnapshotState, vault: VaultData?, session: Data?, material: PasswordUnlockMaterial?) throws {
        guard proof.expectedRevision == state.revision, proof.target == scope, scope.valid, proof.authenticationEpoch > 0,
              let vault, let session, let material,
              [proof.vaultHash, proof.sessionHash, proof.unlockHash, proof.authorityHash, proof.keyHash, proof.membershipHash, proof.mfaHash, proof.confirmationHash].allSatisfy(targetHashValid),
              proof.vaultHash == targetDigest(vault.sync), proof.sessionHash == targetDigest(session),
              proof.unlockHash == targetDigest(material.key), material.key.count == 32, material.config.valid else { throw SnapshotError.invalidInput }
        try vault.validate(scope: scope)
        try validateSessionData(session)
    }
    func verifyTargetResolution(_ proof: TargetRecoveryResolution, record: TargetRecoveryRecord, state: SnapshotState, vault: VaultData?, session: Data?, material: PasswordUnlockMaterial?) throws {
        try record.requireCurrentEvidence(proof)
        guard proof.binding == record.binding, proof.expectedRevision == state.revision,
              proof.target == record.binding.target, proof.target.valid, proof.authenticationEpoch > 0,
              record.phase != "resolved", let vault, let session, let material,
              [proof.vaultHash, proof.sessionHash, proof.unlockHash, proof.authorityHash, proof.keyHash, proof.membershipHash, proof.mfaHash, proof.confirmationHash].allSatisfy(targetHashValid),
              proof.vaultHash == targetDigest(vault.sync), proof.sessionHash == targetDigest(session),
              proof.unlockHash == targetDigest(material.key), material.key.count == 32, material.config.valid else { throw SnapshotError.invalidInput }
        try vault.validate(scope: proof.target)
        try validateSessionData(session)
    }
}

extension SnapshotStore {
    // The actor's password wrapper authorizes metadata access; a blocked actor
    // may inspect recovery but never obtains an ordinary lease through this path.
    func targetRecovery(operation: String, scope: SnapshotScope, expected: String, unlockKey: Data,
                        binding: TargetRecoveryBinding?, summary: Data?, phase: String?,
                        resolution: TargetRecoveryResolution? = nil, vault: VaultData? = nil,
                        session: Data? = nil, material: PasswordUnlockMaterial? = nil,
                        login: TargetRecoveryResolution? = nil, runtime: RuntimeRecoveryAuthority? = nil) throws -> (SnapshotState, [TargetRecoveryRecord]) {
        defer { changed() }
        return try files.locked {
            var state = try files.read()
            guard state.revision == expected else { throw SnapshotError.stale }
            if let runtime {
                guard runtime.scope == scope else { throw SnapshotError.wrongScope }
                if let binding {
                    guard runtime.operationID == binding.operationId, runtime.summaryHash == binding.summaryHash,
                          binding.actor == scope else { throw SnapshotError.wrongScope }
                } else if operation != "targetRecoveryPending" && operation != "targetRecoveryRuntimePending" { throw SnapshotError.invalidInput }
                try runtimeRecoveryAuthorizer(runtime)
            } else if let login {
                guard ["targetRecoveryPending", "targetRecoveryQuery", "targetRecoveryVerify"].contains(operation) else { throw SnapshotError.invalidInput }
                try files.verifyTargetLogin(login, scope: scope, state: state, vault: vault, session: session, material: material)
            } else {
                guard let snapshot = state.snapshot, snapshot.header.scope == scope, !state.signedOut else { throw SnapshotError.wrongScope }
                var key = try unwrapSnapshotKey(snapshot, unlockKey: unlockKey)
                defer { key.resetBytes(in: 0..<key.count) }
                _ = try openSnapshotPayload(snapshot, key: key, scope: scope)
            }
            var records = try files.targetRecords(state)
            if operation == "targetRecoveryRuntimePending" {
                // Bootstrap query is deliberately separate from the exact-operation
                // mutation capability. It cannot carry a dispatch or resolution.
                guard runtime != nil, binding == nil, summary == nil, phase == nil,
                      resolution == nil, login == nil, vault == nil, session == nil,
                      material == nil else { throw SnapshotError.invalidInput }
                return (state, records.filter { $0.binding.actor == scope || $0.binding.target == scope })
            }
            if operation == "targetRecoveryPending" {
                return (state, records.filter { ($0.binding.actor == scope || $0.binding.target == scope) &&
                    (runtime == nil || ($0.binding.operationId == runtime!.operationID && $0.binding.summaryHash == runtime!.summaryHash)) })
            }
            guard let binding, binding.actor == scope || (operation != "targetRecoveryBegin" && binding.target == scope) else { throw SnapshotError.wrongScope }
            let index = records.firstIndex { $0.binding.operationId == binding.operationId }
            if let index, records[index].binding != binding { throw SnapshotError.stale }
            if operation == "targetRecoveryBegin" {
                guard let summary else { throw SnapshotError.invalidInput }
                if let index {
                    guard records[index].summary == summary else { throw SnapshotError.stale }
                    return (state, [records[index]])
                }
                guard binding.storageRevision == expected, binding.actor == scope else { throw SnapshotError.stale }
                try files.requireTargetAccess(state, scope: scope)
                let raw = try JSONSerialization.jsonObject(with: summary) as? [String: Any]
                guard let requires = raw?["RequireTargetLogin"] as? Bool else { throw SnapshotError.invalidInput }
                var record = TargetRecoveryRecord(binding: binding, summary: summary, phase: "prepared", requireTargetLogin: requires,
                    noLocalTarget: state.snapshot?.header.scope != binding.target)
                try record.validate()
                if requires, binding.target == scope, runtime == nil {
                    guard let snapshot = state.snapshot, let config = snapshot.passwordUnlock?.config else { throw SnapshotError.invalidInput }
                    var key = try unwrapSnapshotKey(snapshot, unlockKey: unlockKey)
                    defer { key.resetBytes(in: 0..<key.count) }
                    let old = try openSnapshotPayload(snapshot, key: key, scope: scope)
                    record.protection = TargetRecoveryProtection(scope: scope, pendingPolicyMutations: old.vault?.pendingPolicyMutations ?? [],
                        quarantinedOrganizations: old.vault?.quarantinedOrganizations ?? [])
                    state.snapshot = try sealSnapshot(credentials: [], scope: scope, keyID: snapshot.header.keyID, key: key,
                        passwordUnlock: PasswordUnlockMaterial(config: config, key: unlockKey), session: old.session,
                        vault: old.vault, accountRecovery: old.accountRecovery)
                }
                records.append(record)
            } else {
                guard let index else { throw SnapshotError.unavailable }
                switch operation {
                case "targetRecoveryQuery": return (state, [records[index]])
                case "targetRecoveryResult":
                    guard let phase, ["confirmed", "unknown", "not-dispatched"].contains(phase),
                          records[index].phase == "prepared" || records[index].phase == phase else { throw SnapshotError.invalidInput }
                    if records[index].originalResult == nil, records[index].phase == "prepared",
                       let raw = try JSONSerialization.jsonObject(with: records[index].summary) as? [String: Any], raw["Verification"] != nil {
                        records[index].originalResult = TargetRecoveryOriginalResult(version: 1, phase: phase)
                    }
                    records[index].phase = phase
                case "targetRecoveryVerify":
                    guard let resolution else { throw SnapshotError.invalidInput }
                    try files.verifyTargetResolution(resolution, record: records[index], state: state, vault: vault, session: session, material: material)
                    records[index].verification = resolution
                    records[index].phase = "verified"
                    records[index].verifiedVaultHash = resolution.vaultHash
                    records[index].verifiedSessionHash = resolution.sessionHash
                    records[index].verifiedUnlockHash = resolution.unlockHash
                default: throw SnapshotError.invalidInput
                }
            }
            try files.sealTargetRecords(records, into: &state)
            state.revision = UUID().uuidString
            try files.write(state)
            if let runtime { try runtimeRecoveryAuthorizer(runtime) }
            return (state, records.filter { $0.binding == binding })
        }
    }
}
