// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import CryptoKit
import LocalAuthentication

struct AccountSwitchBinding: Codable, Equatable {
    let operationID: String
    let source: SnapshotScope
    let sourceSnapshotID: String
    let target: SnapshotScope
}
struct AccountSwitchEnvelope: Codable { let version: Int; let pending: Bool; let sealed: Data }
struct AccountSwitchRecord: Codable {
    let binding: AccountSwitchBinding
    let newSnapshotID: String
    let vaultHash: String
    let sessionHash: String
    let wrapperHash: String
    var phase: String
    var oldSnapshot: EncryptedSnapshot?
}
struct AccountSwitchReceipt: Codable {
    let binding: AccountSwitchBinding
    let newSnapshotID: String
    let phase: String
}
private let accountSwitchAAD = Data("mygo-bound-account-switch-v1".utf8)

extension SnapshotFiles {
    func accountSwitchRecord(_ state: SnapshotState) throws -> AccountSwitchRecord? {
        guard let envelope = state.accountSwitch else { return nil }
        guard envelope.version == 1, envelope.sealed.count <= SnapshotTransfer.maximumBytes + 28, let recoveryKeys else { throw SnapshotError.corrupt }
        var key = try recoveryKeys.recoveryKey(create: false)
        defer { key.resetBytes(in: 0..<key.count) }
        var raw: Data
        do { raw = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.sealed), using: SymmetricKey(data:key), authenticating: accountSwitchAAD + Data(envelope.pending ? "pending".utf8 : "confirmed".utf8)) }
        catch { throw SnapshotError.corrupt }
        defer { raw.resetBytes(in:0..<raw.count) }
        let object = try targetStrictObject(raw, keys:["binding","newSnapshotID","vaultHash","sessionHash","wrapperHash","phase","oldSnapshot"])
        guard let bindingObject = object["binding"] else { throw SnapshotError.corrupt }
        let fields = try targetStrictObject(JSONSerialization.data(withJSONObject:bindingObject),keys:["operationID","source","sourceSnapshotID","target"])
        for name in ["source","target"] {
            guard let scope = fields[name] else { throw SnapshotError.corrupt }
            _ = try targetStrictObject(JSONSerialization.data(withJSONObject:scope),keys:["server","account"])
        }
        let record = try snapshotDecode(AccountSwitchRecord.self, from:raw)
        let b = record.binding
        guard b.operationID.count == 32, b.operationID.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              b.source.valid, b.target.valid, b.source != b.target,
              UUID(uuidString:b.sourceSnapshotID) != nil, UUID(uuidString:record.newSnapshotID) != nil,
              [record.vaultHash,record.sessionHash,record.wrapperHash].allSatisfy({ $0.count == 64 && $0.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) }),
              ["pending","confirmed"].contains(record.phase), envelope.pending == (record.phase == "pending") else { throw SnapshotError.corrupt }
        if record.phase == "pending" {
            guard let old = record.oldSnapshot, old.header.scope == b.source,
                  old.header.id == b.sourceSnapshotID, old.header.format == 1,
                  old.header.id != record.newSnapshotID,
                  state.snapshot?.header.id == record.newSnapshotID,
                  state.snapshot?.header.scope == b.target,
                  old.header.keyID != state.snapshot?.header.keyID,
                  !state.retiredKeys.contains(old.header.keyID) else { throw SnapshotError.corrupt }
            var original = SnapshotState(); original.snapshot = old; original.signedOut = false
            try original.validate()
        } else if record.oldSnapshot != nil { throw SnapshotError.corrupt }
        return record
    }
    func storeAccountSwitch(_ record: AccountSwitchRecord, in state: inout SnapshotState) throws {
        var raw = try snapshotJSON(record)
        defer { raw.resetBytes(in:0..<raw.count) }
        guard raw.count <= SnapshotTransfer.maximumBytes else { throw SnapshotError.accountSwitchTooLarge }
        guard let recoveryKeys else { throw SnapshotError.invalidInput }
        var key = try recoveryKeys.recoveryKey(create: state.accountSwitch == nil && state.targetRecovery == nil)
        defer { key.resetBytes(in:0..<key.count) }
        state.accountSwitch = AccountSwitchEnvelope(version:1,pending:record.phase == "pending",sealed:try AES.GCM.seal(raw,using:SymmetricKey(data:key),authenticating:accountSwitchAAD + Data(record.phase.utf8)).combined!)
        state.format = 3
    }
}

extension SnapshotStore {
    // No filesystem lock spans the user-presence prompt. The exact old identity
    // is checked before and after authentication and again inside publication.
    func publishBoundAccount(_ credentials:[VaultCredential], binding:AccountSwitchBinding, expected:String,
                             material:PasswordUnlockMaterial, session:Data, vault:VaultData) throws -> SnapshotLease {
        guard binding.operationID.count == 32, binding.operationID.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
              binding.source.valid, binding.target.valid else { throw SnapshotError.invalidInput }
        let before = try files.locked { () -> SnapshotState in
            let state = try files.read()
            guard state.revision == expected, let old = state.snapshot,
                  old.header.scope == binding.source, old.header.id == binding.sourceSnapshotID,
                  old.header.scope != binding.target,
                  try files.accountSwitchRecord(state)?.phase != "pending" else { throw SnapshotError.stale }
            guard old.header.format == 1 else { throw SnapshotError.protectedAccountSwitch }
            do { try files.requireTargetAccess(state,scope:binding.source) }
            catch SnapshotError.busy { throw SnapshotError.protectedAccountSwitch }
            return state
        }
        guard let old = before.snapshot, vault.scope == binding.target else { throw SnapshotError.wrongScope }
        let context = LAContext(); defer { context.invalidate() }
        var key = try keys.read(id:old.header.keyID,context:context,allowUI:true)
        defer { key.resetBytes(in:0..<key.count) }
        let payload = try openSnapshotPayload(old,key:key,scope:binding.source)
        guard payload.accountRecovery == nil,
              (payload.vault?.pendingPolicyMutations ?? []).isEmpty,
              (payload.vault?.quarantinedOrganizations ?? []).isEmpty else { throw SnapshotError.protectedAccountSwitch }
        return try publish(credentials,scope:binding.target,expected:expected,passwordUnlock:material,session:session,vault:vault,
                           includeVault:true,priorSnapshotKey:key,switching:binding)
    }
    func inspectAccountSwitch(expected:String,operationID:String? = nil) throws -> (SnapshotState,AccountSwitchReceipt) {
        let before = try files.locked { () -> SnapshotState in
            let state = try files.read()
            guard state.revision == expected, let record = try files.accountSwitchRecord(state),
                  operationID == nil || operationID == record.binding.operationID,
                  state.snapshot?.header.scope == record.binding.target else { throw SnapshotError.stale }
            return state
        }
        guard let snapshot = before.snapshot else { throw SnapshotError.unavailable }
        let context = LAContext(); defer { context.invalidate() }
        var key = try keys.read(id:snapshot.header.keyID,context:context,allowUI:true)
        defer { key.resetBytes(in:0..<key.count) }
        _ = try openSnapshotPayload(snapshot,key:key,scope:snapshot.header.scope)
        return try files.locked {
            let current = try files.read()
            guard current.revision == expected, current.snapshot?.header.id == snapshot.header.id,
                  let record = try files.accountSwitchRecord(current), operationID == nil || operationID == record.binding.operationID else { throw SnapshotError.stale }
            return (current,AccountSwitchReceipt(binding:record.binding,newSnapshotID:record.newSnapshotID,phase:record.phase))
        }
    }
    func confirmAccountSwitch(expected:String,operationID:String,unlockKey:Data?) throws -> (SnapshotLease,AccountSwitchReceipt) {
        let before = try files.locked { () -> SnapshotState in
            let state = try files.read()
            guard state.revision == expected, let record = try files.accountSwitchRecord(state),
                  record.binding.operationID == operationID, state.snapshot?.header.scope == record.binding.target else { throw SnapshotError.stale }
            return state
        }
        guard let snapshot = before.snapshot else { throw SnapshotError.unavailable }
        var key:Data
        let context = LAContext(); defer { context.invalidate() }
        if let unlockKey { key = try unwrapSnapshotKey(snapshot,unlockKey:unlockKey) }
        else { key = try keys.read(id:snapshot.header.keyID,context:context,allowUI:true) }
        defer { key.resetBytes(in:0..<key.count) }
        let payload = try openSnapshotPayload(snapshot,key:key,scope:snapshot.header.scope)
        return try files.locked {
            var current = try files.read()
            guard current.revision == expected, current.snapshot?.header.id == snapshot.header.id,
                  var record = try files.accountSwitchRecord(current), record.binding.operationID == operationID,
                  record.newSnapshotID == snapshot.header.id,
                  record.vaultHash == targetDigest(try snapshotJSON(payload.vault)),
                  record.sessionHash == targetDigest(payload.session ?? Data()),
                  record.wrapperHash == targetDigest(try snapshotJSON(snapshot.passwordUnlock)) else { throw SnapshotError.stale }
            if record.phase == "pending" {
                guard let old = record.oldSnapshot else { throw SnapshotError.corrupt }
                record.oldSnapshot = nil; record.phase = "confirmed"
                current.retiredKeys.append(old.header.keyID)
                current.revision = UUID().uuidString
                try files.storeAccountSwitch(record,in:&current)
                try files.write(current)
                // Failure after rename must not delete a possibly current key.
                // Retirement is durable; the existing cleanup path retries it.
            }
            let receipt = AccountSwitchReceipt(binding:record.binding,newSnapshotID:record.newSnapshotID,phase:record.phase)
            let blocked = try files.isTargetBlocked(current,scope:snapshot.header.scope)
            return (SnapshotLease(revision:current.revision,header:snapshot.header,expiresAt:clock()+60,
                                  credentials:blocked ? [] : payload.safeCandidates,session:blocked ? nil : payload.session,
                                  vault:blocked ? nil : payload.vault,recoveryOnly:blocked),receipt)
        }
    }
}
