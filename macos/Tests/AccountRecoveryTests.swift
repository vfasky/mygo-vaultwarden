// SPDX-License-Identifier: GPL-3.0-only
import XCTest
import LocalAuthentication
@testable import CredentialModel

private final class RecoveryMemoryKeys: SnapshotKeyStore {
    var values: [String: Data] = [:]
    var failCreate = false
    func create(id: String, key: Data) throws { if failCreate { throw SnapshotError.keychain(-1) }; values[id] = key }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data { guard let key = values[id] else { throw SnapshotError.unavailable }; return key }
    func delete(id: String) throws { values[id] = nil }
}
final class AccountRecoveryTests: XCTestCase {
    var directory: URL!
    private var keys: RecoveryMemoryKeys!
    var store: SnapshotStore!
    let scope = SnapshotScope(server: "https://recovery.example.invalid", account: "recovery-account")
    var material: PasswordUnlockMaterial { PasswordUnlockMaterial(config: PasswordUnlockConfig(email: "recovery@example.invalid", kdf: PasswordUnlockKDF(kdf: 0, kdfIterations: 5000, kdfMemory: 0, kdfParallelism: 0, salt: nil)), key: Data(repeating: 31, count: 32)) }
    var vault: VaultData { VaultData(version: 2, scope: scope, sync: Data(#"{"profile":{"id":"recovery-account","organizations":[]},"ciphers":[],"future":{"n":9007199254740993}}"#.utf8), pendingPolicyMutations: [PendingPolicyMutation(organizationId: "org-1", policyType: 15, mutationId: "mutation-1")], quarantinedOrganizations: ["org-2"]) }
    let session = Data("original-session-secret".utf8)
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("account-recovery-\(UUID().uuidString)")
        keys = RecoveryMemoryKeys()
        store = try SnapshotStore(directory: directory, keys: keys)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }
    func fixture(kind: String = "rotate-user-key") throws -> (SnapshotLease, AccountRecoveryBinding, Data) {
        let lease = try store.publish([], scope: scope, expected: "empty-v1", passwordUnlock: material, session: session, vault: vault)
        let encodedUnlock = material.key.base64EncodedString()
        let raw = try JSONSerialization.data(withJSONObject: ["version": 1, "operationId": String(repeating: "a", count: 32), "scope": ["server": scope.server, "account": scope.account], "kind": kind,
            "oldRevision": lease.revision, "oldSession": session.base64EncodedString(), "oldVault": try snapshotJSON(vault).base64EncodedString(),
            "oldUnlock": ["config": ["email": material.config.email, "kdf": ["kdf": 0, "kdfIterations": 5000, "kdfMemory": 0, "kdfParallelism": 0]], "key": encodedUnlock],
            "newUserKey": Data(repeating: 61, count: 64).base64EncodedString(), "newWrappedKey": "wrapped-new-key",
            "request": Data("{\"hash\":\"secret-proof\"}".utf8).base64EncodedString(), "futureExtension": ["opaque": "preserve-me"]])
        return (lease, AccountRecoveryBinding(operationId: String(repeating: "a", count: 32), oldRevision: lease.revision, epoch: 17, recordHash: recoveryDigest(raw)), raw)
    }
    func begin(_ lease: SnapshotLease, _ binding: AccountRecoveryBinding, _ raw: Data) throws -> SnapshotLease {
        try store.accountRecovery(operation: "accountRecoveryBegin", scope: scope, expected: lease.revision, unlockKey: material.key, binding: binding, record: raw).0
    }
    func query(_ binding: AccountRecoveryBinding? = nil) throws -> AccountRecoveryJournal {
        try store.accountRecovery(operation: "accountRecoveryQuery", scope: scope, expected: store.state().revision, unlockKey: material.key, binding: binding).1!
    }
    func testBarrierReopenLockOrdinaryWritersAndImmutableMaterials() throws {
        let (old, binding, raw) = try fixture()
        let barrier = try begin(old, binding, raw)
        XCTAssertEqual(barrier.header.format, 2)
        XCTAssertNotEqual(old.header.id, barrier.header.id)
        XCTAssertThrowsError(try store.withCurrentLease(old) {})
        XCTAssertThrowsError(try store.unlock(scope: scope, context: LAContext(), allowUI: true))
        XCTAssertThrowsError(try store.unlockWithPassword(scope: scope, expected: barrier.revision, unlockKey: material.key))
        XCTAssertThrowsError(try store.publish([], scope: scope, expected: barrier.revision, passwordUnlock: material, session: session, vault: vault))
        XCTAssertThrowsError(try store.saveSession(Data("new-token".utf8), scope: scope, expected: barrier.revision, unlockKey: material.key))
        XCTAssertThrowsError(try store.logout(expected: barrier.revision))
        // Simulates process loss after begin / unknown network outcome: independent
        // store has no in-memory transaction, yet recovers the exact original bytes.
        store = try SnapshotStore(directory: directory, keys: keys)
        try store.lock()
        XCTAssertThrowsError(try store.withCurrentLease(barrier) {})
        XCTAssertEqual(try query(binding).record, raw)
        let revision = try store.state().revision
        let result = try store.accountRecovery(operation: "accountRecoveryResult", scope: scope, expected: revision, unlockKey: material.key, binding: binding, phase: "unknown")
        _ = try store.accountRecovery(operation: "accountRecoveryCheckpoint", scope: scope, expected: result.0.revision, unlockKey: material.key, binding: binding, session: Data("recovery-new-token".utf8))
        let saved = try query(binding)
        XCTAssertEqual(saved.record, raw)
        XCTAssertEqual(saved.phase, "unknown")
        XCTAssertEqual(saved.checkpoint, Data("recovery-new-token".utf8))
        let disk = try Data(contentsOf: directory.appendingPathComponent("snapshot-v1.json"))
        for secret in ["secret-proof", "original-session-secret", "wrapped-new-key", "preserve-me", raw.base64EncodedString()] {
            XCTAssertNil(disk.range(of: Data(secret.utf8)))
        }
    }
    func testRejectWrongIdentityRevisionKeyHashAndMissingReceipt() throws {
        let (old, binding, raw) = try fixture()
        let wrong = AccountRecoveryBinding(operationId: binding.operationId, oldRevision: binding.oldRevision, epoch: binding.epoch, recordHash: String(repeating: "0", count: 64))
        XCTAssertThrowsError(try begin(old, wrong, raw))
        XCTAssertEqual(try store.state().revision, old.revision)
        let barrier = try begin(old, binding, raw)
        let foreign = AccountRecoveryBinding(operationId: String(repeating: "b", count: 32), oldRevision: binding.oldRevision, epoch: binding.epoch, recordHash: binding.recordHash)
        XCTAssertThrowsError(try query(foreign))
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryQuery", scope: SnapshotScope(server: scope.server, account: "foreign"), expected: barrier.revision, unlockKey: material.key, binding: binding))
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryQuery", scope: scope, expected: old.revision, unlockKey: material.key, binding: binding))
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryQuery", scope: scope, expected: barrier.revision, unlockKey: Data(repeating: 0, count: 32), binding: binding))
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, credentials: [], material: material, session: session, vault: vault))
        XCTAssertEqual(try query(binding).record, raw)
    }
    func testAtomicVerifiedReplacementPreservesIsolationAndDestroysOldKey() throws {
        let (old, binding, raw) = try fixture()
        var barrier = try begin(old, binding, raw)
        let fresh = VaultData(version: 1, scope: scope, sync: vault.sync)
        let newMaterial = PasswordUnlockMaterial(config: material.config, key: Data(repeating: 72, count: 32))
        let bad = AccountRecoveryResolution(binding: binding, mode: "verified", userConfirmed: true, authorityVerified: true, resourcesVerified: true, vaultHash: "wrong")
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, resolution: bad, credentials: [], material: newMaterial, session: session, vault: fresh))
        let resolution = AccountRecoveryResolution(binding: binding, mode: "verified", userConfirmed: true, authorityVerified: true, resourcesVerified: true, vaultHash: recoveryDigest(fresh.sync))
        keys.failCreate = true
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, resolution: resolution, credentials: [], material: newMaterial, session: session, vault: fresh))
        XCTAssertEqual(try query(binding).record, raw)
        XCTAssertNotNil(keys.values[old.header.keyID])
        keys.failCreate = false
        barrier = try store.accountRecovery(operation: "accountRecoveryQuery", scope: scope, expected: store.state().revision, unlockKey: material.key, binding: binding).0
        let (complete, journal) = try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, resolution: resolution, credentials: [], material: newMaterial, session: session, vault: fresh)
        XCTAssertNil(journal)
        XCTAssertEqual(complete.header.format, 1)
        XCTAssertNotEqual(complete.header.keyID, old.header.keyID)
        XCTAssertNil(keys.values[old.header.keyID])
        XCTAssertEqual(complete.vault?.pendingPolicyMutations, vault.pendingPolicyMutations)
        XCTAssertEqual(complete.vault?.quarantinedOrganizations, vault.quarantinedOrganizations)
        XCTAssertThrowsError(try query(binding))
        XCTAssertThrowsError(try store.withCurrentLease(barrier) {})
        XCTAssertThrowsError(try store.unlockWithPassword(scope: scope, expected: complete.revision, unlockKey: material.key))
        XCTAssertEqual(try store.unlockWithPassword(scope: scope, expected: complete.revision, unlockKey: newMaterial.key).session, session)
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: complete.revision, unlockKey: newMaterial.key, binding: binding, resolution: resolution, credentials: [], material: newMaterial, session: session, vault: fresh))
    }
    func testWriteFailureBeforeBarrierPreservesOriginalCiphertext() throws {
        let (old, binding, raw) = try fixture()
        let file = directory.appendingPathComponent("snapshot-v1.json")
        let original = try Data(contentsOf: file)
        // Directory write denial occurs before rename; restore only this fixture.
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: directory.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path) }
        XCTAssertThrowsError(try begin(old, binding, raw))
        XCTAssertEqual(try Data(contentsOf: file), original)
        XCTAssertEqual(try store.state().revision, old.revision)
    }
    func testDeletionRequiresConfirmedResultAndExplicitReceipt() throws {
        let (old, binding, raw) = try fixture(kind: "delete")
        let barrier = try begin(old, binding, raw)
        let receipt = AccountRecoveryResolution(binding: binding, mode: "delete", userConfirmed: true, authorityVerified: true, resourcesVerified: false, vaultHash: nil)
        XCTAssertThrowsError(try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, resolution: receipt))
        let confirmed = try store.accountRecovery(operation: "accountRecoveryResult", scope: scope, expected: barrier.revision, unlockKey: material.key, binding: binding, phase: "confirmed").0
        _ = try store.accountRecovery(operation: "accountRecoveryResolve", scope: scope, expected: confirmed.revision, unlockKey: material.key, binding: binding, resolution: receipt)
        XCTAssertTrue(try store.state().signedOut)
        XCTAssertNil(try store.state().snapshot)
        XCTAssertTrue(keys.values.isEmpty)
    }
}
