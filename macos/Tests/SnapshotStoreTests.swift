// SPDX-License-Identifier: GPL-3.0-only
import XCTest
import LocalAuthentication
@testable import CredentialModel

// Deliberately a test double. Passing these tests is NOT real Touch ID evidence.
private final class MemoryKeys: SnapshotKeyStore {
    var values: [String: Data] = [:]
    var failCreate = false
    var failDelete = false
    var readError: SnapshotError?
    var afterRead: (() throws -> Void)?
    func create(id: String, key: Data) throws {
        if failCreate { throw SnapshotError.keychain(-1) }
        values[id] = key
    }
    func read(id: String, context: LAContext, allowUI: Bool) throws -> Data {
        guard allowUI else { throw SnapshotError.authenticationRequired }
        if let readError { throw readError }
        guard let key = values[id] else { throw SnapshotError.unavailable }
        try afterRead?()
        return key
    }
    func delete(id: String) throws {
        if failDelete { throw SnapshotError.keychain(-1) }
        values[id] = nil
    }
}

private final class DeferredIndex: SnapshotIdentitySink {
    var onReplace: (([SnapshotIdentity], @escaping (Bool) -> Void) -> Void)?
    func replace(_ identities: [SnapshotIdentity], completion: @escaping (Bool) -> Void) {
        onReplace?(identities, completion)
    }
}

final class SnapshotStoreTests: XCTestCase {
    private var directory: URL!
    private var keys: MemoryKeys!
    private var store: SnapshotStore!
    private var now: TimeInterval = 100
    private var credential: VaultCredential {
        VaultCredential(id: "entry-1", title: "Secret title", username: "secret-user@localhost",
                       password: "unique-test-secret-123456", hosts: ["localhost"], url: "http://localhost:18472/")
    }
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("snapshot-tests-\(UUID().uuidString)")
        keys = MemoryKeys()
        now = 100
        store = try SnapshotStore(directory: directory, keys: keys, clock: { self.now })
    }
    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
        store = nil
        keys = nil
    }
    @discardableResult private func publish() throws -> SnapshotLease {
        try store.publish([credential], scope: .demo, expected: store.state().revision)
    }
    private func unlock() throws -> SnapshotLease {
        try store.unlock(scope: .demo, context: LAContext(), allowUI: true)
    }
    private func assertError(_ expected: SnapshotError, _ action: () throws -> Void,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) {
            XCTAssertEqual($0 as? SnapshotError, expected, file: file, line: line)
        }
    }

    private var passwordMaterial: PasswordUnlockMaterial {
        // Go/Swift wire fixture, matching the independently checked Go KDF vector.
        let json = #"{"config":{"email":"fixture@example.invalid","kdf":{"kdf":0,"kdfIterations":5000,"kdfMemory":0,"kdfParallelism":0,"salt":null}},"key":"fZ4n4RFTciO1YkaotNmnX2vvL/DJ86QolOu1QqT03tQ="}"#
        return try! JSONDecoder().decode(PasswordUnlockMaterial.self, from: Data(json.utf8))
    }
    @discardableResult private func publishPassword() throws -> SnapshotLease {
        try store.publish([credential], scope: .demo, expected: store.state().revision, passwordUnlock: passwordMaterial)
    }
    private func passwordUnlock(expected: String? = nil, key: Data? = nil) throws -> SnapshotLease {
        try store.unlockWithPassword(scope: .demo, expected: expected ?? store.state().revision, unlockKey: key ?? passwordMaterial.key)
    }

    func testPasswordUnlockAfterLockAndReopenWithoutKeychain() throws {
        try publishPassword()
        try store.lock()
        keys.readError = .authenticationRequired
        let reopened = try SnapshotStore(directory: directory, keys: keys)
        let state = try reopened.state()
        let lease = try reopened.unlockWithPassword(scope: .demo, expected: state.revision, unlockKey: passwordMaterial.key)
        XCTAssertEqual(lease.credentials, [credential])
        XCTAssertEqual(state.snapshot?.passwordUnlock?.config, passwordMaterial.config)
        let data = try Data(contentsOf: directory.appendingPathComponent("snapshot-v1.json"))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        for secret in [credential.password, credential.username, credential.title, passwordMaterial.key.base64EncodedString(), "fixture-master-password"] {
            XCTAssertFalse(text.contains(secret))
        }
        // Adding password unlock never weakens the system-authenticated route.
        assertError(.authenticationRequired) { _ = try self.unlock() }
        keys.readError = nil
        XCTAssertEqual(try unlock().credentials, [credential])
    }
    func testWrongPasswordAndTamperedWrapperDoNotChangeSnapshot() throws {
        let lease = try publishPassword()
        assertError(.invalidPassword) { _ = try self.passwordUnlock(key: Data(repeating: 99, count: 32)) }
        XCTAssertEqual(try store.state().revision, lease.revision)
        XCTAssertEqual(try passwordUnlock().credentials, [credential])
        try store.files.locked {
            var state = try store.files.read()
            let wrapper = try XCTUnwrap(state.snapshot?.passwordUnlock)
            var bytes = wrapper.sealed
            bytes[bytes.count - 1] ^= 0xff
            state.snapshot?.passwordUnlock = PasswordWrappedSnapshotKey(config: wrapper.config, sealed: bytes)
            try store.files.write(state)
        }
        assertError(.invalidPassword) { _ = try self.passwordUnlock() }
        // The independent Keychain route survives a damaged password wrapper.
        XCTAssertEqual(try unlock().credentials, [credential])
    }
    func testPasswordWrapperBindsHeaderAndKDFConfiguration() throws {
        try publishPassword()
        let old = try XCTUnwrap(store.state().snapshot)
        try publishPassword()
        try store.files.locked {
            var state = try store.files.read()
            // A valid envelope from a previous snapshot cannot unlock this one.
            state.snapshot?.passwordUnlock = old.passwordUnlock
            try store.files.write(state)
        }
        assertError(.invalidPassword) { _ = try self.passwordUnlock() }
        try publishPassword()
        try store.files.locked {
            var state = try store.files.read()
            let wrapper = try XCTUnwrap(state.snapshot?.passwordUnlock)
            let config = PasswordUnlockConfig(email: "other@example.invalid", kdf: wrapper.config.kdf)
            state.snapshot?.passwordUnlock = PasswordWrappedSnapshotKey(config: config, sealed: wrapper.sealed)
            try store.files.write(state)
        }
        assertError(.invalidPassword) { _ = try self.passwordUnlock() }
    }
    func testPasswordUnlockRejectsStaleRevisionScopeLogoutAndExpiredLease() throws {
        let original = try publishPassword()
        try store.lock()
        assertError(.stale) { _ = try self.passwordUnlock(expected: original.revision) }
        let fresh = try passwordUnlock()
        let wrongScopes = [SnapshotScope(server: "https://other.invalid", account: SnapshotScope.demo.account),
                           SnapshotScope(server: SnapshotScope.demo.server, account: "other-account")]
        for scope in wrongScopes {
            assertError(.wrongScope) {
                _ = try self.store.unlockWithPassword(scope: scope, expected: fresh.revision, unlockKey: self.passwordMaterial.key)
            }
        }
        now += 61
        assertError(.expired) { try self.store.withCurrentLease(fresh) {} }
        let beforeLock = try passwordUnlock()
        try store.lock()
        assertError(.stale) { try self.store.withCurrentLease(beforeLock) {} }
        let beforeLogout = try passwordUnlock()
        try store.logout(expected: beforeLogout.revision)
        assertError(.stale) { try self.store.withCurrentLease(beforeLogout) {} }
        assertError(.unavailable) { _ = try self.passwordUnlock() }
    }
    func testPasswordUnlockRejectsReplacedAccountAndOldWrappingKey() throws {
        let original = try publishPassword()
        let replacement = PasswordUnlockMaterial(config: passwordMaterial.config, key: Data(repeating: 71, count: 32))
        let current = try store.publish([credential], scope: .demo, expected: original.revision, passwordUnlock: replacement)
        assertError(.invalidPassword) { _ = try self.passwordUnlock() }
        XCTAssertEqual(try passwordUnlock(key: replacement.key).credentials, [credential])
        try store.logout(expected: current.revision)
        let other = SnapshotScope(server: "https://other.invalid", account: "other")
        let lease = try store.publish([credential], scope: other, expected: store.state().revision, passwordUnlock: replacement)
        assertError(.wrongScope) {
            _ = try self.store.unlockWithPassword(scope: .demo, expected: lease.revision, unlockKey: replacement.key)
        }
    }
    func testLegacySnapshotStillUsesSystemAuthentication() throws {
        try publish()
        XCTAssertNil(try store.state().snapshot?.passwordUnlock)
        assertError(.passwordUnlockUnavailable) { _ = try self.passwordUnlock() }
        XCTAssertEqual(try unlock().credentials, [credential])
    }
    func testInvalidPasswordConfigurationDoesNotReplaceSnapshot() throws {
        let original = try publishPassword()
        let invalid = PasswordUnlockMaterial(config: passwordMaterial.config, key: Data(repeating: 1, count: 16))
        assertError(.invalidInput) {
            _ = try self.store.publish([self.credential], scope: .demo, expected: original.revision, passwordUnlock: invalid)
        }
        XCTAssertEqual(try store.state().revision, original.revision)
        XCTAssertEqual(try passwordUnlock().credentials, [credential])
    }

    func testSavedSessionEncryptedAndRestoredOnlyByAppUnlock() throws {
        let session = Data("fixture-refresh-token-and-user-key".utf8)
        let published = try store.publish([credential], scope: .demo, expected: store.state().revision,
                                          passwordUnlock: passwordMaterial, session: session)
        XCTAssertNil(published.session) // Indexing never receives login credentials.
        let data = try Data(contentsOf: directory.appendingPathComponent("snapshot-v1.json"))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertFalse(text.contains(String(decoding: session, as: UTF8.self)))
        XCTAssertFalse(text.contains(session.base64EncodedString()))
        XCTAssertNil(try unlock().session) // AutoFill's default lease omits it.
        try store.lock()
        let reopened = try SnapshotStore(directory: directory, keys: keys)
        XCTAssertEqual(try reopened.unlock(scope: .demo, context: LAContext(), allowUI: true, includeSession: true).session, session)
        XCTAssertEqual(try reopened.unlockWithPassword(scope: .demo, expected: reopened.state().revision, unlockKey: passwordMaterial.key).session, session)
        keys.readError = .cancelled
        assertError(.cancelled) { _ = try reopened.unlock(scope: .demo, context: LAContext(), allowUI: true, includeSession: true) }
        assertError(.invalidPassword) { _ = try self.passwordUnlock(key: Data(repeating: 33, count: 32)) }
    }
    func testRefreshCheckpointPreservesVaultAndPersistsNewToken() throws {
        let old = try store.publish([credential], scope: .demo, expected: store.state().revision,
                                    passwordUnlock: passwordMaterial, session: Data("refresh-old".utf8))
        try store.acknowledgeIndex(token: old.header.id)
        let before = try XCTUnwrap(store.state().snapshot)
        let updated = try store.saveSession(Data("refresh-new".utf8), scope: .demo, expected: old.revision, unlockKey: passwordMaterial.key)
        XCTAssertNotEqual(old.revision, updated.revision)
        XCTAssertEqual(old.header, updated.header)
        XCTAssertEqual(try store.state().snapshot?.passwordUnlock?.sealed, before.passwordUnlock?.sealed)
        XCTAssertNotEqual(try store.state().snapshot?.sealed, before.sealed)
        XCTAssertFalse(try store.state().indexPending)
        XCTAssertNil(updated.session)
        assertError(.stale) { try self.store.withCurrentLease(old) {} }
        try store.lock()
        let restored = try passwordUnlock()
        XCTAssertEqual(restored.credentials, [credential])
        XCTAssertEqual(restored.session, Data("refresh-new".utf8))
        XCTAssertEqual(keys.values.count, 1)
    }
    func testRevocationBlocksLateRefreshCheckpointAndRemovesSavedSession() throws {
        let session = Data("refresh-secret".utf8)
        let old = try store.publish([credential], scope: .demo, expected: store.state().revision,
                                    passwordUnlock: passwordMaterial, session: session)
        try store.lock()
        assertError(.stale) {
            _ = try self.store.saveSession(session, scope: .demo, expected: old.revision, unlockKey: self.passwordMaterial.key)
        }
        XCTAssertEqual(try passwordUnlock().session, session)
        let unlocked = try passwordUnlock()
        try store.logout(expected: unlocked.revision)
        XCTAssertNil(try store.state().snapshot)
        assertError(.stale) {
            _ = try self.store.saveSession(session, scope: .demo, expected: unlocked.revision, unlockKey: self.passwordMaterial.key)
        }
        assertError(.unavailable) {
            _ = try self.store.saveSession(session, scope: .demo, expected: self.store.state().revision, unlockKey: self.passwordMaterial.key)
        }
        let other = SnapshotScope(server: "https://other.invalid", account: "other-account")
        let replacement = try store.publish([credential], scope: other, expected: store.state().revision,
                                            passwordUnlock: passwordMaterial, session: Data("other-refresh".utf8))
        assertError(.wrongScope) {
            _ = try self.store.saveSession(session, scope: .demo, expected: replacement.revision, unlockKey: self.passwordMaterial.key)
        }
    }
    func testRefreshCheckpointRejectsWrongKeyAndOversizedSession() throws {
        let old = try publishPassword()
        assertError(.invalidPassword) {
            _ = try self.store.saveSession(Data("refresh".utf8), scope: .demo, expected: old.revision, unlockKey: Data(repeating: 88, count: 32))
        }
        for session in [Data(), Data(repeating: 1, count: 64 * 1024 + 1)] {
            assertError(.invalidInput) {
                _ = try self.store.saveSession(session, scope: .demo, expected: old.revision, unlockKey: self.passwordMaterial.key)
            }
        }
        XCTAssertEqual(try store.state().revision, old.revision)
        XCTAssertEqual(try passwordUnlock().credentials, [credential])
    }
    func testLockDuringSystemAuthenticationCannotReturnSavedSession() throws {
        _ = try store.publish([credential], scope: .demo, expected: store.state().revision,
                              passwordUnlock: passwordMaterial, session: Data("refresh".utf8))
        keys.afterRead = { try self.store.lock() }
        assertError(.stale) { _ = try self.store.unlock(scope: .demo, context: LAContext(), allowUI: true, includeSession: true) }
    }

    func testEncryptedDiskAndReopenedStore() throws {
        try publish()
        let data = try Data(contentsOf: directory.appendingPathComponent("snapshot-v1.json"))
        let text = try XCTUnwrap(String(data: data, encoding: .utf8))
        for secret in [credential.password, credential.username, credential.title] { XCTAssertFalse(text.contains(secret)) }
        let reopened = try SnapshotStore(directory: directory, keys: keys)
        XCTAssertEqual(try reopened.unlock(scope: .demo, context: LAContext(), allowUI: true).credentials, [credential])
        let permissions = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("snapshot-v1.json").path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
    }
    func testRandomKeyAndNonceForEveryReplacement() throws {
        let first = try publish()
        let oldCiphertext = try store.state().snapshot?.sealed
        let second = try publish()
        XCTAssertNotEqual(first.header.keyID, second.header.keyID)
        XCTAssertNotEqual(first.header.id, second.header.id)
        XCTAssertNotEqual(oldCiphertext, try store.state().snapshot?.sealed)
        XCTAssertNil(keys.values[first.header.keyID])
        XCTAssertEqual(keys.values.count, 1)
    }
    func testLockAndExpiryInvalidateOldLeases() throws {
        let lease = try publish()
        try store.lock()
        assertError(.stale) { try store.withCurrentLease(lease) { XCTFail("old request submitted") } }
        let fresh = try unlock()
        now += 61
        assertError(.expired) { try store.withCurrentLease(fresh) { XCTFail("expired request submitted") } }
    }
    func testLogoutDuringAuthenticationRejectsLateSecret() throws {
        try publish()
        keys.afterRead = { try self.store.logout(expected: self.store.state().revision) }
        assertError(.stale) { _ = try self.unlock() }
        XCTAssertTrue(try store.state().signedOut)
        XCTAssertTrue(keys.values.isEmpty)
    }
    func testLockDuringAuthenticationRejectsLateSecret() throws {
        try publish()
        keys.afterRead = { try self.store.lock() }
        assertError(.stale) { _ = try self.unlock() }
    }
    func testAuthenticationCancellationAndNoInteraction() throws {
        try publish()
        keys.readError = .cancelled
        assertError(.cancelled) { _ = try self.unlock() }
        assertError(.authenticationRequired) {
            _ = try self.store.unlock(scope: .demo, context: LAContext(), allowUI: false)
        }
        XCTAssertNotNil(try store.state().snapshot)
    }
    func testTamperedCiphertextFailsClosed() throws {
        try publish()
        try store.files.locked {
            var state = try store.files.read()
            let old = try XCTUnwrap(state.snapshot)
            var bytes = old.sealed
            bytes[bytes.count - 1] ^= 0xff
            state.snapshot = EncryptedSnapshot(header: old.header, sealed: bytes)
            try store.files.write(state)
        }
        assertError(.corrupt) { _ = try self.unlock() }
    }
    func testWrongScopeAndHeaderTamperingFailClosed() throws {
        try publish()
        assertError(.wrongScope) {
            _ = try self.store.unlock(scope: SnapshotScope(server: "https://other.invalid", account: "other"), context: LAContext(), allowUI: true)
        }
        try store.files.locked {
            var state = try store.files.read()
            let old = try XCTUnwrap(state.snapshot)
            let header = SnapshotHeader(format: 1, id: UUID().uuidString, keyID: old.header.keyID,
                                        scope: old.header.scope, createdAt: old.header.createdAt, count: old.header.count)
            state.snapshot = EncryptedSnapshot(header: header, sealed: old.sealed)
            try store.files.write(state)
        }
        assertError(.corrupt) { _ = try self.unlock() }
    }
    func testReplacementRemovesCredentialAndInvalidatesRecordIdentity() throws {
        let second = VaultCredential(id: "entry-2", title: "Other", username: "other", password: "other", hosts: ["localhost"], url: credential.url)
        let old = try store.publish([credential, second], scope: .demo, expected: store.state().revision)
        let fresh = try store.publish([second], scope: old.header.scope, expected: old.revision)
        XCTAssertEqual(fresh.credentials, [second])
        assertError(.stale) { try self.store.withCurrentLease(old) {} }
        let record = SnapshotIndex.recordID(snapshotID: old.header.id, credentialID: credential.id)
        XCTAssertNil(SnapshotIndex.credentialID(recordID: record, snapshotID: fresh.header.id))
    }
    func testStaleWriterCannotOverwriteNewRevision() throws {
        let revision = try store.state().revision
        let other = try SnapshotStore(directory: directory, keys: keys)
        try publish()
        assertError(.stale) { _ = try other.publish([self.credential], scope: .demo, expected: revision) }
        XCTAssertEqual(try unlock().credentials, [credential])
    }
    func testFailedKeyCreationRetainsPriorSnapshotAndJournalsSafely() throws {
        let old = try publish()
        keys.failCreate = true
        assertError(.keychain(-1)) { _ = try self.publish() }
        XCTAssertEqual(try store.state().snapshot?.header.id, old.header.id)
        XCTAssertTrue(try store.state().retiredKeys.isEmpty)
        XCTAssertEqual(try unlock().credentials, [credential])
    }
    func testLogoutRevokesBeforeCleanupAndRetryIsIdempotent() throws {
        let lease = try publish()
        keys.failDelete = true
        assertError(.keychain(-1)) { try self.store.logout(expected: lease.revision) }
        XCTAssertNil(try store.state().snapshot)
        XCTAssertFalse(try store.state().retiredKeys.isEmpty)
        assertError(.unavailable) { _ = try self.unlock() }
        assertError(.stale) { try self.store.withCurrentLease(lease) {} }
        keys.failDelete = false
        try store.retryCleanup()
        try store.retryCleanup()
        XCTAssertTrue(keys.values.isEmpty)
        XCTAssertTrue(try store.state().retiredKeys.isEmpty)
    }
    func testCorruptOrUnsupportedStateCannotBeTreatedAsEmpty() throws {
        try Data("not a snapshot".utf8).write(to: directory.appendingPathComponent("snapshot-v1.json"))
        assertError(.corrupt) { _ = try self.store.state() }
        assertError(.corrupt) { _ = try self.store.publish([self.credential], scope: .demo, expected: SnapshotState.initialRevision) }
    }
    func testLateIndexAckCannotMarkNewGenerationSynchronized() throws {
        let old = try publish()
        let fresh = try publish()
        assertError(.stale) { try self.store.acknowledgeIndex(token: old.header.id) }
        XCTAssertTrue(try store.state().indexPending)
        try store.acknowledgeIndex(token: fresh.header.id)
        XCTAssertFalse(try store.state().indexPending)
    }
    func testEmptySyncRevokesOldCredentialsAndClearsIdentityIndex() throws {
        let scope = SnapshotScope(server: "https://vault.example.com", account: "account-a")
        let old = try store.publish([credential], scope: scope, expected: store.state().revision)
        let sink = DeferredIndex()
        let indexed = expectation(description: "old identities published")
        sink.onReplace = { identities, callback in XCTAssertFalse(identities.isEmpty); callback(true) }
        SnapshotIndex.schedule(store: store, lease: old, sink: sink) { success in XCTAssertTrue(success); indexed.fulfill() }
        wait(for: [indexed], timeout: 3)

        let empty = try store.publish([], scope: scope, expected: old.revision)
        XCTAssertTrue(try store.unlock(scope: scope, context: LAContext(), allowUI: true).credentials.isEmpty)
        XCTAssertEqual(try store.state().snapshot?.header.count, 0)
        XCTAssertNil(keys.values[old.header.keyID])
        assertError(.stale) { try self.store.withCurrentLease(old) { XCTFail("deleted password submitted") } }
        XCTAssertNil(SnapshotIndex.credentialID(recordID: SnapshotIndex.recordID(snapshotID: old.header.id, credentialID: credential.id), snapshotID: empty.header.id))
        let cleared = expectation(description: "empty replacement acknowledged")
        let emptySink = DeferredIndex()
        emptySink.onReplace = { identities, callback in XCTAssertTrue(identities.isEmpty); callback(true) }
        SnapshotIndex.schedule(store: store, lease: empty, sink: emptySink) { success in XCTAssertTrue(success); cleared.fulfill() }
        wait(for: [cleared], timeout: 3)
        XCTAssertFalse(try store.state().indexPending)
    }
    func testFirstLoginCanPublishAnEmptyVault() throws {
        let scope = SnapshotScope(server: "https://vault.example.com", account: "empty-account")
        let lease = try store.publish([], scope: scope, expected: store.state().revision)
        XCTAssertEqual(lease.header.count, 0)
        XCTAssertEqual(try store.state().snapshot?.header.scope, scope)
    }
    func testPublicationReceiptCannotAdoptInterveningLockRevision() throws {
        let other = try SnapshotStore(directory: directory, keys: keys)
        let publishing = try SnapshotStore(directory: directory, keys: keys, changed: { try! other.lock() })
        let lease = try publishing.publish([credential], scope: .demo, expected: store.state().revision)
        // The bridge uses this guard before returning a successful publication receipt.
        assertError(.stale) { try publishing.withCurrentLease(lease) { _ = try publishing.files.read() } }
    }
    func testAccountSwitchRequiresExplicitRevocation() throws {
        let first = SnapshotScope(server: "https://vault.example.com", account: "account-a")
        let second = SnapshotScope(server: "https://vault.example.com", account: "account-b")
        let lease = try store.publish([credential], scope: first, expected: store.state().revision)
        assertError(.wrongScope) { _ = try self.store.publish([self.credential], scope: second, expected: lease.revision) }
        try store.withCurrentLease(lease) {}
        XCTAssertEqual(keys.values.count, 1)
        try store.logout(expected: lease.revision)
        _ = try store.publish([credential], scope: second, expected: store.state().revision)
        XCTAssertEqual(try store.state().snapshot?.header.scope, second)
    }
    func testLockInvalidatesPublishEvenBeforeFirstSnapshot() throws {
        let revision = try store.state().revision
        try store.lock()
        assertError(.stale) { _ = try self.store.publish([self.credential], scope: .demo, expected: revision) }
        XCTAssertNil(try store.state().snapshot)
    }
    func testConcurrentWritersHaveExactlyOneCASWinner() throws {
        let revision = try store.state().revision
        let second = try SnapshotStore(directory: directory, keys: keys)
        let resultsLock = NSLock()
        var successes = 0
        var staleErrors = 0
        DispatchQueue.concurrentPerform(iterations: 2) { index in
            do {
                _ = try (index == 0 ? self.store! : second).publish([self.credential], scope: .demo, expected: revision)
                resultsLock.lock(); successes += 1; resultsLock.unlock()
            } catch {
                if error as? SnapshotError == .stale { resultsLock.lock(); staleErrors += 1; resultsLock.unlock() }
                else { XCTFail("Unexpected concurrent update error: \(error)") }
            }
        }
        XCTAssertEqual(successes, 1)
        XCTAssertEqual(staleErrors, 1)
        XCTAssertEqual(keys.values.count, 1)
    }
    func testSnapshotFileSymlinkIsRejected() throws {
        let target = directory.appendingPathComponent("unrelated.json")
        try snapshotJSON(SnapshotState()).write(to: target)
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("snapshot-v1.json"), withDestinationURL: target)
        assertError(.corrupt) { _ = try self.store.state() }
    }
    func testIndexServiceCannotBlockRevocationOrOvertakeClear() throws {
        let lease = try publish()
        let firstStarted = expectation(description: "index write started")
        let firstFinished = expectation(description: "late write rejected")
        let clearFinished = expectation(description: "clear acknowledged")
        let oldSink = DeferredIndex()
        var callback: ((Bool) -> Void)?
        oldSink.onReplace = { _, completion in callback = completion; firstStarted.fulfill() }
        SnapshotIndex.schedule(store: store, lease: lease, sink: oldSink) { accepted in
            XCTAssertFalse(accepted); firstFinished.fulfill()
        }
        wait(for: [firstStarted], timeout: 3)
        try store.logout(expected: lease.revision) // Must complete while index callback is pending.
        let clearSink = DeferredIndex()
        clearSink.onReplace = { identities, completion in XCTAssertTrue(identities.isEmpty); completion(true) }
        SnapshotIndex.schedule(store: store, lease: nil, sink: clearSink) { accepted in
            XCTAssertTrue(accepted); clearFinished.fulfill()
        }
        callback?(true)
        wait(for: [firstFinished, clearFinished], timeout: 3)
        XCTAssertFalse(try store.state().indexPending)
        XCTAssertTrue(try store.state().signedOut)
    }
}
