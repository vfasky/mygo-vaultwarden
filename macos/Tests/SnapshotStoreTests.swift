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
    private var credential: DemoCredential {
        DemoCredential(id: "entry-1", title: "Secret title", username: "secret-user@localhost",
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
    func testDeleteRotatesKeyAndInvalidatesRecordIdentity() throws {
        let second = DemoCredential(id: "entry-2", title: "Other", username: "other", password: "other", hosts: ["localhost"], url: credential.url)
        let old = try store.publish([credential, second], scope: .demo, expected: store.state().revision)
        let fresh = try store.deleteCredential(id: credential.id, expected: old.revision, context: LAContext())
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
