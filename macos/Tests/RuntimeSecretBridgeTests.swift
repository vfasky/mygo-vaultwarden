// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import CredentialModel

private final class RuntimeMemoryBoard: SensitivePasteboard {
    var changeCount = 0
    var owner: String?
    var value: String?
    var fail = false
    func replace(secret: String, owner: String) -> Bool { if fail { return false }; changeCount += 1; self.owner=owner; value=secret; return true }
    func clear() { changeCount += 1; owner=nil; value=nil }
    func userCopy(_ value: String) { changeCount += 1; owner=nil; self.value=value }
}
final class RuntimeSecretBridgeTests: XCTestCase {
    let scope = SnapshotScope(server:"https://runtime.example.invalid",account:"actor")
    func testNoRenewalExpiryGenerationAndExternalClipboardOwnership() {
        let board = RuntimeMemoryBoard()
        var wall: Int64 = 10000; var monotonic: TimeInterval = 3
        let manager = RuntimeSecretLeases(board:board,wall:{wall},monotonic:{monotonic})
        var request = RuntimeSecretRequest(operation:"activate",purpose:"secret",scope:scope,generation:1,deadlineUnixMS:20000)
        let active = manager.execute(request); XCTAssertTrue(active.ok); XCTAssertEqual(active.leaseID?.count,64)
        wall += 1000; monotonic += 1
        XCTAssertEqual(manager.execute(request).leaseID,active.leaseID)
        request.leaseID=active.leaseID; request.operation="copy"; request.requestID=UUID().uuidString; request.secret="fixture"
        XCTAssertTrue(manager.execute(request).ok)
        let copiedCount=board.changeCount
        XCTAssertTrue(manager.execute(request).ok); XCTAssertEqual(board.changeCount,copiedCount)
        request.secret="different"; XCTAssertFalse(manager.execute(request).ok)
        board.userCopy("user-value")
        request.operation="revoke";request.secret=nil
        XCTAssertTrue(manager.execute(request).ok); XCTAssertEqual(board.value,"user-value")
        request.operation="authorizeDisplay";XCTAssertFalse(manager.execute(request).ok)
        request.operation="activate";request.leaseID=nil;request.requestID=nil
        XCTAssertFalse(manager.execute(request).ok)
        request=RuntimeSecretRequest(operation:"activate",purpose:"secret",scope:scope,generation:2,deadlineUnixMS:21000)
        let next=manager.execute(request); XCTAssertTrue(next.ok)
        request.operation="copy";request.leaseID=next.leaseID;request.requestID=UUID().uuidString;request.secret="second"
        XCTAssertTrue(manager.execute(request).ok)
        let stale = RuntimeSecretRequest(operation:"revoke",purpose:"secret",scope:scope,generation:1,deadlineUnixMS:20000,leaseID:active.leaseID)
        XCTAssertFalse(manager.execute(stale).ok); XCTAssertEqual(board.value,"second")
        let foreign = RuntimeSecretRequest(operation:"authorizeDisplay",purpose:"secret",scope:SnapshotScope(server:scope.server,account:"other"),generation:2,deadlineUnixMS:21000,leaseID:next.leaseID)
        XCTAssertFalse(manager.execute(foreign).ok); XCTAssertEqual(board.value,"second")
        // Wall moving backwards cannot extend the original monotonic lifetime.
        wall=1000;monotonic=20;manager.expire();XCTAssertNil(board.value)
        XCTAssertFalse(manager.execute(request).ok)
    }
    func testPurposesAreIndependentAndRecoveryBindingIsExact() throws {
        let board=RuntimeMemoryBoard()
        let manager=RuntimeSecretLeases(board:board,wall:{10000},monotonic:{1})
        var secret=RuntimeSecretRequest(operation:"activate",purpose:"secret",scope:scope,generation:3,deadlineUnixMS:20000)
        let s=manager.execute(secret)
        let hash=targetDigest(Data("immutable-dispatch".utf8))
        var recovery=RuntimeSecretRequest(operation:"activate",purpose:"recovery",scope:scope,generation:3,deadlineUnixMS:20000,operationID:String(repeating:"a",count:32),summaryHash:hash)
        let r=manager.execute(recovery);XCTAssertTrue(r.ok)
        let authority=RuntimeRecoveryAuthority(scope:scope,generation:3,deadlineUnixMS:20000,leaseID:r.leaseID!,operationID:recovery.operationID!,summaryHash:hash)
        XCTAssertNoThrow(try manager.authorizeRecovery(authority))
        XCTAssertThrowsError(try manager.authorizeRecovery(RuntimeRecoveryAuthority(scope:scope,generation:3,deadlineUnixMS:20000,leaseID:s.leaseID!,operationID:recovery.operationID!,summaryHash:hash)))
        secret.operation="copy";secret.leaseID=s.leaseID;secret.secret="owned-by-secret";secret.requestID=UUID().uuidString
        XCTAssertTrue(manager.execute(secret).ok)
        recovery.operation="authorizeDisplay";recovery.leaseID=r.leaseID;XCTAssertFalse(manager.execute(recovery).ok)
        recovery.operation="revoke";XCTAssertTrue(manager.execute(recovery).ok)
        XCTAssertEqual(board.value,"owned-by-secret")
        XCTAssertThrowsError(try manager.authorizeRecovery(authority))
        var wrong=secret;wrong.leaseID=r.leaseID;XCTAssertFalse(manager.execute(wrong).ok)
    }
    func testBoundsAndFailedCopyDoNotGrantOrRenew() {
        let board=RuntimeMemoryBoard()
        let manager=RuntimeSecretLeases(board:board,wall:{10000},monotonic:{1})
        XCTAssertFalse(manager.execute(RuntimeSecretRequest(operation:"activate",purpose:"secret",scope:scope,generation:1,deadlineUnixMS:40001)).ok)
        var request=RuntimeSecretRequest(operation:"activate",purpose:"secret",scope:scope,generation:1,deadlineUnixMS:20000)
        let active=manager.execute(request);request.leaseID=active.leaseID;request.operation="copy";request.secret="fixture"
        board.fail=true;request.requestID=UUID().uuidString;XCTAssertFalse(manager.execute(request).ok)
        board.fail=false
        for _ in 0..<64 { request.requestID=UUID().uuidString;XCTAssertTrue(manager.execute(request).ok) }
        request.requestID=UUID().uuidString;XCTAssertFalse(manager.execute(request).ok)
        request.secret=String(repeating:"x",count:65537);XCTAssertFalse(manager.execute(request).ok)
    }
}
