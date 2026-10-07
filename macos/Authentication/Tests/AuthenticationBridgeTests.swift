// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import VaultAuthentication

final class AuthenticationBridgeTests: XCTestCase {
    func testOneCompletionAndRelease() async {
        await MainActor.run {
            let requests = AuthenticationRequests()
            let id = requests.reserve()
            requests.finish(id, Data("first".utf8), status: 1)
            requests.finish(id, Data("late".utf8), status: 1)
            var bytes = [UInt8](repeating: 0, count: 100)
            XCTAssertEqual(requests.take(id, into: &bytes, capacity: bytes.count), 5)
            XCTAssertEqual(String(bytes: bytes.prefix(5), encoding: .utf8), "first")
            XCTAssertEqual(requests.take(id, into: &bytes, capacity: bytes.count), -2)
            requests.release(id)
            requests.finish(id, Data("later".utf8), status: 1)
            XCTAssertEqual(requests.take(id, into: &bytes, capacity: bytes.count), -2)
            XCTAssertGreaterThan(requests.reserve(), id)
        }
    }
    func testBoundedRegistryCancelAndLateCallback() async {
        await MainActor.run {
            let requests = AuthenticationRequests()
            let ids = (0..<AuthenticationRequests.limit).map { _ in requests.reserve() }
            XCTAssertFalse(ids.contains(0))
            XCTAssertEqual(requests.reserve(), 0)
            for id in ids {
                requests.release(id)
                requests.finish(id, Data("late".utf8), status: 1)
            }
            XCTAssertGreaterThan(requests.reserve(), ids.last!)
        }
    }
    func testPendingErrorOversizeAndInsufficientCapacity() async {
        await MainActor.run {
            let requests = AuthenticationRequests()
            var bytes = [UInt8](repeating: 0, count: 10)
            let pending = requests.reserve()
            XCTAssertEqual(requests.take(pending, into: &bytes, capacity: 10), 0)
            requests.finish(pending, nil, status: -3)
            XCTAssertEqual(requests.take(pending, into: &bytes, capacity: 10), -3)
            let big = requests.reserve()
            requests.finish(big, Data(repeating: 1, count: AuthenticationRequests.maxBytes + 1), status: 1)
            XCTAssertEqual(requests.take(big, into: &bytes, capacity: 10), -4)
            let short = requests.reserve()
            requests.finish(short, Data(repeating: 1, count: 11), status: 1)
            XCTAssertEqual(requests.take(short, into: &bytes, capacity: 10), -4)
            XCTAssertEqual(requests.take(short, into: &bytes, capacity: 10), -2)
        }
    }
    func testCancelIsOnceAndReentrantCompletionCannotReviveRequest() async {
        await MainActor.run {
            let requests = AuthenticationRequests()
            var cancellations = 0
            var id: UInt64 = 0
            id = requests.reserve(cancel: {
                cancellations += 1
                requests.finish(id, Data("racing callback".utf8), status: 1)
            })
            requests.release(id)
            requests.release(id)
            XCTAssertEqual(cancellations, 1)
            var bytes = [UInt8](repeating: 0, count: 30)
            XCTAssertEqual(requests.take(id, into: &bytes, capacity: 30), -2)
            let success = requests.reserve(cancel: { cancellations += 1 })
            requests.finish(success, Data("ok".utf8), status: 1)
            requests.release(success)
            XCTAssertEqual(cancellations, 1)
        }
    }
    func testUntrustedWindowAndInvalidRPFailClosed() async {
        await MainActor.run {
            let input = Array("{\"kind\":\"browser\"}".utf8)
            input.withUnsafeBufferPointer { buffer in
                XCTAssertEqual(mygoAuthStart(UInt.max, buffer.baseAddress, input.count), 0)
            }
            // These are rejected before any signing-information lookup.
            XCTAssertFalse(AuthenticationRequests.signedRP("*.example.com"))
            XCTAssertFalse(AuthenticationRequests.signedRP("https://example.com"))
        }
    }
}
