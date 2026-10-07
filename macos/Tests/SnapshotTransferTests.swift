// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import CredentialModel

final class SnapshotTransferTests: XCTestCase {
    private func begin(_ transport: SnapshotTransfer, _ input: Data) throws -> String {
        try transport.exchange(SnapshotTransferFrame(action: "begin", total: input.count, digest: SnapshotTransfer.hash(input)), execute: unused).handle!
    }
    private func unused(_ data: Data) throws -> (Data, (Data, Range<Int>) throws -> Data) {
        XCTFail("invalid/incomplete transport must not reach the snapshot executor")
        throw SnapshotError.invalidInput
    }
    private func append(_ transport: SnapshotTransfer, _ handle: String, _ input: Data) throws {
        for offset in stride(from: 0, to: input.count, by: SnapshotTransfer.chunkBytes) {
            _ = try transport.exchange(SnapshotTransferFrame(action: "append", handle: handle, offset: offset,
                data: input.subdata(in: offset..<min(offset + SnapshotTransfer.chunkBytes, input.count))), execute: unused)
        }
    }
    func testLargeRoundTripAndOneTimeHandle() throws {
        let transport = SnapshotTransfer()
        let input = Data(repeating: 71, count: 5 * 1024 * 1024 + 3)
        let handle = try begin(transport, input)
        try append(transport, handle, input)
        let ready = try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle)) { bytes in
            XCTAssertEqual(bytes, input)
            return (bytes, { data, range in data.subdata(in: range) })
        }
        XCTAssertEqual(ready.total, input.count)
        var output = Data()
        while output.count < input.count {
            let page = try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle, offset: output.count), execute: unused)
            XCTAssertLessThanOrEqual(page.data!.count, SnapshotTransfer.chunkBytes)
            output.append(page.data!)
        }
        XCTAssertEqual(output, input)
        XCTAssertEqual(ready.digest, SnapshotTransfer.hash(output))
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle), execute: unused))
    }
    func testMissingDuplicateWrongOrderAndDigestRevoke() throws {
        let input = Data(repeating: 1, count: 12)
        for mode in 0..<4 {
            let transport = SnapshotTransfer()
            let handle = try begin(transport, input)
            if mode == 0 {
                XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle), execute: unused))
            } else if mode == 1 {
                XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "append", handle: handle, offset: 1, data: input), execute: unused))
            } else if mode == 2 {
                try append(transport, handle, input)
                XCTAssertThrowsError(try append(transport, handle, input))
            } else {
                try append(transport, handle, Data(repeating: 2, count: 12))
                XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle), execute: unused))
            }
            XCTAssertThrowsError(try append(transport, handle, input))
        }
    }
    func testCancelDuringExecutionCannotAdmitAnotherLargeExecution() throws {
        let transport = SnapshotTransfer()
        let input = Data([1])
        let handle = try begin(transport, input)
        try append(transport, handle, input)
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle)) { bytes in
            transport.cancel(handle)
            XCTAssertThrowsError(try self.begin(transport, input))
            return (bytes, { data, range in data.subdata(in: range) })
        })
        let replacement = try begin(transport, input)
        transport.cancel(replacement)
    }
    func testReadReplayAndOversizedChunkDestroyHandle() throws {
        let input = Data(repeating: 1, count: SnapshotTransfer.chunkBytes + 1)
        let transport = SnapshotTransfer()
        var handle = try begin(transport, input)
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "append", handle: handle, data: input), execute: unused))
        handle = try begin(transport, input)
        try append(transport, handle, input)
        _ = try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle)) { bytes in (bytes, { data, range in data.subdata(in: range) }) }
        _ = try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle), execute: unused)
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle), execute: unused))
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle, offset: SnapshotTransfer.chunkBytes), execute: unused))
    }
    func testLeaseRevocationCancelExpiryCapacityAndForeignHandle() throws {
        var now: TimeInterval = 0
        let transport = SnapshotTransfer(clock: { now })
        let input = Data(repeating: 1, count: SnapshotTransfer.chunkBytes + 1)
        var handle = try begin(transport, input)
        XCTAssertThrowsError(try begin(transport, input))
        XCTAssertThrowsError(try append(transport, "foreign", input))
        try append(transport, handle, input)
        var valid = true
        _ = try transport.exchange(SnapshotTransferFrame(action: "finish", handle: handle)) { bytes in
            (bytes, { data, range in
                guard valid else { throw SnapshotError.stale }
                return data.subdata(in: range)
            })
        }
        _ = try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle), execute: unused)
        valid = false
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "read", handle: handle, offset: SnapshotTransfer.chunkBytes), execute: unused))
        handle = try begin(transport, input)
        transport.cancel(handle)
        XCTAssertThrowsError(try append(transport, handle, input))
        handle = try begin(transport, input)
        now = 60
        XCTAssertThrowsError(try append(transport, handle, input))
        XCTAssertThrowsError(try transport.exchange(SnapshotTransferFrame(action: "begin", total: SnapshotTransfer.maximumBytes + 1, digest: SnapshotTransfer.hash(input)), execute: unused))
    }
}
