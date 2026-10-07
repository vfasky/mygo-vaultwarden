// SPDX-License-Identifier: GPL-3.0-only
// Standalone bridge codec test executable; do not add this file to app targets.
import Foundation
import XCTest
final class AuthenticationEncodingTests: XCTestCase {
    func testRawCredentialBytesPreserved() throws {
        for bytes in [Data(), Data([0]), Data([0, 255, 254, 253, 127]), Data((0...255).map { UInt8($0) })] {
            let encoded = b64(bytes)
            XCTAssertFalse(encoded.contains("="))
            XCTAssertFalse(encoded.contains("+"))
            XCTAssertFalse(encoded.contains("/"))
            let normalized = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            let padded = normalized + String(repeating: "=", count: (4 - normalized.count % 4) % 4)
            XCTAssertEqual(Data(base64Encoded: padded), bytes)
        }
    }
    func testChallengeNotUTF8Reencoded() throws {
        XCTAssertEqual(b64(Data([251, 255, 239])), "-__v")
    }
    static var allTests = [
        ("testRawCredentialBytesPreserved", testRawCredentialBytesPreserved),
        ("testChallengeNotUTF8Reencoded", testChallengeNotUTF8Reencoded)
    ]
}
XCTMain([testCase(AuthenticationEncodingTests.allTests)])
