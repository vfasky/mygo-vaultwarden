// SPDX-License-Identifier: GPL-3.0-only
// SwiftPM discovers these tests; do not add this file to app targets.
import Foundation
import XCTest
@testable import VaultAuthentication
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
    private func decodeBytes(_ value: String) throws -> Data {
        let normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return try XCTUnwrap(Data(base64Encoded: normalized + String(repeating: "=", count: (4 - normalized.count % 4) % 4)))
    }

    // Required object-valued extensions mirrors VW 1.37.4
    // src/api/core/two_factor/webauthn.rs PublicKeyCredentialCopy. Optional
    // fields would hide the missing-field regression in a permissive decoder.
    private struct AssertionDTO: Decodable {
        let id: String
        let rawId: String
        let type: String
        let extensions: [String: Bool]
        let response: Response
        struct Response: Decodable {
            let clientDataJSON: String
            let authenticatorData: String
            let signature: String
            let userHandle: String
        }
    }

    func testCompleteAssertionDTO() throws {
        let id = Data([251, 255, 239, 0])
        // Whitespace/key order must survive: these exact bytes are signed.
        let client = Data("{ \"origin\":\"https://vault.example\", \"type\":\"webauthn.get\", \"challenge\":\"-__v\" }\n".utf8)
        let auth = Data((0...255).map { UInt8($0) })
        let signature = Data([0, 255, 128, 1, 251])
        for handle in [Data(), Data([255, 0, 127])] {
            let raw = try encodeVaultCredential(id: id, clientDataJSON: client,
                response: .assertion(authenticatorData: auth, signature: signature, userHandle: handle))
            let dto = try JSONDecoder().decode(AssertionDTO.self, from: raw)
            XCTAssertEqual(dto.id, "-__vAA")
            XCTAssertEqual(dto.id, dto.rawId)
            XCTAssertEqual(try decodeBytes(dto.rawId), id)
            XCTAssertEqual(dto.type, "public-key")
            XCTAssertTrue(dto.extensions.isEmpty) // no fabricated appid=true
            XCTAssertEqual(try decodeBytes(dto.response.clientDataJSON), client)
            XCTAssertEqual(try decodeBytes(dto.response.authenticatorData), auth)
            XCTAssertEqual(try decodeBytes(dto.response.signature), signature)
            XCTAssertEqual(try decodeBytes(dto.response.userHandle), handle)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
            XCTAssertEqual(Set(object.keys), ["id", "rawId", "type", "extensions", "response"])
            XCTAssertNotNil(object["extensions"] as? [String: Any])
            let response = try XCTUnwrap(object["response"] as? [String: String])
            XCTAssertEqual(Set(response.keys), ["clientDataJSON", "authenticatorData", "signature", "userHandle"])

            // Prove the DTO check rejects the previous missing field and wrong
            // shapes, rather than accidentally treating extensions as optional.
            for invalid in [nil, NSNull(), [] as [Bool], true] as [Any?] {
                var broken = object
                broken["extensions"] = invalid
                let data = try JSONSerialization.data(withJSONObject: broken)
                XCTAssertThrowsError(try JSONDecoder().decode(AssertionDTO.self, from: data))
            }
        }
    }

    func testCompleteRegistrationDTO() throws {
        let id = Data([0, 255, 251])
        let client = Data("{ \"type\": \"webauthn.create\" }\n".utf8)
        let attestation = Data([163, 0, 255, 128, 251])
        let raw = try encodeVaultCredential(id: id, clientDataJSON: client,
            response: .registration(attestationObject: attestation))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["id", "rawId", "type", "extensions", "response"])
        XCTAssertEqual(object["id"] as? String, "AP_7")
        XCTAssertEqual(object["rawId"] as? String, "AP_7")
        XCTAssertEqual(object["type"] as? String, "public-key")
        XCTAssertEqual(try XCTUnwrap(object["extensions"] as? [String: Bool]), [:])
        let response = try XCTUnwrap(object["response"] as? [String: String])
        XCTAssertEqual(Set(response.keys), ["clientDataJSON", "attestationObject"])
        XCTAssertEqual(try decodeBytes(XCTUnwrap(response["clientDataJSON"])), client)
        XCTAssertEqual(try decodeBytes(XCTUnwrap(response["attestationObject"])), attestation)
        XCTAssertThrowsError(try JSONDecoder().decode(AssertionDTO.self, from: raw))
    }
}
