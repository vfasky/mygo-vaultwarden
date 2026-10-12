// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import CredentialModel

final class VaultCredentialTests: XCTestCase {
    private func fixture() throws -> VaultCredential {
        VaultCredential(id: "legacy-entry", title: "Legacy login", username: "test@example.invalid",
                        password: "test-password", hosts: ["localhost", "127.0.0.1"], url: "http://localhost/")
    }

    func testTOTPWireAndLimits() throws {
        let legacy = try fixture()
        let data = try JSONEncoder().encode(legacy)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(object["totp"])
        XCTAssertNil(try JSONDecoder().decode(VaultCredential.self, from: data).totp)
        for seed in ["", "MY======", String(repeating: "é", count: 2048)] {
            object["totp"] = seed
            let credential = try JSONDecoder().decode(VaultCredential.self, from: JSONSerialization.data(withJSONObject: object))
            XCTAssertEqual(credential.totp, seed)
            XCTAssertNoThrow(try validateCredentials([credential]))
            XCTAssertEqual(try JSONDecoder().decode(VaultCredential.self, from: JSONEncoder().encode(credential)), credential)
        }
        object["totp"] = String(repeating: "é", count: 2048) + "a"
        let oversized = try JSONDecoder().decode(VaultCredential.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertThrowsError(try validateCredentials([oversized]))
    }

    func testAcceptsOnlyExactLoopbackDomainIdentities() throws {
        let credential = try fixture()
        XCTAssertTrue(credential.matches(serviceIdentifier: "localhost", isURL: false))
        XCTAssertTrue(credential.matches(serviceIdentifier: "LOCALHOST", isURL: false))
        XCTAssertTrue(credential.matches(serviceIdentifier: "127.0.0.1", isURL: false))
        for host in ["localhost.evil.test", "evil-localhost", "www.localhost", "example.com", "", "localhost:18472"] {
            XCTAssertFalse(credential.matches(serviceIdentifier: host, isURL: false), host)
        }
    }

    func testParsesURLHostRatherThanSubstring() throws {
        let credential = try fixture()
        for url in ["http://localhost:18472/", "https://127.0.0.1/login", "http://LOCALHOST/"] {
            XCTAssertTrue(credential.matches(serviceIdentifier: url, isURL: true), url)
        }
        for url in ["http://localhost.evil.test/", "https://evil.test/?next=localhost",
                    "https://localhost@evil.test/", "https://evil@localhost/",
                    "file://localhost/passwords", "javascript:localhost", "localhost", ""] {
            XCTAssertFalse(credential.matches(serviceIdentifier: url, isURL: true), url)
        }
    }
}
