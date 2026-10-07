// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import CredentialModel

final class VaultURITests: XCTestCase {
    func testBaseDomainAndLookalikes() {
        let rule = CredentialURI(uri: "https://login.example.co.uk/", match: 0, baseDomain: "example.co.uk", includeSubdomains: true)
        XCTAssertTrue(rule.valid)
        XCTAssertTrue(rule.matches(serviceIdentifier: "https://other.example.co.uk/login", isURL: true))
        XCTAssertTrue(rule.matches(serviceIdentifier: "example.co.uk", isURL: false))
        XCTAssertFalse(rule.matches(serviceIdentifier: "example.co.uk.evil.test", isURL: false))
        XCTAssertFalse(rule.matches(serviceIdentifier: "https://example.co.uk@evil.test/", isURL: true))
    }
    func testHostAndExactRulesFailWhenSourceCannotBeProved() {
        let host = CredentialURI(uri: "https://example.com:8443/", match: 1, baseDomain: "example.com", includeSubdomains: false)
        XCTAssertTrue(host.matches(serviceIdentifier: "https://example.com:8443/login", isURL: true))
        XCTAssertFalse(host.matches(serviceIdentifier: "example.com", isURL: false))
        XCTAssertFalse(host.matches(serviceIdentifier: "https://example.com/", isURL: true))
        let exact = CredentialURI(uri: "https://example.com/private", match: 3, baseDomain: "example.com", includeSubdomains: false)
        XCTAssertTrue(exact.matches(serviceIdentifier: "https://example.com/private", isURL: true))
        XCTAssertFalse(exact.matches(serviceIdentifier: "https://example.com/public", isURL: true))
        XCTAssertFalse(exact.matches(serviceIdentifier: "example.com", isURL: false))
        let item = VaultCredential(id: "real", title: "real", username: "user", password: "fixture", hosts: ["example.com"], url: exact.uri, uris: [exact])
        XCTAssertTrue(item.matches(serviceIdentifier: exact.uri, isURL: true))
        XCTAssertFalse(item.quickFillMatches(serviceIdentifier: exact.uri, isURL: true))
    }
    func testEmptyOrUnsupportedURIsNeverFallBackToHosts() {
        let item = VaultCredential(id: "real", title: "real", username: "user", password: "fixture", hosts: ["example.com"], url: "", uris: [])
        XCTAssertFalse(item.matches(serviceIdentifier: "example.com", isURL: false))
        for mode in [2,4,5] {
            let rule = CredentialURI(uri: "https://example.com", match: mode, baseDomain: "example.com", includeSubdomains: true)
            XCTAssertFalse(rule.valid)
            XCTAssertFalse(rule.matches(serviceIdentifier: "example.com", isURL: false))
        }
    }
    func testRealScopeCanBeAuthenticatedAndOldAccountLeaseRevoked() throws {
        // Schema scope and credential validation are exercised independently from real Keychain.
        let scope = SnapshotScope(server: "https://vault.example.com/subpath", account: "user-id")
        XCTAssertTrue(scope.valid)
        XCTAssertFalse(SnapshotScope(server: "http://vault.example.com", account: "user-id").valid)
        let rule = CredentialURI(uri: "https://example.com/", match: 0, baseDomain: "example.com", includeSubdomains: true)
        let item = VaultCredential(id: "entry", title: "login", username: "u", password: "p", hosts: ["example.com"], url: rule.uri, uris: [rule])
        let key = Data(repeating: 7, count: 32)
        let encrypted = try sealSnapshot(credentials: [item], scope: scope, keyID: UUID().uuidString, key: key, vault: policyVaultFixture(scope: scope, ids: [item.id]))
        let migrated = try openSnapshot(encrypted, key: key, scope: scope)
        XCTAssertEqual(migrated.count, 1)
        XCTAssertEqual(migrated.first?.uris, []) // old projection lacks sourceIndex
        XCTAssertFalse(migrated[0].matches(serviceIdentifier: "https://example.com/", isURL: true))
        XCTAssertThrowsError(try openSnapshot(encrypted, key: key, scope: .demo))
    }
    func testPublicSuffixCannotBecomeQuickSuggestion() {
        let rule = CredentialURI(uri: "https://co.uk/", match: 0, baseDomain: "co.uk", includeSubdomains: false)
        XCTAssertTrue(rule.valid)
        XCTAssertFalse(rule.quickEligible)
        XCTAssertFalse(rule.matches(serviceIdentifier: "example.co.uk", isURL: false))
    }
    func testIDNAEncodedHost() {
        let rule = CredentialURI(uri: "https://xn--fsqu00a.xn--0zwm56d/", match: 0, baseDomain: "xn--fsqu00a.xn--0zwm56d", includeSubdomains: true)
        XCTAssertTrue(rule.valid)
        XCTAssertTrue(rule.matches(serviceIdentifier: "https://xn--fsqu00a.xn--0zwm56d/login", isURL: true))
    }
}
