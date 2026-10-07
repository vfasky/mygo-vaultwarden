// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import XCTest
@testable import CredentialModel

func policyVaultFixture(scope: SnapshotScope, ids: [String]) throws -> VaultData {
    let object: [String: Any] = ["profile": ["id": scope.account, "email": "fixture@example.invalid", "key": "wrapped-fixture", "organizations": [], "organizationsNew": []],
        "policies": [], "policiesNew": [], "ciphers": ids.map { ["id": $0, "type": 1, "reprompt": 0, "viewPassword": true] as [String: Any] }]
    return VaultData(version: 1, scope: scope, sync: try JSONSerialization.data(withJSONObject: object))
}

final class SnapshotPolicyTests: XCTestCase {
    let scope = SnapshotScope(server: "https://policy.example.invalid", account: "account-a")
    func credential(_ id: String) -> VaultCredential {
        VaultCredential(id: id, title: "fixture", username: "u", password: "fixture", hosts: [], url: "", uris: [])
    }
    func vault(_ mutate: (inout [String: Any]) -> Void) throws -> VaultData {
        let base = try policyVaultFixture(scope: scope, ids: ["personal", "org-item", "other-item"])
        var object = try JSONSerialization.jsonObject(with: base.sync) as! [String: Any]
        let members = ["org-a", "org-b"].map { id in
            ["id": id, "organizationUserId": "member-\(id)", "userId": scope.account, "type": 2, "status": 2, "enabled": true, "usePolicies": true, "permissions": ["managePolicies": false]] as [String: Any]
        }
        object["profile"] = ["id": scope.account, "email": "fixture@example.invalid", "key": "wrapped-fixture", "organizations": members, "organizationsNew": members]
        var ciphers = object["ciphers"] as! [[String: Any]]
        ciphers[1]["organizationId"] = "org-a"
        ciphers[2]["organizationId"] = "org-b"
        object["ciphers"] = ciphers
        mutate(&object)
        return VaultData(version: 1, scope: scope, sync: try JSONSerialization.data(withJSONObject: object))
    }
    var credentials: [VaultCredential] { ["personal", "org-item", "other-item"].map(credential) }

    func testPendingPolicySharedScopeVectors() throws {
        struct Vector: Decodable { let name: String; let version: Int; let pending: [PendingPolicyMutation]; let valid: Bool; let personalRead: Bool }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("internal/vaultwarden/testdata/pending-policy-cases.json")
        let vectors = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: path))
        for vector in vectors {
            var v = try vault { _ in }
            v.version = vector.version; v.pendingPolicyMutations = vector.pending
            XCTAssertEqual((try? v.validate(scope: scope)) != nil, vector.valid, vector.name)
            XCTAssertEqual(v.policyCandidates(credentials).contains(where: { $0.id == "personal" }), vector.personalRead, vector.name)
            if vector.valid { XCTAssertTrue(v.policyCandidates(credentials).contains(where: { $0.id == "other-item" }), vector.name) }
        }
    }

    func testPendingPolicyVersionsTypesAndIndependentOrganizationScope() throws {
        var v = try vault { _ in }
        let record = PendingPolicyMutation(organizationId: "org-a", policyType: 15, mutationId: "mutation-1")
        v.pendingPolicyMutations = [record]
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty) // v1 must not silently carry a v2 barrier
        v.version = 2
        XCTAssertEqual(v.policyCandidates(credentials).map(\.id), ["org-item", "other-item"])
        v.pendingPolicyMutations = [record, record]
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
        v.pendingPolicyMutations = []
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty) // stripped v2 marker fails closed
        v.pendingPolicyMutations = [PendingPolicyMutation(organizationId: "org-a", policyType: 5, mutationId: "mutation-2")]
        XCTAssertEqual(v.policyCandidates(credentials).count, 3) // ownership is write-only
        v.pendingPolicyMutations = [PendingPolicyMutation(organizationId: "org-a", policyType: 99, mutationId: "mutation-3")]
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
    }

    func testLegacyCandidatesRequireSuccessfulPolicyMigration() throws {
        let v = try vault { $0.removeValue(forKey: "policies") }
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
        XCTAssertEqual(try vault { _ in }.policyCandidates(credentials).count, 3)
        let key = Data(repeating: 7, count: 32)
        let old = try sealSnapshot(credentials: credentials, scope: scope, keyID: UUID().uuidString, key: key)
        XCTAssertTrue(try openSnapshot(old, key: key, scope: scope).isEmpty)
        let restricted = try sealSnapshot(credentials: credentials, scope: scope, keyID: UUID().uuidString, key: key, vault: v)
        XCTAssertTrue(try openSnapshot(restricted, key: key, scope: scope).isEmpty)
    }
    func testPersonalUnionAndOrganizationOwnPolicySurviveIsolation() throws {
        var v = try vault { object in
            let policy: [String: Any] = ["id": "policy-a", "organizationId": "org-a", "type": 15, "enabled": true, "data": [1]]
            object["policies"] = [policy]; object["policiesNew"] = [policy]
        }
        XCTAssertEqual(v.policyCandidates(credentials).map(\.id), ["other-item"])
        v.quarantinedOrganizations = ["org-a"]
        XCTAssertEqual(v.policyCandidates(credentials).map(\.id), ["other-item"])
        let ownership = try vault { object in
            let p: [String: Any] = ["id": "policy-a", "organizationId": "org-a", "type": 5, "enabled": true, "data": NSNull()]
            object["policies"] = [p]; object["policiesNew"] = [p]
        }
        XCTAssertEqual(ownership.policyCandidates(credentials).count, 3)
    }
    func testDeletedArchivedRepromptAndPermissionAreAlwaysExcluded() throws {
        for (field, value) in [("deletedDate", "2026-01-01" as Any), ("archivedDate", "2026-01-01"), ("reprompt", 1), ("viewPassword", false), ("organizationId", "")] {
            let v = try vault { object in
                var ciphers = object["ciphers"] as! [[String: Any]]
                ciphers[0][field] = value
                object["ciphers"] = ciphers
            }
            XCTAssertEqual(v.policyCandidates(credentials).map(\.id), ["org-item", "other-item"])
        }
    }
    func testDuplicateKeysAndExcessiveNestingFailClosed() throws {
        let base = try policyVaultFixture(scope: scope, ids: ["personal"])
        let raw = String(decoding: base.sync, as: UTF8.self)
        for prefix in [#"{"policies":[],"# , #"{"\u0070olicies":[],"#] {
            let v = VaultData(version: 1, scope: scope, sync: Data((prefix + raw.dropFirst()).utf8))
            XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
        }
        let nested = String(repeating: "[", count: 34) + "null" + String(repeating: "]", count: 34)
        let v = VaultData(version: 1, scope: scope, sync: Data(("{\"future\":" + nested + "," + raw.dropFirst()).utf8))
        XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
    }
    func testMismatchedPoliciesAndMembershipFailClosed() throws {
        let missing = try vault { $0["policiesNew"] = [] }
        XCTAssertEqual(missing.policyCandidates(credentials).count, 3)
        for change in 0...2 {
            let v = try vault { object in
                let p: [String: Any] = ["id": "policy-a", "organizationId": "org-a", "type": 15, "enabled": true, "data": change == 1 ? [1, 1] : [1]]
                object["policies"] = [p]
                object["policiesNew"] = change == 0 ? [] : [p]
                if change == 2 { object["profile"] = ["id": scope.account, "email": "fixture@example.invalid", "key": "wrapped-fixture", "organizations": [], "organizationsNew": []] }
            }
            XCTAssertTrue(v.policyCandidates(credentials).isEmpty)
        }
    }
}
