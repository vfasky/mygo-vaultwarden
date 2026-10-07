// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import XCTest
@testable import CredentialModel

extension SnapshotPolicyTests {
    func testURIDefaultSharedVectorsAndSourceBoundCandidates() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("internal/vaultwarden/testdata/uri-default-policy-cases.json")
        let vectors = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [[String: Any]]
        for vector in vectors {
            let name = vector["name"] as! String
            let roles = vector["roles"] as! [Int]
            let values = vector["values"] as! [Any]
            let expected = vector["expected"] as! Int
            let accepted = vector["acceptedOnly"] as? Bool == true
            let v = try vault { object in
                let members = roles.enumerated().map { i, role in
                    ["id": "org-\(i)", "organizationUserId": "member-\(i)", "userId": scope.account,
                     "type": role, "status": accepted ? 1 : 2,
                     "enabled": vector["organizationDisabled"] as? Bool != true,
                     "usePolicies": true, "permissions": ["managePolicies": false]] as [String: Any]
                }
                var profile = object["profile"] as! [String: Any]
                profile["organizations"] = members; profile["organizationsNew"] = members
                object["profile"] = profile
                let policies = roles.indices.map { i in
                    ["id": "policy-\(i)", "organizationId": "org-\(i)", "type": 16,
                     "enabled": !(i == 0 && vector["disabledFirst"] as? Bool == true),
                     "data": ["uriMatchDetection": values[i]]] as [String: Any]
                }
                object["policies"] = accepted ? [] : policies; object["policiesNew"] = policies
                object["ciphers"] = [["id": "personal", "type": 1, "reprompt": 0, "viewPassword": true,
                                      "login": ["uris": [["match": NSNull()], ["match": 0]]]]]
            }
            for match in [0, 1, 3] {
                let inherited = CredentialURI(uri: "https://login.example.invalid/path", match: match, baseDomain: "example.invalid", includeSubdomains: true, sourceIndex: 0)
                let explicit = CredentialURI(uri: "https://explicit.example.invalid/path", match: 0, baseDomain: "example.invalid", includeSubdomains: true, sourceIndex: 1)
                let c = VaultCredential(id: "personal", title: "fixture", username: "u", password: "secret", hosts: ["example.invalid"], url: inherited.uri, uris: [inherited, explicit])
                let checked = try XCTUnwrap(v.policyCandidates([c]).first, name)
                XCTAssertEqual(checked.uris, match == expected ? [inherited, explicit] : [explicit], name)
                XCTAssertEqual(checked.hosts, match == expected ? ["example.invalid"] : [], name)
                // Round-trip the bridge model, including provenance, before checking.
                let roundTrip = try JSONDecoder().decode(VaultCredential.self, from: JSONEncoder().encode(c))
                XCTAssertEqual(v.policyCandidates([roundTrip]), [checked], name)
                var pending = v
                pending.version = 2
                pending.pendingPolicyMutations = [PendingPolicyMutation(organizationId: "org-0", policyType: 16, mutationId: "pending-uri")]
                XCTAssertEqual(pending.policyCandidates([c]).first?.uris, [explicit], "pending: " + name)
            }
        }
    }

    func testNewDefaultCannotBeBypassedByLegacyOrStaleDerivedURI() throws {
        for defaultMatch in [0, 1, 2, 3, 4, 5] {
            let v = try vault { object in
                let policy: [String: Any] = ["id": "policy-a", "organizationId": "org-a", "type": 16, "enabled": true, "data": ["uriMatchDetection": defaultMatch]]
                object["policies"] = [policy]; object["policiesNew"] = [policy]
                var ciphers = object["ciphers"] as! [[String: Any]]
                for i in ciphers.indices { ciphers[i]["login"] = ["uris": [["match": NSNull()], ["match": 0]]] }
                object["ciphers"] = ciphers
            }
            for id in ["personal", "org-item", "other-item"] {
                for index: Int? in (defaultMatch == 0 ? [nil, -1, 99] : [nil, 0, -1, 99]) {
                    let rule = CredentialURI(uri: "https://login.example.invalid/path", match: 0, baseDomain: "example.invalid", includeSubdomains: true, sourceIndex: index)
                    let stale = VaultCredential(id: id, title: "fixture", username: "u", password: "secret", hosts: ["localhost"], url: rule.uri, uris: [rule])
                    let checked = try XCTUnwrap(v.policyCandidates([stale]).first)
                    XCTAssertFalse(checked.matches(serviceIdentifier: "https://other.example.invalid/", isURL: true))
                    XCTAssertFalse(checked.matches(serviceIdentifier: "localhost", isURL: false))
                    XCTAssertEqual(checked.uris, [])
                    XCTAssertTrue(checked.url.isEmpty)
                }
            }
        }
    }
}
