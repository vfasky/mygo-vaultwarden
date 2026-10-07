// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// This projection reads only the authenticated encrypted payload. Missing policy
// on a legacy cache yields no candidates; main-app network credentials can still
// be restored so a successful sync migrates the cache.
private struct CandidatePolicySync: Decodable {
    struct Member: Decodable, Equatable {
        let id: String
        let organizationUserId: String
        let userId: String
        let type: Int
        let status: Int
        let enabled: Bool
        let usePolicies: Bool
        let permissions: [String: Bool]
    }
    struct Profile: Decodable {
        let id: String
        let email: String
        let key: String
        let organizations: [Member]
        let organizationsNew: [Member]
    }
    struct Policy: Decodable, Equatable {
        let id: String
        let organizationId: String
        let type: Int
        let enabled: Bool
        let data: PolicyValue
    }
    indirect enum PolicyValue: Decodable, Equatable {
        case null, bool(Bool), number(Double), text(String), array([PolicyValue]), object([String: PolicyValue])
        init(from decoder: Decoder) throws {
            let v = try decoder.singleValueContainer()
            if v.decodeNil() { self = .null }
            else if let x = try? v.decode(Bool.self) { self = .bool(x) }
            else if let x = try? v.decode(Double.self) { self = .number(x) }
            else if let x = try? v.decode(String.self) { self = .text(x) }
            else if let x = try? v.decode([PolicyValue].self) { self = .array(x) }
            else { self = .object(try v.decode([String: PolicyValue].self)) }
        }
    }
    struct Cipher: Decodable {
        struct Login: Decodable {
            struct URI: Decodable { let match: Int? }
            let uris: [URI]?
        }
        let login: Login?
        let id: String
        let organizationId: String?
        let type: Int
        let reprompt: Int
        let viewPassword: Bool
        let deletedDate: String?
        let archivedDate: String?
    }
    let profile: Profile
    let policies: [Policy]
    let policiesNew: [Policy]
    let ciphers: [Cipher]
}

extension VaultData {
    func policyCandidates(_ credentials: [VaultCredential]) -> [VaultCredential] {
        guard (try? self.validate(scope: scope)) != nil, !sync.isEmpty, sync.count <= 32 * 1024 * 1024,
              (try? CandidateJSONShape.check(sync)) != nil,
              let data = try? JSONDecoder().decode(CandidatePolicySync.self, from: sync),
              data.profile.id == scope.account, !data.profile.email.isEmpty, data.profile.email.utf8.count <= 1024,
              !data.profile.key.isEmpty, data.profile.key.utf8.count <= 4096, data.profile.organizations.count <= 1024,
              data.profile.organizationsNew.count <= 2048, data.policies.count <= 32768,
              data.policiesNew.count <= 32768, data.ciphers.count <= 100000 else { return [] }
        var newerIDs = Set<String>()
        var newerMembers = Set<String>()
        for m in data.profile.organizationsNew {
            guard !m.id.isEmpty, !m.organizationUserId.isEmpty, m.userId == scope.account,
                  m.organizationUserId != scope.account, newerIDs.insert(m.id).inserted,
                  newerMembers.insert(m.organizationUserId).inserted else { return [] }
        }
        var members: [String: CandidatePolicySync.Member] = [:]
        var memberIDs = Set<String>()
        for m in data.profile.organizations {
            guard !m.id.isEmpty, !m.organizationUserId.isEmpty, m.organizationUserId != scope.account,
                  m.userId == scope.account, [0, 1, 2, 4].contains(m.type), (-1...2).contains(m.status),
                  m.usePolicies, m.permissions["managePolicies"] == false,
                  members[m.id] == nil, memberIDs.insert(m.organizationUserId).inserted,
                  data.profile.organizationsNew.filter({ $0.id == m.id }) == [m] else { return [] }
            members[m.id] = m
        }
        func validate(_ rows: [CandidatePolicySync.Policy], accepted: Bool) -> [String: CandidatePolicySync.Policy]? {
            var result: [String: CandidatePolicySync.Policy] = [:]
            var types = Set<String>()
            for p in rows {
                guard let m = members[p.organizationId], m.status == 2 || (accepted && m.status == 1),
                      !p.id.isEmpty, result[p.id] == nil,
                      [0, 1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 20].contains(p.type),
                      types.insert("\(p.organizationId):\(p.type)").inserted else { return nil }
                result[p.id] = p
            }
            return result
        }
        guard let confirmed = validate(data.policies, accepted: false),
              let newer = validate(data.policiesNew, accepted: true) else { return [] }
        for (id, p) in confirmed { guard newer[id] == p else { return [] } }
        for (id, p) in newer where members[p.organizationId]?.status == 2 {
            guard confirmed[id] == p else { return [] }
        }
        // DefaultPolicyService uses the ordered legacy policies array (the new
        // policy service has a separate policiesNew state). First applicable
        // policy wins even when its data is null/invalid; role exemptions apply.
        var defaultMatch = 0
        if let first = data.policies.first(where: { p in
            guard p.type == 16, p.enabled, let member = members[p.organizationId] else { return false }
            return member.type != 0 && member.type != 1 && member.status >= 1
        }), case .object(let fields) = first.data,
           case .number(let value) = fields["uriMatchDetection"],
           value >= 0, value <= 5, value.rounded() == value {
            defaultMatch = Int(value)
        }
        if (pendingPolicyMutations ?? []).contains(where: { $0.policyType == 16 }) { defaultMatch = 5 }
        var personal = Set<Int>()
        var restricted: [String: Set<Int>] = [:]
        for p in confirmed.values where p.enabled && p.type == 15 {
            var kinds = Set<Int>()
            switch p.data {
            case .null: kinds = [3]
            case .array(let values):
                guard values.count <= 8 else { return [] }
                for value in values {
                    guard case .number(let n) = value, n >= 1, n <= 8, n.rounded() == n,
                          kinds.insert(Int(n)).inserted else { return [] }
                }
            default: return []
            }
            restricted[p.organizationId] = kinds
            personal.formUnion(kinds)
        }
        if (pendingPolicyMutations ?? []).contains(where: { $0.policyType == 15 }) { personal.formUnion(1...8) }
        let isolated = Set(quarantinedOrganizations ?? [])
        var permitted: [String: CandidatePolicySync.Cipher] = [:]
        var seen = Set<String>()
        for cipher in data.ciphers {
            guard seen.insert(cipher.id).inserted else { return [] }
            guard cipher.type == 1, cipher.reprompt == 0, cipher.viewPassword,
                  cipher.deletedDate == nil, cipher.archivedDate == nil else { continue }
            if let org = cipher.organizationId {
                guard !org.isEmpty, !isolated.contains(org), let member = members[org], member.status == 2,
                      member.enabled, !(restricted[org]?.contains(1) ?? false) else { continue }
            } else if personal.contains(1) { continue }
            permitted[cipher.id] = cipher
        }
        return credentials.compactMap { credential in
            guard let cipher = permitted[credential.id] else { return nil }
            guard let rules = credential.uris else { return nil }
            let retained = rules.filter { rule in
                // Legacy rules have no proof of their encrypted source. They
                // require successful sync to migrate, never hosts fallback.
                guard let index = rule.sourceIndex else { return false }
                guard let sources = cipher.login?.uris, sources.indices.contains(index) else { return false }
                return rule.match == (sources[index].match ?? defaultMatch) && rule.valid
            }
            if retained == rules { return credential }
            return VaultCredential(id: credential.id, title: credential.title, username: credential.username,
                                   password: credential.password, hosts: [], url: retained.first?.uri ?? "", uris: retained)
        }
    }
}

// JSONDecoder otherwise silently accepts duplicate object keys. Inspect shape
// before decoding policy, including escaped duplicate names and bounded nesting.
private struct CandidateJSONShape {
    var bytes: [UInt8]
    var offset = 0
    static func check(_ data: Data) throws {
        var parser = CandidateJSONShape(bytes: Array(data))
        try parser.value(depth: 0)
        parser.whitespace()
        guard parser.offset == parser.bytes.count else { throw SnapshotError.corrupt }
    }
    mutating func whitespace() {
        while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 }
    }
    mutating func consume(_ byte: UInt8) throws {
        whitespace()
        guard offset < bytes.count, bytes[offset] == byte else { throw SnapshotError.corrupt }
        offset += 1
    }
    mutating func string() throws -> String {
        whitespace()
        let start = offset
        try consume(34)
        while offset < bytes.count {
            let b = bytes[offset]
            offset += 1
            if b == 92 {
                guard offset < bytes.count else { throw SnapshotError.corrupt }
                offset += 1
            } else if b == 34 {
                return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset]))
            }
        }
        throw SnapshotError.corrupt
    }
    mutating func value(depth: Int) throws {
        guard depth <= 32 else { throw SnapshotError.corrupt }
        whitespace()
        guard offset < bytes.count else { throw SnapshotError.corrupt }
        switch bytes[offset] {
        case 123:
            offset += 1
            whitespace()
            var keys = Set<String>()
            if offset < bytes.count && bytes[offset] == 125 { offset += 1; return }
            while true {
                guard keys.insert(try string()).inserted else { throw SnapshotError.corrupt }
                try consume(58)
                try value(depth: depth + 1)
                whitespace()
                guard offset < bytes.count else { throw SnapshotError.corrupt }
                if bytes[offset] == 125 { offset += 1; return }
                try consume(44)
            }
        case 91:
            offset += 1
            whitespace()
            if offset < bytes.count && bytes[offset] == 93 { offset += 1; return }
            while true {
                try value(depth: depth + 1)
                whitespace()
                guard offset < bytes.count else { throw SnapshotError.corrupt }
                if bytes[offset] == 93 { offset += 1; return }
                try consume(44)
            }
        case 34: _ = try string()
        default:
            let start = offset
            while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
            guard offset > start else { throw SnapshotError.corrupt }
            // JSONDecoder below validates scalar spelling and value types.
        }
    }
}
