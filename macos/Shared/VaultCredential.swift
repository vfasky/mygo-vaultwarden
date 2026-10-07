// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Darwin

struct CredentialURI: Codable, Equatable {
    let uri: String
    let match: Int
    let baseDomain: String?
    let includeSubdomains: Bool?
    let sourceIndex: Int?

    init(uri: String, match: Int, baseDomain: String?, includeSubdomains: Bool?, sourceIndex: Int? = nil) {
        self.uri = uri; self.match = match; self.baseDomain = baseDomain
        self.includeSubdomains = includeSubdomains; self.sourceIndex = sourceIndex
    }

    private func components(_ value: String) -> URLComponents? {
        guard let url = URLComponents(string: value), ["https", "http"].contains(url.scheme?.lowercased() ?? ""),
              url.host != nil, url.user == nil, url.password == nil else { return nil }
        return url
    }
    private func host(_ value: URLComponents) -> String? {
        guard var host = value.url?.host()?.lowercased() else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return host
    }
    func matches(serviceIdentifier: String, isURL: Bool) -> Bool {
        guard let expected = components(uri), let originalHost = host(expected) else { return false }
        let requested = isURL ? components(serviceIdentifier) : nil
        let domain = !isURL && !serviceIdentifier.contains(where: { "/?#@".contains($0) }) ? components("https://" + serviceIdentifier) : nil
        let requestedHost = isURL ? requested.flatMap(host) : domain.flatMap(host)
        guard let host = requestedHost, !host.isEmpty else { return false }
        switch match {
        case 0:
            let base = baseDomain ?? originalHost
            guard originalHost == base || originalHost.hasSuffix("." + base) else { return false }
            return host == base || (includeSubdomains == true && base.contains(".") && host.hasSuffix("." + base))
        case 1:
            guard host == originalHost else { return false }
            // A domain-only callback cannot prove an explicit port restriction.
            if !isURL { return false }
            func port(_ u: URLComponents) -> Int { u.port ?? (u.scheme == "https" ? 443 : 80) }
            return requested.map { port($0) == port(expected) } ?? false
        case 3:
            guard var requested else { return false }
            var expected = expected
            requested.fragment = nil; expected.fragment = nil
            if requested.path.isEmpty { requested.path = "/" }
            if expected.path.isEmpty { expected.path = "/" }
            return requested.string == expected.string
        default: return false
        }
    }
    var quickEligible: Bool {
        guard match == 0, let base = baseDomain else { return false }
        var ipv4 = in_addr(); var ipv6 = in6_addr()
        let address = base.withCString { inet_pton(AF_INET, $0, &ipv4) == 1 || inet_pton(AF_INET6, $0, &ipv6) == 1 }
        return includeSubdomains == true || base == "localhost" || address
    }
    var valid: Bool {
        guard [0, 1, 3].contains(match), uri.utf8.count <= 8192, let value = components(uri), let host = host(value) else { return false }
        if match == 0 {
            guard let base = baseDomain, !base.isEmpty, host == base || host.hasSuffix("." + base) else { return false }
            if includeSubdomains == true && !base.contains(".") { return false }
        }
        return true
    }
}

// Kept Codable-compatible with phase-2 fixtures. Real items carry explicit URI
// rules; only legacy public loopback fixtures may use the old `hosts` fallback.
struct VaultCredential: Codable, Equatable {
    let id: String
    let title: String
    let username: String
    let password: String
    let hosts: [String]
    let url: String
    let uris: [CredentialURI]?
    init(id: String, title: String, username: String, password: String, hosts: [String], url: String, uris: [CredentialURI]? = nil) {
        self.id=id; self.title=title; self.username=username; self.password=password; self.hosts=hosts; self.url=url; self.uris=uris
    }
    func matches(serviceIdentifier: String, isURL: Bool) -> Bool {
        if let uris { return uris.contains { $0.matches(serviceIdentifier: serviceIdentifier, isURL: isURL) } }
        let host: String?
        if isURL {
            guard let components = URLComponents(string: serviceIdentifier),
                  components.scheme == "http" || components.scheme == "https",
                  components.user == nil, components.password == nil else { return false }
            host = components.host
        } else { host = serviceIdentifier }
        guard let host, ["localhost", "127.0.0.1"].contains(host.lowercased()) else { return false }
        return hosts.contains(host.lowercased())
    }
    func quickFillMatches(serviceIdentifier: String, isURL: Bool) -> Bool {
        if let uris { return uris.contains { $0.quickEligible && $0.matches(serviceIdentifier: serviceIdentifier, isURL: isURL) } }
        return matches(serviceIdentifier: serviceIdentifier, isURL: isURL)
    }
}
